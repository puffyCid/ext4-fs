use crate::{extfs::Ext4Reader, structs::Extents, utils::bytes::read_bytes};
use log::{debug, error};
use std::io::{self, BufReader, Error, Read, Seek};

pub struct FileReader<'reader, T>
where
    T: std::io::Seek + std::io::Read,
{
    reader: &'reader mut BufReader<T>,
    blocksize: u64,
    extents: Extents,
    disk_position: u64,
    file_position: u64,
    file_size: u64,
    logical_block: u32,
    total_sparse: u64,
}

impl<'reader, T: io::Seek + io::Read> Ext4Reader<T> {
    pub(crate) fn file_reader(
        &'reader mut self,
        extents: &Extents,
        file_size: u64,
    ) -> FileReader<'reader, T> {
        FileReader {
            reader: &mut self.fs,
            blocksize: self.blocksize as u64,
            extents: extents.clone(),
            disk_position: 0,
            file_position: 0,
            file_size,
            logical_block: 0,
            total_sparse: 0,
        }
    }
}

impl<'reader, T> Read for FileReader<'reader, T>
where
    T: std::io::Seek + std::io::Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.extents.extent_descriptors.is_empty() && self.extents.index_descriptors.is_empty() {
            debug!("[ext4-fs] Got empty extents descriptors and index descriptors. Sparse file?");
            return Ok(buf.len());
        }
        let mut size = buf.len();
        // The max depth limit is 3
        let max_extents = 3;
        let mut limit = 0;
        let mut indexes = self.extents.index_descriptors.clone();

        // If we have no extent descriptors we need to parse extent indexes in order to get them
        if self.extents.extent_descriptors.is_empty() {
            // Check for extent indexes
            while self.extents.depth > 0 && limit != max_extents {
                let mut next_depth = Vec::new();
                for extent_index in indexes {
                    let offset = extent_index.block_number * self.blocksize;
                    let bytes = match read_bytes(offset, self.blocksize, self.reader) {
                        Ok(result) => result,
                        Err(err) => {
                            error!(
                                "[ext4-fs] Could not read extent index bytes at offset {offset}. Wanted {size} bytes. Error: {err:?}"
                            );
                            return Err(Error::new(io::ErrorKind::InvalidData, err));
                        }
                    };
                    let mut extents = match Extents::read_extents(&bytes) {
                        Ok(result) => result,
                        Err(err) => {
                            error!(
                                "[ext4-fs] Could not parse extent index data at offset {offset}. Wanted {size} bytes. Error: {err:?}"
                            );
                            return Err(Error::new(io::ErrorKind::InvalidData, err));
                        }
                    };
                    if extents.depth != 0 {
                        next_depth.append(&mut extents.index_descriptors);
                    }
                    self.extents
                        .extent_descriptors
                        .append(&mut extents.extent_descriptors);
                }
                indexes = next_depth;
                self.extents.depth -= 1;
                limit += 1;
            }
        }

        // Update the BTreeMap
        if self.extents.extent_descriptor_list.len() != self.extents.extent_descriptors.len() {
            for entry in &self.extents.extent_descriptors {
                self.extents
                    .extent_descriptor_list
                    .insert(entry.logical_block_number, entry.clone());
            }
        }

        // If the caller wants to read a very large file all into memory
        // We will have to read multiple blocks
        // We have to accumulate the bytes and return them
        let mut total_bytes: Vec<u8> = Vec::new();
        // If the caller just wants to stream the file
        // We can read small amounts at a time
        let mut bytes = Vec::new();

        // If logical block is zero but the extent BTreeMap does not have 0. Then the beginning of the file is sparse
        if self.logical_block == 0
            && !self.extents.extent_descriptor_list.contains_key(&0)
            && let Some((first_block, _extent)) =
                self.extents.extent_descriptor_list.first_key_value()
        {
            let sparse_size = *first_block as u64 * self.blocksize;
            // Keep "reading" until we have reached the "end" of the sparse data
            if self.disk_position <= sparse_size {
                self.disk_position += size as u64;
                if self.disk_position == sparse_size {
                    self.logical_block = *first_block;

                    self.disk_position = 0;
                }
                return Ok(size);
            }
            // We ready to go to the next block
            self.logical_block = *first_block;
            self.disk_position = 0;
        }

        let tree_list = self.extents.extent_descriptor_list.len();
        while let Some(extent) = self
            .extents
            .extent_descriptor_list
            .get_mut(&self.logical_block)
        {
            let max_position = extent.number_of_blocks as u64 * self.blocksize;

            // We have reached the end if the logical block is larger than the next block (default is 0)
            // If the reader continues to want to read data
            // Return their own buffer
            // Commonly occurs if their is sparse data and the end of a file
            if extent.next_logical_block_number == 0 && self.disk_position >= max_position {
                return Ok(size);
            }

            if self.disk_position >= max_position && extent.block_diff == 0 {
                debug!(
                    "[ext4-fs] disk position {} larger or equal than max {max_position}. file size: {}. file position: {}",
                    self.disk_position, self.file_size, self.file_position
                );
                // If we jumped to a really large offset using seek
                // We need to preserve the offset we are at in the next extent block
                // Ex: For a 200MB file we seek to the end -10 bytes
                // We loop to the next extent, but our offset should not reset
                // We keep subtracting until we get to our correct extent
                // Otherwise if the values are equal we reset to position and start reading at the next extent
                self.disk_position -= extent.number_of_blocks as u64 * self.blocksize;

                self.logical_block = extent.next_logical_block_number;
                continue;
            }

            // We have sparse data before the next extent data
            // Need to handle it
            let sparse_size = extent.block_diff as u64 * self.blocksize;
            if self.disk_position >= max_position {
                debug!(
                    "[ext4-fs] disk postiion now: {}. Diff: {}. sparse: {}. file position: {}",
                    self.disk_position, extent.block_diff, self.total_sparse, self.file_position
                );
                if extent.block_diff != 0 && self.total_sparse < sparse_size {
                    if sparse_size < size as u64 {
                        self.total_sparse += sparse_size;
                        self.file_position += sparse_size;

                        return Ok(sparse_size as usize);
                    }
                    self.total_sparse += size as u64;
                    self.file_position += size as u64;

                    // Keep "reading" until we have reached the "end" of the sparse data
                    return Ok(size);
                }

                self.disk_position = 0;
                self.logical_block = extent.next_logical_block_number;
                self.total_sparse = 0;
                continue;
            }

            // Offset to the extent block. We need to account for our current reader position too
            let offset = (extent.block_number * self.blocksize) + self.disk_position;

            debug!("     [ext4-fs] ### reading offset: {offset}");
            // If the user wants to read more bytes than allocated in a block then we need to reduce our bytes to read
            // We will keep reading until we have enough bytes to fill the user's buffer
            if size as u64 > (extent.number_of_blocks as u64 * self.blocksize) {
                size = (extent.number_of_blocks as u64 * self.blocksize) as usize;
            }
            // Ensure we do not read out of the max offset for an extent
            if (self.disk_position + size as u64) >= max_position {
                let diff = (self.disk_position + size as u64) - max_position;
                size -= diff as usize;
            }
            bytes = match read_bytes(offset, size as u64, self.reader) {
                Ok(result) => result,
                Err(err) => {
                    error!(
                        "[ext4-fs] Could not read data at offset {offset}. Wanted {size} bytes. Error: {err:?}"
                    );
                    return Err(Error::new(io::ErrorKind::InvalidData, err));
                }
            };
            // Make sure we track our position after reading bytes from disk
            self.disk_position += size as u64;
            self.file_position += size as u64;
            debug!(
                "    [ext4-fs] ->   reading disk postiion is now: {}. Diff: {}. sparse: {}. file position: {}",
                self.disk_position, extent.block_diff, self.total_sparse, self.file_position
            );
            if self.disk_position >= max_position && extent.block_diff == 0 {
                // We have reached the end if the logical block is larger than the next block (default is 0)
                // If we only have one extent we do not need to do any additional work
                if tree_list != 1 {
                    self.logical_block = extent.next_logical_block_number;
                    self.disk_position = 0;
                }
            }

            // If the user wants to read more bytes than allocated in a block then we must keep reading
            if buf.len() as u64 > (extent.number_of_blocks as u64 * self.blocksize) {
                total_bytes.append(&mut bytes);

                // If we have read enough bytes. We are done
                if total_bytes.len() >= size {
                    break;
                }
                continue;
            }

            buf[..size].copy_from_slice(&bytes);
            return Ok(size);
        }

        if size >= total_bytes.len() {
            buf[..total_bytes.len()].copy_from_slice(&total_bytes);
            return Ok(total_bytes.len());
        }

        error!(
            "[ext4-fs] Failed to process {} bytes read wanted {}",
            bytes.len(),
            buf.len()
        );
        Err(Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Failed to process {} bytes read wanted {}",
                bytes.len(),
                buf.len()
            ),
        ))
    }
}

impl<'reader, T> Seek for FileReader<'reader, T>
where
    T: std::io::Seek + std::io::Read,
{
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        // Always reset our logical_block tracker whenever we seek
        // We cannot keep track of where a user may seek to and the logical block of the file
        self.logical_block = 0;
        match position {
            std::io::SeekFrom::Start(start_position) => {
                self.file_position = start_position;
                self.disk_position = start_position;
            }
            std::io::SeekFrom::End(end_position) => {
                self.disk_position =
                    (end_position + self.file_size as i64)
                        .try_into()
                        .map_err(|_err| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "seek is out of range of 64-bit position",
                            )
                        })?;
                self.file_position = self.disk_position;
            }
            std::io::SeekFrom::Current(relative_position) => {
                self.disk_position = self
                    .disk_position
                    .try_into()
                    .map_or_else(
                        |_| (self.disk_position as i64) + (relative_position),
                        |pos: i64| pos + relative_position,
                    )
                    .try_into()
                    .map_err(|_err| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "seek is out of range of 64-bit position",
                        )
                    })?;
                self.file_position = self.disk_position;
            }
        }

        Ok(self.disk_position)
    }
}
