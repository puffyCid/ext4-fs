use crate::{
    descriptors::Descriptor,
    error::Ext4Error,
    extents::{ExtentDescriptor, Extents},
    extfs::Ext4Reader,
    superblock::block::IncompatFlags,
    utils::bytes::read_bytes,
};
use log::error;
use std::io::{self, BufReader, Error, Read, Seek, SeekFrom};

pub struct FileReader<'reader, T>
where
    T: std::io::Seek + std::io::Read,
{
    reader: &'reader mut BufReader<T>,
    blocksize: u16,
    number_blocks: u32,
    inode_size: u16,
    inodes_per_group: u32,
    incompat_flags: Vec<IncompatFlags>,
    descriptors: Vec<Descriptor>,
    extents: Vec<Extents>,
    current_inode: u64,
    disk_position: u64,
    file_position: u64,
    fs_size: u64,
    file_size: u64,
}

impl<'reader, T: io::Seek + io::Read> Ext4Reader<T> {
    pub(crate) fn file_reader(
        &'reader mut self,
        extents: &[Extents],
        file_size: u64,
    ) -> FileReader<'reader, T> {
        FileReader {
            reader: &mut self.fs,
            blocksize: self.blocksize,
            number_blocks: self.number_blocks,
            inode_size: self.inode_size,
            inodes_per_group: self.inodes_per_group,
            incompat_flags: self.incompat_flags.clone(),
            // Unwrap is ok because self.descriptors should not be None because Ext4Reader must be initialized with it
            descriptors: self.descriptors.as_ref().unwrap_or(&Vec::new()).to_vec(),
            extents: extents.to_vec(),
            current_inode: self.current_inode,
            disk_position: 0,
            file_position: 0,
            fs_size: self.fs_size,
            file_size,
        }
    }
}

impl<'reader, T> Read for FileReader<'reader, T>
where
    T: std::io::Seek + std::io::Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut size = buf.len();
        // The max depth limit is 3
        let max_extents = 3;
        let mut limit = 0;
        println!("extents: {:?}", self.extents);
        for extent in &mut self.extents {
            let mut indexes = extent.index_descriptors.clone();

            while extent.depth > 0 && limit != max_extents {
                let mut next_depth = Vec::new();
                for extent_index in indexes {
                    let offset = extent_index.lower_part_physical_block_number as u64
                        * self.blocksize as u64;
                    let bytes = match read_bytes(offset, self.blocksize as u64, self.reader) {
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
                    extent
                        .extent_descriptors
                        .append(&mut extents.extent_descriptors);
                }
                indexes = next_depth;
                extent.depth -= 1;
                limit += 1;
            }

            if !extent.extent_descriptors.is_empty() {
                // If the caller wants to read a very large file all into memory
                // We will have to read multiple blocks
                // We have to accumulate the bytes and return them
                let mut total_bytes = Vec::new();
                // If the caller just wants to stream the file
                // We can read small amounts at a time
                let mut bytes = Vec::new();

                let mut next_extent = false;
                for entry in &extent.extent_descriptors {
                    // If our position does not match the logical block value
                    // Then we are technically not reading at the correct spot
                    // Commonly seen with sparse files
                    // Extents point to the data and not sparse values
                    // We need to add sparse data ourselves (zeros)
                    let sparse_size = entry.logical_block_number as u64 * self.blocksize as u64;
                    println!("disk position now: {}. Sparse is {sparse_size}. file position is: {}", self.disk_position, self.file_position);
                    if self.file_position < sparse_size {
                        self.disk_position += size as u64;
                        self.file_position += size as u64;
                        return Ok(size);
                    } else if self.file_position == sparse_size {
                        println!("reset!");
                        // Reading sparse "data" is complete. Can start to read the actual data now
                        self.disk_position = 0;
                    }

                    // If our current position is larger than allocated blocks in our current extent
                    // We must move to the next one. We have read all of the data in the current extent
                    if self.disk_position >= (entry.number_of_blocks as u64 * self.blocksize as u64) {
                        next_extent = true;

                        // Reset our position since we are now at a new extent
                        self.disk_position = 0;
                        // Go the next extent
                        continue;
                    }

                    // Offset to the extent block. We need to account for our current reader position too
                    let offset = (entry.lower_part_physical_block_number as u64
                        * self.blocksize as u64)
                        + self.disk_position;

                    println!("reading at offset {offset}. Position {}", self.disk_position);
                    // If the user wants to read more bytes than allocated in a block then we need to reduce our bytes to read
                    // We will keep reading until we have enough bytes to fill the user's buffer
                    if size as u64 > (entry.number_of_blocks as u64 * self.blocksize as u64) {
                        size = (entry.number_of_blocks as u64 * self.blocksize as u64) as usize;
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

                    // If the user wants to read more bytes than allocated in a block then we must keep reading
                    if buf.len() as u64 > (entry.number_of_blocks as u64 * self.blocksize as u64) {
                        total_bytes.append(&mut bytes);
                        continue;
                    }

                    // We read bytes from the next extent
                    // We need remove the old one now
                    if next_extent {
                        break;
                    }
                    buf[..size].copy_from_slice(&bytes);
                    return Ok(size);
                }

                // Remove old extent. We read all the data from the extent.
                if next_extent && !extent.extent_descriptors.is_empty() {
                    if total_bytes.is_empty() {
                        if bytes.len() != size {
                            buf[..bytes.len()].copy_from_slice(&bytes);
                        } else {
                            buf[..size].copy_from_slice(&bytes);
                        }
                    }
                    extent.extent_descriptors.remove(0);
                    return Ok(size);
                }

                if size >= total_bytes.len() {
                    buf[..total_bytes.len()].copy_from_slice(&total_bytes);
                    return Ok(total_bytes.len());
                }
                //panic!("total bytes size: {}. buf size: {size}", total_bytes.len());
                // Since blocks are typically 4096 bytes. We may have read too much data at the last block
                buf[..size].copy_from_slice(&total_bytes[..size]);
                return Ok(size);
            }
        }

        Ok(0)
    }
}

impl<'reader, T> Seek for FileReader<'reader, T>
where
    T: std::io::Seek + std::io::Read,
{
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        match position {
            std::io::SeekFrom::Start(start_position) => self.disk_position = start_position,
            std::io::SeekFrom::End(end_position) => {
                self.disk_position =
                    (end_position + self.fs_size as i64)
                        .try_into()
                        .map_err(|_err| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "seek is out of range of 64-bit position",
                            )
                        })?;
            }
            std::io::SeekFrom::Current(relative_position) => {
                self.disk_position = self
                    .disk_position
                    .try_into()
                    .map_or_else(
                        |_| {
                            ((self.disk_position as i128) + (relative_position as i128))
                                .try_into()
                                .unwrap()
                        },
                        |pos: i64| pos + relative_position,
                    )
                    .try_into()
                    .map_err(|_err| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "seek is out of range of 64-bit position",
                        )
                    })?;
            }
        }

        Ok(self.disk_position)
    }
}
