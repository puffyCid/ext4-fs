use crate::{
    error::Ext4Error,
    extfs::Ext4Reader,
    structs::{Directory, Extents, FileType},
    utils::{bytes::read_bytes, strings::extract_utf8_string},
};
use log::error;
use nom::{
    bytes::complete::take,
    number::complete::{le_u8, le_u16, le_u32},
};
use std::collections::HashMap;

impl Directory {
    /// Read the directory attribute data associated with an directory
    pub(crate) fn read_directory_data<T: std::io::Seek + std::io::Read>(
        reader: &mut Ext4Reader<T>,
        extent: &Extents,
    ) -> Result<Vec<HashMap<u64, Directory>>, Ext4Error> {
        let mut dirs = Vec::new();
        if extent.depth == 0 {
            for entry in &extent.extent_descriptors {
                let offset = entry.lower_part_physical_block_number as u64
                    * reader.blocksize as u64
                    + reader.offset_start;
                let size = entry.number_of_blocks as u64 * reader.blocksize as u64;
                let bytes = read_bytes(offset, size, &mut reader.fs)?;

                let dir = match Directory::parse_linear_directory(&bytes) {
                    Ok((_, result)) => result,
                    Err(err) => {
                        error!("[ext4-fs] Failed to parse linear directory: {err:?}");
                        continue;
                    }
                };
                dirs.push(dir);
            }
        }
        for entry in &extent.index_descriptors {
            let offset = entry.lower_part_physical_block_number as u64 * reader.blocksize as u64;
            let bytes = read_bytes(offset, reader.blocksize as u64, &mut reader.fs)?;
            let extents = Extents::read_extents(&bytes)?;
            for entry in &extents.extent_descriptors {
                let offset =
                    entry.lower_part_physical_block_number as u64 * reader.blocksize as u64;
                let size = entry.number_of_blocks as u64 * reader.blocksize as u64;
                let bytes = read_bytes(offset, size, &mut reader.fs)?;

                let dir = match Directory::parse_linear_directory(&bytes) {
                    Ok((_, result)) => result,
                    Err(err) => {
                        error!("[ext4-fs] Failed to parse linear directory: {err:?}");
                        continue;
                    }
                };
                dirs.push(dir);
            }
        }

        Ok(dirs)
    }

    /// Parse a linear formatted directory. These are the most common types
    fn parse_linear_directory(data: &[u8]) -> nom::IResult<&[u8], HashMap<u64, Directory>> {
        let mut remaining = data;

        let mut dirs = HashMap::new();
        let min_size = 9;
        while remaining.len() > min_size {
            let (input, inode) = le_u32(remaining)?;
            if inode == 0 {
                break;
            }
            let (input, entry_size) = le_u16(input)?;

            let adjust = 6;
            if entry_size < adjust {
                break;
            }
            // Entry size includes inode and entry_size itself. We already nom'ed those away
            let (input, entry_data) = take(entry_size - adjust)(input)?;
            remaining = input;

            let (input, name_size) = le_u8(entry_data)?;
            let (input, file_type) = le_u8(input)?;
            let (_, name_data) = take(name_size)(input)?;

            let name = extract_utf8_string(name_data);
            if name == "." {
                continue;
            }

            let dir = Directory {
                inode,
                file_type: Directory::get_file_type(file_type),
                name,
            };
            dirs.insert(inode as u64, dir);
        }

        Ok((remaining, dirs))
    }

    /// Determine File type
    fn get_file_type(data: u8) -> FileType {
        match data {
            1 => FileType::File,
            2 => FileType::Directory,
            3 => FileType::Device,
            4 => FileType::Block,
            5 => FileType::FifoQueue,
            6 => FileType::Socket,
            7 => FileType::SymbolicLink,
            _ => FileType::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::directory::{Directory, FileType};
    use std::{fs::read, path::PathBuf};

    #[test]
    fn test_parse_linear_directory() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/debian/bookworm/root.raw");
        let test = read(test_location.to_str().unwrap()).unwrap();

        let (_, result) = Directory::parse_linear_directory(&test).unwrap();
        assert_eq!(result.len(), 26);
        assert_eq!(result.get(&261121).unwrap().name, "var");
        assert_eq!(result.get(&261121).unwrap().inode, 261121);
        assert_eq!(result.get(&261121).unwrap().file_type, FileType::Directory);

        assert_eq!(result.get(&261122).unwrap().name, "dev");
        assert_eq!(result.get(&261122).unwrap().inode, 261122);
        assert_eq!(result.get(&261122).unwrap().file_type, FileType::Directory);

        assert_eq!(result.get(&38).unwrap().name, "initrd.img");
        assert_eq!(result.get(&38).unwrap().inode, 38);
        assert_eq!(result.get(&38).unwrap().file_type, FileType::SymbolicLink);
    }

    #[test]
    fn test_get_file_type() {
        let test = [1, 2, 3, 4, 5, 6, 7];
        for entry in test {
            assert_ne!(Directory::get_file_type(entry), FileType::Unknown);
        }
    }
}
