use crate::{
    error::Ext4Error,
    extfs::Ext4Reader,
    structs::{BlockFlags, Descriptor},
    superblock::block::IncompatFlags,
    utils::bytes::read_bytes,
};
use log::error;
use nom::number::complete::{le_u16, le_u32};

/**
 * Get Group Descriptor Table info. To capture the entire table you need to:
 * `descriptor_count` = `SuperBlock.number_blocks`/`SuperBlock.number_blocks_per_block_group`
 * Each Group Descriptor Table size is equal to `SuperBlock.block_size`
 *
 * Group Descriptor Table size = `descriptor_count` * `SuperBlock.block_size`
 */
impl Descriptor {
    /// Read and parse the descriptor data from the EXT4 filesystem
    pub(crate) fn read_descriptor<T: std::io::Seek + std::io::Read>(
        reader: &mut Ext4Reader<T>,
    ) -> Result<Vec<Descriptor>, Ext4Error> {
        let boot_sector_size = 1024;
        // May need to account for the boot sector at offset 0
        // Size will be 1024 bytes
        let adjust_offset = if reader.blocksize == boot_sector_size {
            2
        } else {
            1
        };

        // If we have small blocksize (1024) we need to adjust to ensure we are at the offset for the descriptors
        // Descriptors always follow the superblock
        // Ex: Blocksize 1024
        // Offset: 0 - boot sector
        // Offset: 1024 - Superblock
        // Offset: 2048 - Descriptors
        // Ex: Blocksize 4096
        // Offset: 0 - boot sector
        // Offset: 1024 - Superblock - 1024 bytes in size. We do not need to adjust because the 4096 block includes both boot sector and superblock
        // Offset: 4096 - Descriptors
        let offset = reader.blocksize as u64 * adjust_offset + reader.offset_start;
        let mut bytes = 32;
        let desc_count = reader.number_blocks / reader.blocks_per_group;

        let mut count = 0;
        let is_bit64 = reader.incompat_flags.contains(&IncompatFlags::Bit64);
        if is_bit64 {
            bytes = 64;
        }
        let mut descs = Vec::new();
        while count < desc_count || count == 0 {
            let bytes = read_bytes(offset + (count as u64 * bytes), bytes, &mut reader.fs)?;
            let desc = match Descriptor::parse_descriptor(&bytes, is_bit64) {
                Ok((_, result)) => result,
                Err(err) => {
                    error!("[ext4-fs] Could not parse the descriptor {err:?}");
                    return Err(Ext4Error::Descriptor);
                }
            };
            count += 1;
            descs.push(desc);
        }

        Ok(descs)
    }

    /// Parse the Group Descriptor Table. Always follows the Superblock
    fn parse_descriptor(data: &[u8], is_bit64: bool) -> nom::IResult<&[u8], Descriptor> {
        let (input, bitmap_block) = le_u32(data)?;
        let (input, bitmap_inode) = le_u32(input)?;
        let (input, inode_table_block) = le_u32(input)?;

        let (input, unallocated_blocks) = le_u16(input)?;
        let (input, unallocated_inodes) = le_u16(input)?;
        let (input, directories) = le_u16(input)?;
        let (input, block_group_flags_data) = le_u16(input)?;

        let (input, exclude_bitmap_block) = le_u32(input)?;
        let (input, block_bitmap_checksum) = le_u16(input)?;
        let (input, inode_bitmap_checksum) = le_u16(input)?;
        let (input, unused_inodes) = le_u16(input)?;
        let (input, checksum) = le_u16(input)?;

        let mut info = Descriptor {
            bitmap_block,
            bitmap_inode,
            inode_table_block: inode_table_block as u64,
            unallocated_blocks,
            unallocated_inodes,
            directories,
            block_group_flags: Descriptor::block_flags(block_group_flags_data),
            exclude_bitmap_block,
            block_bitmap_checksum,
            inode_bitmap_checksum,
            unused_inodes,
            checksum,
            upper_bitmap_block: 0,
            upper_bitmap_inode: 0,
            upper_inode_table_block: 0,
            upper_unallocated_blocks: 0,
            upper_unallocated_inodes: 0,
            upper_directories: 0,
            upper_unused_inodes: 0,
            upper_exclude_bitmap_block: 0,
            upper_block_bitmap_checksum: 0,
            upper_inode_bitmap_checksum: 0,
        };

        if !is_bit64 {
            return Ok((input, info));
        }

        let (input, upper_bitmap_block) = le_u32(input)?;
        let (input, upper_bitmap_inode) = le_u32(input)?;
        let (input, upper_inode_table_block) = le_u32(input)?;

        let (input, upper_unallocated_blocks) = le_u16(input)?;
        let (input, upper_unallocated_inodes) = le_u16(input)?;
        let (input, upper_directories) = le_u16(input)?;
        let (input, upper_unused_inodes) = le_u16(input)?;

        let (input, upper_exclude_bitmap_block) = le_u32(input)?;
        let (input, upper_block_bitmap_checksum) = le_u16(input)?;
        let (input, upper_inode_bitmap_checksum) = le_u16(input)?;
        let (input, _reserved) = le_u32(input)?;

        info.upper_bitmap_block = upper_bitmap_block;
        info.upper_bitmap_inode = upper_bitmap_inode;
        info.upper_inode_table_block = upper_inode_table_block;
        info.inode_table_block |= (upper_inode_table_block as u64) << 32;
        info.upper_unallocated_blocks = upper_unallocated_blocks;
        info.upper_unallocated_inodes = upper_unallocated_inodes;
        info.upper_directories = upper_directories;
        info.upper_unused_inodes = upper_unused_inodes;
        info.upper_exclude_bitmap_block = upper_exclude_bitmap_block;
        info.upper_block_bitmap_checksum = upper_block_bitmap_checksum;
        info.upper_inode_bitmap_checksum = upper_inode_bitmap_checksum;

        Ok((input, info))
    }

    /// Determine the block flags
    fn block_flags(data: u16) -> Vec<BlockFlags> {
        let mut flags = Vec::new();
        if (data & 0x1) == 0x1 {
            flags.push(BlockFlags::InodeBitmapUnused);
        }
        if (data & 0x2) == 0x2 {
            flags.push(BlockFlags::BlockBitmapUnused);
        }
        if (data & 0x4) == 0x4 {
            flags.push(BlockFlags::InodeTableEmpty);
        }
        flags
    }
}

#[cfg(test)]
mod tests {
    use crate::descriptors::Descriptor;
    use std::{fs::read, path::PathBuf};

    #[test]
    fn test_parse_descriptor() {
        let test = [
            4, 4, 0, 0, 20, 4, 0, 0, 36, 4, 0, 0, 245, 91, 204, 31, 3, 0, 4, 0, 0, 0, 0, 0, 139,
            74, 167, 172, 183, 31, 231, 240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 98, 236, 4, 58, 0, 0, 0, 0,
        ];

        let (_, result) = Descriptor::parse_descriptor(&test, true).unwrap();
        assert_eq!(result.directories, 3);
        assert_eq!(result.bitmap_block, 1028);
        assert_eq!(result.upper_inode_bitmap_checksum, 14852);
        assert_eq!(result.inode_table_block, 1060);
    }

    #[test]
    fn test_block_flags() {
        let test = [1, 2, 4];
        for entry in test {
            assert_eq!(Descriptor::block_flags(entry).len(), 1);
        }
    }

    #[test]
    fn test_parse_descriptor_full() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/debian/bookworm/descriptor.raw");
        let mut test = read(test_location.to_str().unwrap()).unwrap();

        let mut total = 0;
        while test.len() >= 64 {
            let (remaining, result) = Descriptor::parse_descriptor(&test, true).unwrap();
            assert_ne!(result.bitmap_block, 0);
            test = remaining.to_vec();
            total += 1;
        }

        assert_eq!(total, 64);
    }
}
