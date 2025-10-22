use crate::{
    error::Ext4Error,
    extents::Extents,
    extfs::Ext4Reader,
    structs::{InodePermissions, InodeType},
    utils::{bytes::read_bytes, encoding::base64_encode_standard, strings::extract_utf8_string},
};
use log::{error, info, warn};
use nom::{
    bytes::complete::take,
    number::complete::{le_i32, le_u8, le_u16, le_u32},
};
use std::collections::HashMap;

#[derive(Debug)]
pub struct Inode {
    pub(crate) inode_type: InodeType,
    pub(crate) permissions: Vec<InodePermissions>,
    pub(crate) uid: u16,
    pub(crate) size: u64,
    pub(crate) accessed: i64,
    pub(crate) changed: i64,
    pub(crate) modified: i64,
    pub(crate) deleted: i32,
    pub(crate) gid: u16,
    pub(crate) hard_links: u16,
    blocks_count: u32,
    pub(crate) flags: Vec<InodeFlags>,
    direct_blocks: Vec<u32>,
    indirect_block: u32,
    double_indirect: u32,
    triple_indirect: u32,
    pub(crate) extents: Vec<Extents>,
    file_entry: Vec<u8>,
    nfs: u32,
    acl_block: u32,
    upper_size: u32,
    fragment_offset: u32,
    upper_block_count: u16,
    upper_acl_block: u16,
    upper_uid: u16,
    upper_gid: u16,
    checksum: u16,
    extended_inode_size: u16,
    upper_checksum: u16,
    changed_precision: u32,
    modified_precision: u32,
    accessed_precision: u32,
    pub(crate) created: i64,
    created_precision: u32,
    pub(crate) extended_attributes: HashMap<String, String>,
    pub(crate) symoblic_link: String,
    pub(crate) is_sparse: bool,
}

#[derive(Debug, PartialEq)]
pub(crate) enum InodeFlags {
    SecureDelete,
    Undelete,
    Compressed,
    SynchronousUpdates,
    Immutable,
    AppendOnly,
    NoDump,
    NoAtime,
    Dirty,
    CompressedClusters,
    NoCompression,
    /**Only used on Ext2 and Ext3 */
    _CompressionError,
    Encrypted,
    Index,
    Imagic,
    Journal,
    NoTail,
    TopDirectory,
    DirectorySync,
    HugeFile,
    Extents,
    Verity,
    ExtendedAttribute,
    BlocksEof,
    Snapshot,
    Dax,
    SnapshotDeleted,
    SnapshotShrink,
    Inline,
    ProjectInherit,
    Casefold,
    Reserved,
}

impl Inode {
    /// Read and parse the inode table. This will contain most metadata about files on EXT4 filesystem
    pub(crate) fn read_inode_table<T: std::io::Seek + std::io::Read>(
        reader: &mut Ext4Reader<T>,
        inode: u32,
    ) -> Result<Inode, Ext4Error> {
        let desc_group = (inode - 1) / reader.inodes_per_group;
        let index = (inode - 1) % reader.inodes_per_group;

        // Unwrap is safe because we must initialize descriptors when creating Ext4Reader
        if let Some(desc) = reader
            .descriptors
            .as_ref()
            .unwrap_or(&Vec::new())
            .get(desc_group as usize)
        {
            // Offset is our inode table block + inode index value (inodes are typically 256 bytes)
            // Ex: (1060 * 4096) + 1 * 256
            let offset = (desc.inode_table_block as u64 * reader.blocksize as u64)
                + (index * reader.inode_size as u32) as u64;
            info!(
                "[ext4-fs] Reading offset {offset}. Inode table block: {}. Index: {index}",
                desc.inode_table_block
            );

            let bytes = read_bytes(offset, reader.inode_size as u64, &mut reader.fs)?;
            let dir = match Inode::parse_inode(&bytes, reader) {
                Ok((_, result)) => result,
                Err(err) => {
                    error!("[ext4-fs] Could not parse the directory {err:?}");
                    return Err(Ext4Error::Directory);
                }
            };

            return Ok(dir);
        };

        error!("[ext4-fs] Bad inode provided {inode}");
        Err(Ext4Error::BadInode)
    }

    /// Parse the inode data and get file metadata
    fn parse_inode<'a, T: std::io::Seek + std::io::Read>(
        data: &'a [u8],
        reader: &mut Ext4Reader<T>,
    ) -> nom::IResult<&'a [u8], Inode> {
        let (input, modes) = le_u16(data)?;
        let (input, uid) = le_u16(input)?;
        let (input, size) = le_u32(input)?;

        // If there is NO ExtendedAttribute flag, these are timestamps
        // If the Inode ExtendedAttribute flag is set, these are lower parts of the extended attribute
        let (input, mut accessed_or_checksum) = le_i32(input)?;
        let (input, changed_or_reference_count) = le_i32(input)?;
        let (input, modified_or_inode_extended_attribute) = le_i32(input)?;
        let (input, deleted) = le_i32(input)?;

        let (input, gid) = le_u16(input)?;
        let (input, hard_links) = le_u16(input)?;
        let (input, blocks_count) = le_u32(input)?;
        let (input, flag_data) = le_u32(input)?;
        let flags = Inode::get_flags(flag_data);

        // If the ExtendedAttribute flag is set this is upper part of the extended attribute reference count
        // Otherwise its the lower part of the version
        let (mut remaining, lower_version_or_upper_extended_attributes) = le_u32(input)?;
        let mut symoblic_link = String::new();
        let mut extents = Vec::new();
        if !flags.contains(&InodeFlags::Extents) && !flags.contains(&InodeFlags::Inline) {
            // If target file path is less than 60 bytes
            // It will be stored here
            let path_size: u8 = 60;
            let (input, link_data) = take(path_size)(remaining)?;
            remaining = input;
            if size < path_size as u32 {
                symoblic_link = extract_utf8_string(link_data);
            } else {
                warn!("[ext4-fs] Got large SymbolicLink path: {link_data:?}");
            }
        } else if flags.contains(&InodeFlags::Extents) {
            let extent_size: u8 = 60;
            let (input, extent_data) = take(extent_size)(remaining)?;
            let (_, extent) = Extents::parse_extents(extent_data)?;
            extents.push(extent);
            remaining = input;
        } else if flags.contains(&InodeFlags::Inline) {
            let file_entry_size: u8 = 60;
            let (input, file_data) = take(file_entry_size)(remaining)?;
            warn!("[ext4-tfs] Got Inline data. This is not supported yet. Data: {file_data:?}");
            remaining = input;
        }

        let (input, nfs) = le_u32(remaining)?;
        let (input, acl_block) = le_u32(input)?;
        let (input, upper_size) = le_u32(input)?;
        let (input, fragment_offset) = le_u32(input)?;

        let (input, upper_block_count) = le_u16(input)?;
        let (input, upper_acl_block) = le_u16(input)?;
        let (input, upper_uid) = le_u16(input)?;
        let (input, upper_gid) = le_u16(input)?;
        let (input, checksum) = le_u16(input)?;
        let (input, _unknown) = le_u16(input)?;
        let (input, extended_inode_size) = le_u16(input)?;
        let (input, upper_checksum) = le_u16(input)?;

        let (input, changed_precision) = le_u32(input)?;
        let (input, modified_precision) = le_u32(input)?;
        let (input, accessed_precision) = le_u32(input)?;
        let (input, created) = le_i32(input)?;
        let (input, created_precision) = le_u32(input)?;
        let (input, upper_version) = le_u32(input)?;
        let (input, i_projid) = le_u32(input)?;

        let mut inode = Inode {
            inode_type: Inode::get_file_type(modes),
            permissions: Inode::get_permissions(modes),
            uid,
            size: ((upper_size as u64) << 32) | size as u64,
            accessed: 0,
            changed: 0,
            modified: 0,
            deleted,
            gid,
            hard_links,
            blocks_count,
            flags,
            direct_blocks: Vec::new(),
            indirect_block: 0,
            double_indirect: 0,
            triple_indirect: 0,
            is_sparse: Inode::check_sparse(&extents),
            extents,
            file_entry: Vec::new(),
            nfs,
            acl_block,
            upper_size,
            fragment_offset,
            upper_block_count,
            upper_acl_block,
            upper_uid,
            upper_gid,
            checksum,
            extended_inode_size,
            upper_checksum,
            changed_precision,
            modified_precision,
            accessed_precision,
            created: ((created_precision as i64) << 32) | created as i64,
            created_precision,
            extended_attributes: HashMap::new(),
            symoblic_link,
        };
        if !inode.flags.contains(&InodeFlags::Inline) {
            inode.accessed = Inode::complete_time(accessed_or_checksum, accessed_precision);
            inode.changed = Inode::complete_time(changed_or_reference_count, changed_precision);
            inode.created = Inode::complete_time(created, created_precision);
            inode.modified =
                Inode::complete_time(modified_or_inode_extended_attribute, modified_precision);
        }

        let min_size = 48;
        if input.len() > min_size {
            let (_, attributes) =
                Inode::parse_extended_attributes(input, reader, acl_block as u64, false)?;
            inode.extended_attributes = attributes;
        }

        Ok((input, inode))
    }

    fn complete_time(timestamp: i32, precision: u32) -> i64 {
        let mut full_time = timestamp as i64;
        let bit = 2;
        let mask = (1 << bit) - 1;
        let nano_mask = !0u32 << bit;
        let upper = 32;
        full_time += ((precision & mask) as i64) << upper;
        let nanoseconds = ((precision & nano_mask) >> bit) as i64;

        let adjust_nano = 1000000000;
        full_time = full_time * adjust_nano + nanoseconds;
        full_time
    }

    /// Determine the Inode Filetype
    fn get_file_type(data: u16) -> InodeType {
        if (data & 0x1000) == 0x1000 && data < 0x2000 {
            return InodeType::Pipe;
        } else if ((data & 0x2000) == 0x2000) && data < 0x4000 {
            return InodeType::Device;
        } else if (data & 0x4000) == 0x4000 && data < 0x6000 {
            return InodeType::Directory;
        } else if (data & 0x6000) == 0x6000 {
            return InodeType::BlockDevice;
        } else if (data & 0x8000) == 0x8000 && data < 0xa000 {
            return InodeType::File;
        } else if (data & 0xa000) == 0xa000 && data < 0xc000 {
            return InodeType::SymbolicLink;
        } else if (data & 0xc000) == 0xc000 {
            return InodeType::Socket;
        }
        warn!("[ext4-fs] Got unknown file {data}");
        InodeType::Unknown
    }

    /// Determine permissions for a file
    fn get_permissions(data: u16) -> Vec<InodePermissions> {
        let mut perms = Vec::new();
        if (data & 0x1) == 0x1 {
            perms.push(InodePermissions::ExecuteOther);
        }
        if (data & 0x2) == 0x2 {
            perms.push(InodePermissions::WriteOther);
        }
        if (data & 0x4) == 0x4 {
            perms.push(InodePermissions::ReadOther);
        }

        if (data & 0x8) == 0x8 {
            perms.push(InodePermissions::ExecuteGroup);
        }
        if (data & 0x10) == 0x10 {
            perms.push(InodePermissions::WriteGroup);
        }
        if (data & 0x20) == 0x20 {
            perms.push(InodePermissions::ReadGroup);
        }

        if (data & 0x40) == 0x40 {
            perms.push(InodePermissions::ExecuteUser);
        }
        if (data & 0x80) == 0x80 {
            perms.push(InodePermissions::WriteUser);
        }
        if (data & 0x100) == 0x100 {
            perms.push(InodePermissions::ReadUser);
        }

        if (data & 0x200) == 0x200 {
            perms.push(InodePermissions::Sticky);
        }
        if (data & 0x400) == 0x400 {
            perms.push(InodePermissions::Sgid);
        }
        if (data & 0x800) == 0x800 {
            perms.push(InodePermissions::Suid);
        }

        perms
    }

    /// Get the inode flags for a file
    fn get_flags(data: u32) -> Vec<InodeFlags> {
        let mut flags = Vec::new();
        if (data & 0x1) == 0x1 {
            flags.push(InodeFlags::SecureDelete);
        }
        if (data & 0x2) == 0x2 {
            flags.push(InodeFlags::Undelete);
        }
        if (data & 0x4) == 0x4 {
            flags.push(InodeFlags::Compressed);
        }
        if (data & 0x8) == 0x8 {
            flags.push(InodeFlags::SynchronousUpdates);
        }
        if (data & 0x10) == 0x10 {
            flags.push(InodeFlags::Immutable);
        }
        if (data & 0x20) == 0x20 {
            flags.push(InodeFlags::AppendOnly);
        }
        if (data & 0x40) == 0x40 {
            flags.push(InodeFlags::NoDump);
        }
        if (data & 0x80) == 0x80 {
            flags.push(InodeFlags::NoAtime);
        }
        if (data & 0x100) == 0x100 {
            flags.push(InodeFlags::Dirty);
        }
        if (data & 0x200) == 0x200 {
            flags.push(InodeFlags::CompressedClusters);
        }
        if (data & 0x400) == 0x400 {
            flags.push(InodeFlags::NoCompression);
        }
        if (data & 0x800) == 0x800 {
            flags.push(InodeFlags::Encrypted);
        }
        if (data & 0x1000) == 0x1000 {
            flags.push(InodeFlags::Index);
        }
        if (data & 0x2000) == 0x2000 {
            flags.push(InodeFlags::Imagic);
        }
        if (data & 0x4000) == 0x4000 {
            flags.push(InodeFlags::Journal);
        }
        if (data & 0x8000) == 0x8000 {
            flags.push(InodeFlags::NoTail);
        }
        if (data & 0x10000) == 0x10000 {
            flags.push(InodeFlags::DirectorySync);
        }
        if (data & 0x20000) == 0x20000 {
            flags.push(InodeFlags::TopDirectory);
        }
        if (data & 0x40000) == 0x40000 {
            flags.push(InodeFlags::HugeFile);
        }
        if (data & 0x80000) == 0x80000 {
            flags.push(InodeFlags::Extents);
        }
        if (data & 0x100000) == 0x100000 {
            flags.push(InodeFlags::Verity);
        }
        if (data & 0x200000) == 0x200000 {
            flags.push(InodeFlags::ExtendedAttribute);
        }
        if (data & 0x400000) == 0x400000 {
            flags.push(InodeFlags::BlocksEof);
        }
        if (data & 0x1000000) == 0x1000000 {
            flags.push(InodeFlags::Snapshot);
        }
        if (data & 0x2000000) == 0x2000000 {
            flags.push(InodeFlags::Dax);
        }
        if (data & 0x4000000) == 0x4000000 {
            flags.push(InodeFlags::SnapshotDeleted);
        }
        if (data & 0x8000000) == 0x8000000 {
            flags.push(InodeFlags::SnapshotShrink);
        }
        if (data & 0x10000000) == 0x10000000 {
            flags.push(InodeFlags::Inline);
        }
        if (data & 0x20000000) == 0x20000000 {
            flags.push(InodeFlags::ProjectInherit);
        }
        if (data & 0x40000000) == 0x40000000 {
            flags.push(InodeFlags::Casefold);
        }
        if (data & 0x80000000) == 0x80000000 {
            flags.push(InodeFlags::Reserved);
        }
        flags
    }

    /// Get the extended attributes for file
    fn parse_extended_attributes<'a, T: std::io::Seek + std::io::Read>(
        data: &'a [u8],
        reader: &mut Ext4Reader<T>,
        ea_inode: u64,
        read_inode: bool,
    ) -> nom::IResult<&'a [u8], HashMap<String, String>> {
        let (mut remaining, sig) = le_u32(data)?;
        let extended_attribute_sig = 3925999616;
        if sig != extended_attribute_sig {
            return Ok((data, HashMap::new()));
        }

        // An extended attribute may live in its own inode
        // However a file may have multiple extended attributes in both dedicated inodes and within the remaining bytes of the file's original inode
        // We parse both. But we parse the dedicated extended attribute inodes after parsing the remaining bytes in original inode
        if read_inode {
            let (input, _ref_count) = le_u32(remaining)?;
            let (input, _number_blocks) = le_u32(input)?;
            let (input, _attributes_hash) = le_u32(input)?;
            let (input, _checksum) = le_u32(input)?;
            let reserved_size: u8 = 12;
            let (input, _reserved) = take(reserved_size)(input)?;
            remaining = input;
        }

        let (input, name_size) = le_u8(remaining)?;
        let (input, name_index) = le_u8(input)?;
        let (input, value_data_offset) = le_u16(input)?;
        let (input, value_inode) = le_u32(input)?;
        let (input, value_size) = le_u32(input)?;
        let (input, attribute_entry_hash) = le_u32(input)?;

        let (_input, name_data) = take(name_size)(input)?;
        let name = extract_utf8_string(name_data);
        let index_name = match name_index {
            0 => String::new(),
            1 => String::from("user."),
            2 => String::from("system.posix_acl_access"),
            3 => String::from("system.posix_acl_default"),
            4 => String::from("trusted."),
            6 => String::from("security."),
            7 => String::from("system."),
            8 => String::from("system.richacl"),
            _ => format!("Unknown: {name_index}"),
        };
        if read_inode {
            remaining = data;
        }
        let (value_start, _) = take(value_data_offset)(remaining)?;
        let (input, value_data) = take(value_size)(value_start)?;
        let mut value = extract_utf8_string(value_data);
        // Extended attributes can be either a string or binary
        // No way to determine which though
        // If we failed to extract a string. Its probably binary
        if value.starts_with("[ext4fs] ") {
            value = base64_encode_standard(value_data);
        }
        let mut attributes = HashMap::new();
        attributes.insert(format!("{index_name}{name}"), value);

        let ea_in_inode = 0;
        // Have another extended attribute!
        // The ACL is an inode!
        if ea_inode != ea_in_inode {
            let offset = ea_inode * reader.blocksize as u64;
            let bytes = match read_bytes(offset, reader.blocksize as u64, &mut reader.fs) {
                Ok(result) => result,
                Err(err) => {
                    error!(
                        "[ext4-fs] Could not read extended inode {ea_inode} attribute at offset {offset}: {err:?}"
                    );
                    return Ok((input, attributes));
                }
            };
            // Parse the extended attribute bytes. It should be safe to recursively call this since we do not provide another inode
            // We will also parse the extra data like ref_count, number_blocks, hash, and checksum
            let no_additional_inode = 0;
            let ea_attributes = match Inode::parse_extended_attributes(
                &bytes,
                reader,
                no_additional_inode,
                true,
            ) {
                Ok((_, results)) => results,
                Err(err) => {
                    error!(
                        "[ext4-fs] Could not parse extended inode {ea_inode} attribute at offset {offset}: {err:?}"
                    );
                    return Ok((input, attributes));
                }
            };
            attributes.extend(ea_attributes);
        }

        Ok((input, attributes))
    }

    fn check_sparse(extents: &[Extents]) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        extfs::Ext4Reader,
        inode::{Inode, InodeType},
    };
    use std::{fs::File, io::BufReader, path::PathBuf};

    #[test]
    fn test_parse_inode() {
        let test = [
            237, 65, 0, 0, 0, 0, 0, 0, 142, 143, 129, 104, 142, 143, 129, 104, 142, 143, 129, 104,
            142, 143, 129, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 8, 0, 0, 0, 10, 243, 0, 0, 4,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 50, 190,
            248, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 238, 124, 0, 0,
            32, 0, 211, 235, 0, 97, 214, 229, 0, 97, 214, 229, 0, 97, 214, 229, 254, 136, 129, 104,
            0, 149, 22, 204, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/images/test.img");
        let reader = File::open(test_location.to_str().unwrap()).unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
        let (_, results) = Inode::parse_inode(&test, &mut ext4_reader).unwrap();
        assert_eq!(results.accessed, 1753321358964008000);
        assert_eq!(results.inode_type, InodeType::Directory);
        assert_eq!(results.hard_links, 0);
        assert_eq!(results.created, 1753319678856008000);
        assert_eq!(results.modified, 1753321358964008000);
        assert_eq!(results.changed, 1753321358964008000);
    }

    #[test]
    fn test_get_flags() {
        let test = [
            0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000,
            0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000,
            0x1000000, 0x2000000, 0x4000000, 0x8000000,
        ];
        for entry in test {
            let flag = Inode::get_flags(entry);
            assert!(!flag.is_empty())
        }
    }

    #[test]
    fn test_get_file_type() {
        let test = [0x1000, 0x2000, 0x4000, 0x6000, 0x8000, 0xa000, 0xc000];
        for entry in test {
            assert_ne!(Inode::get_file_type(entry), InodeType::Unknown);
        }
    }

    #[test]
    fn test_complete_time() {
        let test = 1753321358;
        let precision = 400343432;
        assert_eq!(Inode::complete_time(test, precision), 1753321358100085858);
    }

    #[test]
    fn test_root_inode() {
        let test = [
            237, 65, 0, 0, 0, 16, 0, 0, 210, 141, 129, 104, 195, 141, 129, 104, 195, 141, 129, 104,
            0, 0, 0, 0, 0, 0, 19, 0, 8, 0, 0, 0, 0, 0, 8, 0, 60, 1, 0, 0, 10, 243, 1, 0, 4, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 186, 139, 0, 0, 32, 0, 162,
            149, 0, 137, 11, 102, 0, 137, 11, 102, 0, 49, 215, 126, 235, 136, 129, 104, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/images/test.img");
        let reader = File::open(test_location.to_str().unwrap()).unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
        let (_, results) = Inode::parse_inode(&test, &mut ext4_reader).unwrap();
        assert_eq!(results.extents.len(), 1);
        assert_eq!(results.accessed, 1753320914532008000);
        assert_eq!(results.created, 1753319659000000000);
    }

    #[test]
    fn test_parse_extended_attributes() {
        let tests = [
            0, 0, 2, 234, 7, 6, 52, 0, 0, 0, 0, 0, 37, 0, 0, 0, 0, 0, 0, 0, 115, 101, 108, 105,
            110, 117, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 117, 110, 99, 111, 110, 102, 105, 110, 101, 100, 95, 117, 58, 111, 98,
            106, 101, 99, 116, 95, 114, 58, 117, 110, 108, 97, 98, 101, 108, 101, 100, 95, 116, 58,
            115, 48, 0, 0, 0, 0,
        ];
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/images/test.img");
        let reader = File::open(test_location.to_str().unwrap()).unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();

        let (_, results) =
            Inode::parse_extended_attributes(&tests, &mut ext4_reader, 0, false).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_parse_inode_symoblic_link() {
        let test = [
            255, 161, 232, 3, 25, 0, 0, 0, 244, 24, 227, 104, 244, 24, 227, 104, 244, 24, 227, 104,
            0, 0, 0, 0, 232, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 47, 111, 112, 116, 47,
            111, 115, 113, 117, 101, 114, 121, 47, 98, 105, 110, 47, 111, 115, 113, 117, 101, 114,
            121, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 52, 57, 14, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 156, 93, 0, 0, 32, 0, 180, 45, 180, 191, 209, 53, 180, 191, 209, 53,
            204, 200, 14, 54, 244, 24, 227, 104, 180, 191, 209, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            2, 234, 7, 6, 52, 0, 0, 0, 0, 0, 37, 0, 0, 0, 0, 0, 0, 0, 115, 101, 108, 105, 110, 117,
            120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 117, 110, 99, 111, 110, 102, 105, 110, 101, 100, 95, 117, 58, 111, 98, 106, 101,
            99, 116, 95, 114, 58, 117, 110, 108, 97, 98, 101, 108, 101, 100, 95, 116, 58, 115, 48,
            0, 0, 0, 0,
        ];

        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/images/test.img");
        let reader = File::open(test_location.to_str().unwrap()).unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
        let (_, results) = Inode::parse_inode(&test, &mut ext4_reader).unwrap();
        assert_eq!(results.accessed, 1759713524226734643);
        assert_eq!(results.inode_type, InodeType::SymbolicLink);
        assert_eq!(results.hard_links, 1);
        assert_eq!(results.created, 1759713524225734637);
        assert_eq!(results.symoblic_link, "/opt/osquery/bin/osqueryd")
    }
}
