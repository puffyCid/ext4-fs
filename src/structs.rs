use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug)]
pub struct Inode {
    pub inode_type: InodeType,
    pub permissions: Vec<InodePermissions>,
    pub uid: u16,
    pub size: u64,
    pub accessed: i64,
    pub changed: i64,
    pub modified: i64,
    pub deleted: i32,
    pub gid: u16,
    pub hard_links: u16,
    pub blocks_count: u32,
    pub flags: Vec<InodeFlags>,
    pub direct_blocks: Vec<u32>,
    pub indirect_block: u32,
    pub double_indirect: u32,
    pub triple_indirect: u32,
    pub extents: Option<Extents>,
    pub file_entry: Vec<u8>,
    pub nfs: u32,
    pub acl_block: u32,
    pub upper_size: u32,
    pub fragment_offset: u32,
    pub upper_block_count: u16,
    pub upper_acl_block: u16,
    pub upper_uid: u16,
    pub upper_gid: u16,
    pub checksum: u16,
    pub extended_inode_size: u16,
    pub upper_checksum: u16,
    pub changed_precision: u32,
    pub modified_precision: u32,
    pub accessed_precision: u32,
    pub created: i64,
    pub created_precision: u32,
    pub extended_attributes: HashMap<String, String>,
    pub symoblic_link: String,
    pub is_sparse: bool,
}

#[derive(Debug, PartialEq)]
pub enum InodeFlags {
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
#[derive(Debug, Clone)]
pub struct Descriptor {
    /**If IncompatFlags.Bit64 enabled then contains lower 32 bit value */
    pub bitmap_block: u32,
    /**If IncompatFlags.Bit64 enabled then contains lower 32 bit value */
    pub bitmap_inode: u32,
    /**If IncompatFlags.Bit64 enabled then contains lower 32 bit value */
    pub inode_table_block: u64,
    /**Count of unallocated blocks. If IncompatFlags.Bit64 enabled then contains lower 16 bit value  */
    pub unallocated_blocks: u16,
    /**Count of unallocated inodes. If IncompatFlags.Bit64 enabled then contains lower 16 bit value */
    pub unallocated_inodes: u16,
    /**Count of directories. If IncompatFlags.Bit64 enabled then contains lower 16 bit value */
    pub directories: u16,
    pub block_group_flags: Vec<BlockFlags>,
    /**If IncompatFlags.Bit64 enabled then contains lower 32 bit value */
    pub exclude_bitmap_block: u32,
    /**If IncompatFlags.Bit64 enabled then contains lower 16 bit value */
    pub block_bitmap_checksum: u16,
    /**If IncompatFlags.Bit64 enabled then contains lower 16 bit value */
    pub inode_bitmap_checksum: u16,
    /**If IncompatFlags.Bit64 enabled then contains lower 16 bit value */
    pub unused_inodes: u16,
    pub checksum: u16,
    /**If IncompatFlags.Bit64 enabled and descriptors > 32 bytes */
    pub upper_bitmap_block: u32,
    /**If IncompatFlags.Bit64 enabled and descriptors > 32 bytes */
    pub upper_bitmap_inode: u32,
    /**If IncompatFlags.Bit64 enabled and descriptors > 32 bytes */
    pub upper_inode_table_block: u32,
    /**If IncompatFlags.Bit64 enabled and descriptors > 32 bytes */
    pub upper_unallocated_blocks: u16,
    /**If IncompatFlags.Bit64 enabled and descriptors > 32 bytes */
    pub upper_unallocated_inodes: u16,
    /**If IncompatFlags.Bit64 enabled and descriptors > 32 bytes */
    pub upper_directories: u16,
    /**If IncompatFlags.Bit64 enabled and descriptors > 32 bytes */
    pub upper_unused_inodes: u16,
    /**If IncompatFlags.Bit64 enabled and descriptors > 32 bytes */
    pub upper_exclude_bitmap_block: u32,
    /**If IncompatFlags.Bit64 enabled and descriptors > 32 bytes */
    pub upper_block_bitmap_checksum: u16,
    /**If IncompatFlags.Bit64 enabled and descriptors > 32 bytes */
    pub upper_inode_bitmap_checksum: u16,
}

#[derive(Debug, Clone)]
pub struct Extents {
    pub signature: u16,
    pub number_of_extents_or_indexes: u16,
    pub max_extents_or_indexes: u16,
    pub depth: u16,
    pub generation: u32,
    pub extent_descriptors: Vec<ExtentDescriptor>,
    pub index_descriptors: Vec<IndexDescriptor>,
    pub extent_descriptor_list: BTreeMap<u32, ExtentDescriptor>,
}

#[derive(Debug, Clone)]
pub struct ExtentDescriptor {
    pub logical_block_number: u32,
    pub number_of_blocks: u16,
    pub block_number: u64,
    pub next_logical_block_number: u32,
    pub block_diff: u32,
    pub upper_part_physical_block_number: u16,
    pub lower_part_physical_block_number: u32,
}

#[derive(Debug, Clone)]
pub struct IndexDescriptor {
    pub logical_block_number: u32,
    pub block_number: u64,
    pub lower_part_physical_block_number: u32,
    pub upper_part_physical_block_number: u16,
}

#[derive(Debug, Clone)]
pub enum BlockFlags {
    InodeBitmapUnused,
    BlockBitmapUnused,
    /**Bitmap is zeroed */
    InodeTableEmpty,
}

pub struct Ext4Hash {
    pub md5: bool,
    pub sha1: bool,
    pub sha256: bool,
}

#[derive(Debug, PartialEq)]
pub struct HashValue {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}
#[derive(Debug, PartialEq, Clone)]
pub struct Directory {
    pub inode: u32,
    pub file_type: FileType,
    pub name: String,
}

#[derive(Debug, PartialEq)]
pub struct FileInfo {
    pub name: String,
    pub inode: u64,
    pub parent_inode: u64,
    pub size: u64,
    pub permission: Vec<InodePermissions>,
    pub inode_type: InodeType,
    pub accessed: i64,
    pub changed: i64,
    pub created: i64,
    pub modified: i64,
    pub deleted: i32,
    pub hard_links: u16,
    pub children: Vec<Directory>,
    pub extended_attributes: HashMap<String, String>,
    pub uid: u16,
    pub gid: u16,
    pub is_sparse: bool,
}

#[derive(Debug, PartialEq, Serialize, Copy, Clone)]
pub enum InodeType {
    Pipe,
    Device,
    Directory,
    BlockDevice,
    File,
    SymbolicLink,
    Socket,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub struct Stat {
    pub inode: u64,
    pub size: u64,
    pub permission: Vec<InodePermissions>,
    pub inode_type: InodeType,
    pub accessed: i64,
    pub changed: i64,
    pub created: i64,
    pub modified: i64,
    pub deleted: i32,
    pub hard_links: u16,
    pub extended_attributes: HashMap<String, String>,
    pub uid: u16,
    pub gid: u16,
    pub is_sparse: bool,
}
#[derive(Debug, PartialEq, Serialize, Clone, Copy)]
pub enum InodePermissions {
    ReadOther,
    WriteOther,
    ExecuteOther,
    ReadGroup,
    WriteGroup,
    ExecuteGroup,
    ReadUser,
    WriteUser,
    ExecuteUser,
    Sticky,
    Suid,
    Sgid,
    Unknown,
}

#[derive(Debug, PartialEq, Clone, Copy, Serialize)]
pub enum FileType {
    Unknown,
    File,
    Directory,
    Device,
    Block,
    FifoQueue,
    Socket,
    SymbolicLink,
}

impl FileInfo {
    pub(crate) fn new(
        inode_info: Inode,
        dirs: Vec<HashMap<u64, Directory>>,
        inode: u64,
    ) -> FileInfo {
        let mut children = Vec::new();
        let root = 2;
        let mut parent_inode = if inode == root { root } else { 0 };
        let mut name = if inode == root {
            String::from("/")
        } else {
            String::new()
        };
        for entry in &dirs {
            if let Some(dir) = entry.get(&inode)
                && name.is_empty()
            {
                name = dir.name.clone();
            }
            for value in entry.values() {
                children.push(value.clone());
                if value.name == ".." {
                    parent_inode = value.inode as u64;
                }
            }
        }

        FileInfo {
            name,
            inode,
            parent_inode,
            size: inode_info.size,
            permission: inode_info.permissions,
            inode_type: inode_info.inode_type,
            accessed: inode_info.accessed,
            changed: inode_info.changed,
            created: inode_info.created,
            modified: inode_info.modified,
            deleted: inode_info.deleted,
            hard_links: inode_info.hard_links,
            children,
            extended_attributes: inode_info.extended_attributes,
            uid: inode_info.uid,
            gid: inode_info.gid,
            is_sparse: inode_info.is_sparse,
        }
    }
}

impl Stat {
    pub(crate) fn new(inode_info: Inode, inode: u64) -> Stat {
        Stat {
            inode,
            size: inode_info.size,
            permission: inode_info.permissions,
            inode_type: inode_info.inode_type,
            accessed: inode_info.accessed,
            changed: inode_info.changed,
            created: inode_info.created,
            modified: inode_info.modified,
            deleted: inode_info.deleted,
            hard_links: inode_info.hard_links,
            extended_attributes: inode_info.extended_attributes,
            uid: inode_info.uid,
            gid: inode_info.gid,
            is_sparse: inode_info.is_sparse,
        }
    }
}
