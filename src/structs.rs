use serde::Serialize;

use crate::inode::Inode;
use std::collections::HashMap;

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
    pub accessed: u64,
    pub changed: u64,
    pub created: u64,
    pub modified: u64,
    pub deleted: u64,
    pub hard_links: u16,
    pub children: Vec<Directory>,
    pub extended_attributes: HashMap<String, String>,
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
    pub accessed: u64,
    pub changed: u64,
    pub created: u64,
    pub modified: u64,
    pub deleted: u64,
    pub hard_links: u16,
    pub extended_attributes: HashMap<String, String>,
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
            size: inode_info.size as u64,
            permission: inode_info.permissions,
            inode_type: inode_info.inode_type,
            accessed: inode_info.accessed as u64,
            changed: inode_info.changed as u64,
            created: inode_info.created as u64,
            modified: inode_info.modified as u64,
            deleted: inode_info.deleted as u64,
            hard_links: inode_info.hard_links,
            children: children,
            extended_attributes: inode_info.extended_attributes,
        }
    }
}

impl Stat {
    pub(crate) fn new(inode_info: Inode, inode: u64) -> Stat {
        Stat {
            inode,
            size: inode_info.size as u64,
            permission: inode_info.permissions,
            inode_type: inode_info.inode_type,
            accessed: inode_info.accessed as u64,
            changed: inode_info.changed as u64,
            created: inode_info.created as u64,
            modified: inode_info.modified as u64,
            deleted: inode_info.deleted as u64,
            hard_links: inode_info.hard_links,
            extended_attributes: inode_info.extended_attributes,
        }
    }
}
