use std::fmt;

#[derive(Debug)]
pub enum Ext4Error {
    Header,
    SeekFile,
    ReadFile,
    Superblock,
    Descriptor,
    BadInode,
    Directory,
    Extents,
    NotAFile,
    FailedToRead,
}

impl std::error::Error for Ext4Error {}

impl fmt::Display for Ext4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ext4Error::Header => write!(f, "Could not parse header"),
            Ext4Error::SeekFile => write!(f, "Failed to seek to provided offset"),
            Ext4Error::ReadFile => write!(f, "Failed to read bytes from ext4 filesystem"),
            Ext4Error::Superblock => write!(f, "Failed to parse the superblock"),
            Ext4Error::Descriptor => write!(f, "Failed to parse the descriptor"),
            Ext4Error::BadInode => write!(f, "Invalid inode provided"),
            Ext4Error::Directory => write!(f, "Failed to parse directory info"),
            Ext4Error::Extents => write!(f, "Failed to parse extents info"),
            Ext4Error::NotAFile => write!(f, "Inode is not a file"),
            Ext4Error::FailedToRead => write!(f, "Could not read bytes from filesystem"),
        }
    }
}
