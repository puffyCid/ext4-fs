use crate::{
    descriptors::Descriptor,
    error::Ext4Error,
    inode::Inode,
    reader::FileReader,
    structs::{Directory, Ext4Hash, FileInfo, HashValue, InodeType, Stat},
    superblock::block::{IncompatFlags, SuperBlock},
};
use log::error;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::{
    collections::HashMap,
    io::{BufReader, Read, copy},
};

/*
 * TODO:
 * 0. Add is_sparse value to FileInfo. complete "check_sparse" function
 * 1. Keep info/debug entries. Since it is experimental it will be helpful to have
 * 2. More integration tests
 * 4. Review your cache idea. I dont think it will work for large filesystems
 *    - check memoyr usage on ur 6TB system?
 *    - it might be fine for now
 * 5. add option to set log level for example binary
 * Resources:
 * https://blogs.oracle.com/linux/post/understanding-ext4-disk-layout-part-2
 * https://blogs.oracle.com/linux/post/understanding-ext4-disk-layout-part-1
 * https://github.com/libyal/libfsext/blob/main/documentation/Extended%20File%20System%20(EXT).asciidoc
 *
 */
pub struct Ext4Reader<T: std::io::Seek + std::io::Read> {
    pub fs: BufReader<T>,
    /// Default is probably 4096
    pub blocksize: u16,
    superblock: Option<SuperBlock>,
    pub(crate) descriptors: Option<Vec<Descriptor>>,
    pub(crate) incompat_flags: Vec<IncompatFlags>,
    pub(crate) blocks_per_group: u32,
    pub(crate) fs_size: u64,
    pub(crate) number_blocks: u32,
    pub(crate) inode_size: u16,
    pub(crate) inodes_per_group: u32,
    pub(crate) cache_names: HashMap<u64, String>,
}

pub trait Ext4ReaderAction<'ext4, 'reader, T: std::io::Seek + std::io::Read> {
    fn root(&mut self) -> Result<FileInfo, Ext4Error>;
    fn read_dir(&mut self, inode: u32) -> Result<FileInfo, Ext4Error>;
    fn superblock(&mut self) -> Result<SuperBlock, Ext4Error>;
    fn stat(&mut self, inode: u32) -> Result<Stat, Ext4Error>;
    fn hash(&mut self, inode: u32, hash: &Ext4Hash) -> Result<HashValue, Ext4Error>;
    fn reader(&'reader mut self, inode: u32) -> Result<FileReader<'reader, T>, Ext4Error>;
    fn read(&mut self, inode: u32) -> Result<Vec<u8>, Ext4Error>;
}

impl<T: std::io::Seek + std::io::Read> Ext4Reader<T> {
    pub fn new(fs: BufReader<T>, blocksize: u16) -> Result<Ext4Reader<T>, Ext4Error> {
        let mut reader = Ext4Reader {
            fs,
            blocksize,
            superblock: None,
            descriptors: None,
            incompat_flags: Vec::new(),
            blocks_per_group: 0,
            fs_size: 0,
            number_blocks: 0,
            inode_size: 0,
            inodes_per_group: 0,
            cache_names: HashMap::new(),
        };

        let block = SuperBlock::read_superblock(&mut reader.fs)?;
        let size = 1024;
        let base: u16 = 2;
        reader.blocksize = size * base.pow(block.block_size) as u16;
        reader.incompat_flags = block.incompatible_features_flags.clone();
        reader.blocks_per_group = block.number_blocks_per_block_group;
        reader.fs_size = block.number_blocks as u64 * blocksize as u64;
        reader.number_blocks = block.number_blocks;
        reader.inode_size = block.inode_size;
        reader.inodes_per_group = block.number_inodes_per_block_group;
        reader.superblock = Some(block);
        // println!("{:?}", reader.superblock);
        reader.descriptors = Some(Descriptor::read_descriptor(&mut reader)?);
        //  println!("{}", reader.descriptors.as_ref().unwrap().len());
        Ok(reader)
    }
}

impl<'ext4, 'reader, T: std::io::Seek + std::io::Read> Ext4ReaderAction<'ext4, 'reader, T>
    for Ext4Reader<T>
{
    fn root(&mut self) -> Result<FileInfo, Ext4Error> {
        let root_inode = 2;
        self.read_dir(root_inode)
    }

    fn read_dir(&mut self, inode: u32) -> Result<FileInfo, Ext4Error> {
        let inode_value = Inode::read_inode_table(self, inode)?;
        // println!("inode: {inode}. Info: {inode_value:?}");

        let dirs = Directory::read_directory_data(self, &inode_value.extents)?;
        let mut info = FileInfo::new(inode_value, dirs, inode as u64);
        if let Some(name) = self.cache_names.get(&info.inode) {
            info.name = name.clone();
        }
        update_cache(&mut self.cache_names, &info);
        Ok(info)
    }

    fn superblock(&mut self) -> Result<SuperBlock, Ext4Error> {
        SuperBlock::read_superblock(&mut self.fs)
    }

    fn stat(&mut self, inode: u32) -> Result<Stat, Ext4Error> {
        let inode_value = Inode::read_inode_table(self, inode)?;
        Ok(Stat::new(inode_value, inode as u64))
    }

    fn hash(&mut self, inode: u32, hashes: &Ext4Hash) -> Result<HashValue, Ext4Error> {
        if hashes.md5 == false && hashes.sha1 == false && hashes.sha256 == false {
            return Ok(HashValue {
                md5: String::new(),
                sha1: String::new(),
                sha256: String::new(),
            });
        }
        let inode_value = Inode::read_inode_table(self, inode)?;
        if inode_value.inode_type != InodeType::File {
            return Err(Ext4Error::NotAFile);
        }
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();

        let mut file_reader = self.reader(inode)?;
        // Keep track of how many bytes we read
        let mut bytes_read = 0;
        // Keep track of our cumulative buffer size when reading in chunks
        let mut buf_size = 0;
        // Read file in small chunks
        let mut temp_buf_size = 65536;
        loop {
            let mut temp_buf = vec![0u8; temp_buf_size];
            let bytes = match file_reader.read(&mut temp_buf) {
                Ok(result) => result,
                Err(err) => {
                    error!("[ext4-fs] Failed to read bytes for inode {inode}: {err:?}");
                    return Err(Ext4Error::FailedToRead);
                }
            };
            bytes_read += bytes;
            if bytes_read + temp_buf_size > inode_value.size as usize {
                temp_buf_size = bytes_read + temp_buf_size - inode_value.size as usize;
            }
            // println!("bytes read: {bytes_read}. Bytes now: {bytes}");
            //println!("{temp_buf:?}");
            // Make sure our temp buff does not have any extra zeros from the initialization
            if bytes < temp_buf_size {
                temp_buf = temp_buf[0..bytes].to_vec();
            } else if bytes > inode_value.size as usize {
                // Also check for opposite
                // Small files maybe allocated more block bytes than needed
                // Ex: A file less than 4k in size
                temp_buf = temp_buf[0..inode_value.size as usize].to_vec();
                // println!("{temp_buf:?}");
            }
            if bytes == 0 && bytes_read < inode_value.size as usize {
                // File is sparse. Remaining bytes are zeros
                // There are no more extents we can read
                // We will fill in the remaining zeros
                let remaining = inode_value.size as usize - bytes_read as usize;
                temp_buf = vec![0u8; remaining];
                bytes_read += remaining;
            }

            // We may have read too many bytes at the end of the file
            // If we have, adjust our buffer a little
            if bytes_read > inode_value.size as usize && inode_value.size as usize > buf_size {
                temp_buf = temp_buf[0..(inode_value.size as usize - buf_size)].to_vec();
            }
            buf_size += temp_buf.len();

            if hashes.md5 {
                let _ = copy(&mut temp_buf.as_slice(), &mut md5);
            }
            if hashes.sha1 {
                let _ = copy(&mut temp_buf.as_slice(), &mut sha1);
            }
            if hashes.sha256 {
                let _ = copy(&mut temp_buf.as_slice(), &mut sha256);
            }

            // Once we have read enough bytes, we are done
            if bytes_read >= inode_value.size as usize {
                break;
            }
        }

        let mut hash_value = HashValue {
            md5: String::new(),
            sha1: String::new(),
            sha256: String::new(),
        };

        if hashes.md5 {
            let hash = md5.finalize();
            hash_value.md5 = format!("{hash:x}");
        }
        if hashes.sha1 {
            let hash = sha1.finalize();
            hash_value.sha1 = format!("{hash:x}");
        }
        if hashes.sha256 {
            let hash = sha256.finalize();
            hash_value.sha256 = format!("{hash:x}");
        }

        Ok(hash_value)
    }

    fn read(&mut self, inode: u32) -> Result<Vec<u8>, Ext4Error> {
        let inode_value = Inode::read_inode_table(self, inode)?;
        if inode_value.inode_type != InodeType::File {
            return Err(Ext4Error::NotAFile);
        }
        let mut file_reader = self.reader(inode)?;
        let mut buf = vec![0; inode_value.size as usize];
        if let Err(err) = file_reader.read(&mut buf) {
            error!("[ext4-fs] Could not read file: {err:?}");
            return Err(Ext4Error::ReadFile);
        }

        Ok(buf)
    }

    fn reader(&'reader mut self, inode: u32) -> Result<FileReader<'reader, T>, Ext4Error> {
        let inode_value = Inode::read_inode_table(self, inode)?;
        if inode_value.inode_type != InodeType::File {
            return Err(Ext4Error::NotAFile);
        }
        Ok(Ext4Reader::file_reader(
            self,
            &inode_value.extents,
            inode_value.size,
        ))
    }
}

fn update_cache(cache: &mut HashMap<u64, String>, info: &FileInfo) {
    for entry in &info.children {
        if entry.inode as u64 == info.inode {
            continue;
        }
        cache.insert(entry.inode as u64, entry.name.clone());
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        extfs::{Ext4Reader, Ext4ReaderAction},
        structs::{Ext4Hash, FileInfo, FileType},
    };
    use std::{collections::HashMap, fs::File, io::BufReader, path::PathBuf};

    fn walk_dir<T: std::io::Seek + std::io::Read>(
        info: &FileInfo,
        reader: &mut Ext4Reader<T>,
        cache: &mut HashMap<u64, String>,
    ) {
        for entry in &info.children {
            if entry.file_type == FileType::Directory
                && entry.name != "."
                && entry.name != ".."
                && entry.inode != 2
            {
                let info = reader.read_dir(entry.inode).unwrap();
                cache_paths(cache, &info);
                walk_dir(&info, reader, cache);
                continue;
            }
            if entry.file_type == FileType::Directory {
                continue;
            }
        }
    }

    fn cache_paths(cache: &mut HashMap<u64, String>, info: &FileInfo) {
        for entry in &info.children {
            if entry.file_type != FileType::Directory || entry.name == "." || entry.name == ".." {
                continue;
            }
            if cache.contains_key(&(entry.inode as u64))
                && entry.inode != 2
                && entry.name != "."
                && entry.name != ".."
            {
                continue;
            }

            let path = cache.get(&(info.inode as u64)).unwrap();

            cache.insert(
                entry.inode as u64,
                format!("{}/{}", path, entry.name.clone()),
            );
        }
    }

    #[test]
    fn test_read_ext4_root() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/images/test.img");
        let reader = File::open(test_location.to_str().unwrap()).unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
        let dir = ext4_reader.root().unwrap();

        assert_eq!(dir.created, 1759689014000000000);
        assert_eq!(dir.changed, 1759713496631583423);
        assert_eq!(dir.children.len(), 6);
    }

    #[test]
    fn test_read_ext4_dir() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/images/test.img");
        let reader = File::open(test_location.to_str().unwrap()).unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
        ext4_reader.root().unwrap();
        let dir = ext4_reader.read_dir(7634).unwrap();

        assert_eq!(dir.created, 1759689167899447083);
        assert_eq!(dir.changed, 1759689170863467296);
        assert_eq!(dir.children.len(), 10);
        assert_eq!(dir.parent_inode, 2);
    }

    #[test]
    fn test_read_ext4_index_dir() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/images/test.img");
        let reader = File::open(test_location.to_str().unwrap()).unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
        ext4_reader.root().unwrap();
        let dir = ext4_reader.read_dir(7633).unwrap();

        assert_eq!(dir.created, 1759689153355347892);
        assert_eq!(dir.changed, 1759689156340368251);
        assert_eq!(dir.children.len(), 165);
        assert_eq!(dir.parent_inode, 2);
    }

    #[test]
    fn test_walk_dir() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/images/test.img");
        let reader = File::open(test_location.to_str().unwrap()).unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
        let root = ext4_reader.root().unwrap();
        let mut cache = HashMap::new();
        cache.insert(2, String::from(""));
        cache_paths(&mut cache, &root);
        walk_dir(&root, &mut ext4_reader, &mut cache);
        assert_eq!(cache.len(), 10);
    }

    #[test]
    fn test_stat() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/images/test.img");
        let reader = File::open(test_location.to_str().unwrap()).unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
        let root = ext4_reader.root().unwrap();
        let mut cache = HashMap::new();
        cache.insert(2, String::from(""));
        cache_paths(&mut cache, &root);
        walk_dir(&root, &mut ext4_reader, &mut cache);

        let info = ext4_reader.stat(16).unwrap();
        assert_eq!(info.created, 1759689156064366369);
        assert_eq!(info.changed, 1759689156065366375);
        assert_eq!(info.accessed, 1759689156064366369);
        assert_eq!(info.modified, 1676375355000000000);
        assert_eq!(
            info.extended_attributes.get("security.selinux").unwrap(),
            "unconfined_u:object_r:unlabeled_t:s0"
        );
    }

    #[test]
    fn test_hash_large_file() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/images/test.img");
        let reader = File::open(test_location.to_str().unwrap()).unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
        let hashes = Ext4Hash {
            md5: true,
            sha1: true,
            sha256: true,
        };
        let info = ext4_reader.hash(676, &hashes).unwrap();
        assert_eq!(info.md5, "df8e85bd10b33ac804b7c46073768dc9");
        assert_eq!(info.sha1, "beb51c72d95518720c76e69fd2ad5f7a57e01d6b");
        assert_eq!(
            info.sha256,
            "703df175cdcbbe0163f4ed7c83819070630b8bffdf65dc5739caef062a9c7a73"
        );
    }

    #[test]
    fn test_read_large_file() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/images/test.img");
        let reader = File::open(test_location.to_str().unwrap()).unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
        let info = ext4_reader.read(676).unwrap();
        assert_eq!(info.len(), 274310864);
    }

    //#[test]
    fn test_walk_dir_os() {
        let reader = File::open("/home/ubunty/Downloads/ext4_root.img").unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
        let root = ext4_reader.root().unwrap();
        let mut cache = HashMap::new();
        cache.insert(2, String::from(""));
        cache_paths(&mut cache, &root);
        walk_dir(&root, &mut ext4_reader, &mut cache);
        assert_eq!(cache.len(), 5920);
    }
}
