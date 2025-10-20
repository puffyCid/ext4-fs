use ext4_fs::{
    extfs::{Ext4Reader, Ext4ReaderAction},
    structs::{Ext4Hash, FileInfo, FileType},
};
use std::{fs::File, io::BufReader, path::PathBuf};

fn walk_dir<T: std::io::Seek + std::io::Read>(
    info: &FileInfo,
    reader: &mut Ext4Reader<T>,
    cache: &mut Vec<String>,
    hash: bool,
    stat: bool,
    values: &mut Vec<FileInfo>,
) {
    for entry in &info.children {
        if stat {
            let info = reader.stat(entry.inode).unwrap();
            assert_ne!(info.inode, 0);
        }
        if entry.file_type == FileType::Directory
            && entry.name != "."
            && entry.name != ".."
            && entry.inode != 2
        {
            let info = reader.read_dir(entry.inode).unwrap();
            cache.push(info.name.clone());
            walk_dir(&info, reader, cache, hash, stat, values);
            cache.pop();
            continue;
        }
        if entry.file_type == FileType::Directory {
            continue;
        }

        if entry.file_type == FileType::File {
            let hash_data = Ext4Hash {
                md5: true,
                sha1: false,
                sha256: false,
            };
            let hash_value = reader.hash(entry.inode, &hash_data).unwrap();
            assert!(!hash_value.md5.is_empty());
            // Check sparse files
            if format!("{}/{}", cache.join("/"), entry.name).contains("trailing_sparse") {
                assert_eq!(hash_value.md5, "e0b16e3a6c58c67928b5895797fccaa0");
            } else if format!("{}/{}", cache.join("/"), entry.name).contains("initial_sparse") {
                assert_eq!(hash_value.md5, "c53dd591cf199ec5d692de2cbdb8559b");
            }
        }
    }
}

#[test]
fn test_read_root_directory() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/images/test.img");
    let reader = File::open(test_location.to_str().unwrap()).unwrap();
    let buf = BufReader::new(reader);
    let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
    let dir = ext4_reader.root().unwrap();

    assert_eq!(dir.created, 1759689014);
    assert_eq!(dir.changed, 1759713496);
    assert_eq!(dir.children.len(), 6);
}

#[test]
fn test_walk_entire_filesystem() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/images/test.img");
    let reader = File::open(test_location.to_str().unwrap()).unwrap();
    let buf = BufReader::new(reader);
    let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
    let root = ext4_reader.root().unwrap();

    let mut cache = Vec::new();
    cache.push(String::new());

    let mut values = Vec::new();
    walk_dir(
        &root,
        &mut ext4_reader,
        &mut cache,
        false,
        false,
        &mut values,
    );
}

#[test]
fn test_hash_helloworld() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/images/test.img");
    let reader = File::open(test_location.to_str().unwrap()).unwrap();
    let buf = BufReader::new(reader);
    let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();

    let mut cache = Vec::new();
    cache.push(String::new());

    let hash_data = Ext4Hash {
        md5: true,
        sha1: false,
        sha256: false,
    };
    let hash_value = ext4_reader.hash(14, &hash_data).unwrap();
    assert_eq!(hash_value.md5, "c897d1410af8f2c74fba11b1db511e9e");
}

#[test]
fn test_hash_every_file() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/images/test.img");
    let reader = File::open(test_location.to_str().unwrap()).unwrap();
    let buf = BufReader::new(reader);
    let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
    let root = ext4_reader.root().unwrap();

    let mut cache = Vec::new();
    cache.push(String::new());

    let mut values = Vec::new();
    walk_dir(
        &root,
        &mut ext4_reader,
        &mut cache,
        true,
        false,
        &mut values,
    );
}

#[test]
fn test_stat_everything() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/images/test.img");
    let reader = File::open(test_location.to_str().unwrap()).unwrap();
    let buf = BufReader::new(reader);
    let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
    let root = ext4_reader.root().unwrap();

    let mut cache = Vec::new();
    cache.push(String::new());

    let mut values = Vec::new();
    walk_dir(
        &root,
        &mut ext4_reader,
        &mut cache,
        false,
        true,
        &mut values,
    );
}

#[test]
fn test_ext4_minefield() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/keramics/ext4.raw");
    let reader = File::open(test_location.to_str().unwrap()).unwrap();
    let buf = BufReader::new(reader);

    // The blocksize for the example is actually 1024. The blocksize should self correct once the superblock is parsed
    let mut ext4_reader = Ext4Reader::new(buf, 4096).unwrap();
    let root = ext4_reader.root().unwrap();

    let mut cache = Vec::new();
    cache.push(String::new());
    let mut values = Vec::new();
    walk_dir(&root, &mut ext4_reader, &mut cache, true, true, &mut values);
}
