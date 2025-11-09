use crate::error::Ext4Error;
use log::{error, warn};
use std::io::{BufReader, Read, Seek, SeekFrom};

pub(crate) fn read_bytes<T: std::io::Read + std::io::Seek>(
    offset: u64,
    bytes: u64,
    fs: &mut BufReader<T>,
) -> Result<Vec<u8>, Ext4Error> {
    if fs.seek(SeekFrom::Start(offset)).is_err() {
        error!("[ext4-fs] Could not seek to offset {offset}");
        return Err(Ext4Error::SeekFile);
    }
    let mut buff_size = vec![0u8; bytes as usize];
    let bytes_read = match fs.read(&mut buff_size) {
        Ok(result) => result,
        Err(err) => {
            error!("[ext4-fs] Could not read bytes: {err:?}");
            return Err(Ext4Error::ReadFile);
        }
    };

    if bytes_read != buff_size.len() {
        warn!("[ext4-fs] Did not read expected number of bytes. Wanted {bytes} got {bytes_read}",);
    }

    Ok(buff_size)
}

#[cfg(test)]
mod tests {
    use crate::{extfs::Ext4Reader, utils::bytes::read_bytes};
    use std::{fs::File, io::BufReader, path::PathBuf};

    #[test]
    fn test_read_bytes() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/images/test.img");
        let reader = File::open(test_location.to_str().unwrap()).unwrap();
        let buf = BufReader::new(reader);
        let mut ext4_reader = Ext4Reader::new(buf, 4096, 0).unwrap();
        assert_eq!(read_bytes(12, 90, &mut ext4_reader.fs).unwrap().len(), 90);
    }
}
