use crate::utils::encoding::base64_encode_standard;
use log::warn;
use std::string::FromUtf8Error;
use uuid::Uuid;

/// Get a UTF8 string from provided bytes data. Invalid UTF8 is base64 encoded
pub(crate) fn extract_utf8_string(data: &[u8]) -> String {
    let utf8_result = bytes_to_utf8_string(data);
    match utf8_result {
        Ok(result) => result,
        Err(err) => {
            warn!("[ext4fs] Failed to get UTF8 string: {err:?}");
            let max_size = 2097152;
            let issue = if data.len() < max_size {
                base64_encode_standard(data)
            } else {
                format!(
                    "[ext4fs] Binary data size larger than 2MB, size: {}",
                    data.len()
                )
            };
            format!("[ext4fs] Failed to get UTF8 string: {issue}")
        }
    }
}

/// Convert little endian bytes to a UUID/GUID string
pub(crate) fn format_guid_le_bytes(data: &[u8]) -> String {
    let guid_size = 16;
    if data.len() != guid_size {
        warn!(
            "[ext4fs] Provided little endian data does not meet GUID size of 16 bytes, got: {}",
            data.len()
        );
        return format!("Not a GUID/UUID: {data:?}");
    }

    let guid_data = data.try_into();
    match guid_data {
        Ok(result) => Uuid::from_bytes_le(result).hyphenated().to_string(),
        Err(_err) => {
            warn!("[ext4fs] Could not convert little endian bytes to a GUID/UUID format: {data:?}");
            format!("Could not convert data: {data:?}")
        }
    }
}

/// Convert big endian bytes to a UUID/GUID string
pub(crate) fn format_guid_be_bytes(data: &[u8]) -> String {
    let guid_size = 16;
    if data.len() != guid_size {
        warn!(
            "[ext4fs] Provided big endian data does not meet GUID size of 16 bytes, got: {}",
            data.len()
        );
        return format!("Not a GUID/UUID: {data:?}");
    }

    let guid_data = data.try_into();
    match guid_data {
        Ok(result) => Uuid::from_bytes(result).hyphenated().to_string(),
        Err(_err) => {
            warn!("[ext4fs] Could not convert big endian bytes to a GUID/UUID format: {data:?}");
            format!("Could not convert data: {data:?}")
        }
    }
}

/// Get a UTF8 string from provided bytes data
fn bytes_to_utf8_string(data: &[u8]) -> Result<String, FromUtf8Error> {
    let result = String::from_utf8(data.to_vec())?;
    let value = result.trim_end_matches('\0').to_string();
    Ok(value)
}
