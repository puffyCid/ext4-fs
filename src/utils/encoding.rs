use base64::{Engine, engine::general_purpose};

/// Base64 encode data using the STANDARD engine (alphabet along with "+" and "/")
pub(crate) fn base64_encode_standard(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use crate::utils::encoding::base64_encode_standard;

    #[test]
    fn test_base64_encode_standard() {
        let test = b"Hello word!";
        let result = base64_encode_standard(test);
        assert_eq!(result, "SGVsbG8gd29yZCE=")
    }
}
