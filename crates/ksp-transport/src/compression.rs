//! zstd compression for KSP payloads.
//!
//! Compression is applied before encryption (compress-then-encrypt)
//! and only when the COMPRESSED flag is negotiated and set.

use ksp_core::error::KspError;

/// Compress data using zstd.
///
/// Uses compression level 3 (good balance of speed and ratio).
pub fn compress(data: &[u8]) -> Result<Vec<u8>, KspError> {
    zstd::encode_all(std::io::Cursor::new(data), 3)
        .map_err(|e| KspError::InternalError(format!("compression failed: {}", e)))
}

/// Decompress zstd-compressed data.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, KspError> {
    zstd::decode_all(std::io::Cursor::new(data))
        .map_err(|e| KspError::InternalError(format!("decompression failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let data = b"Hello, KSP! This is some data that should compress well. \
                     Hello, KSP! This is some data that should compress well.";

        let compressed = compress(data).unwrap();
        let decompressed = decompress(&compressed).unwrap();

        assert_eq!(decompressed, data);
        assert!(compressed.len() < data.len()); // Should actually compress
    }

    #[test]
    fn test_empty_data() {
        let compressed = compress(b"").unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }
}
