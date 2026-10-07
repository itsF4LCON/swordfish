//! Redaction and fingerprinting. Full secrets never leave this crate unless the
//! caller explicitly opts in.

use sha2::{Digest, Sha256};

/// Characters kept in clear by [`redact`].
pub const VISIBLE_PREFIX: usize = 4;
/// Secrets shorter than this are fully masked, since a 4-char prefix would
/// reveal most of them.
pub const MIN_LEN_FOR_PREFIX: usize = 8;

/// `abcdefgh...` -> `abcd****`; short secrets become `****`.
pub fn redact(secret: &[u8]) -> String {
    let text = String::from_utf8_lossy(secret);
    if text.chars().count() < MIN_LEN_FOR_PREFIX {
        return "****".to_string();
    }
    let prefix: String = text.chars().take(VISIBLE_PREFIX).collect();
    format!("{prefix}****")
}

/// Hex SHA-256 of the raw secret bytes; stable identity for a secret.
pub fn fingerprint(secret: &[u8]) -> String {
    hex::encode(Sha256::digest(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_four_chars() {
        assert_eq!(redact(b"abcdefghijklmnopqrst"), "abcd****");
        assert_eq!(redact(b"12345678"), "1234****");
    }

    #[test]
    fn masks_short_secrets_entirely() {
        assert_eq!(redact(b""), "****");
        assert_eq!(redact(b"abc"), "****");
        assert_eq!(redact(b"1234567"), "****");
    }

    #[test]
    fn handles_multibyte_and_invalid_utf8() {
        assert_eq!(redact("päss✓wörd-long".as_bytes()), "päss****");
        assert_eq!(redact(b"\xff\xfeabcdefgh"), "\u{fffd}\u{fffd}ab****");
    }

    #[test]
    fn fingerprint_is_sha256_hex() {
        assert_eq!(
            fingerprint(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(fingerprint(b"x").len(), 64);
    }
}
