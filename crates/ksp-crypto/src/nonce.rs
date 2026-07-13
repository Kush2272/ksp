//! Counter-based nonce generation for AEAD.
//!
//! Implements TLS 1.3-style nonce construction (RFC-0001 Section 8.4):
//! `nonce = write_iv XOR (sequence_number padded to 12 bytes)`
//!
//! This ensures unique nonces without requiring random generation,
//! while the XOR with the IV prevents nonce collision across sessions.

use std::sync::atomic::{AtomicU64, Ordering};

use ksp_core::NONCE_SIZE;

/// A nonce generator that produces unique 12-byte nonces from a base IV and counter.
///
/// Thread-safe via atomic counter. Nonces are constructed by XORing the base IV
/// with a left-zero-padded sequence number.
pub struct NonceGenerator {
    /// Base IV (12 bytes) derived from HKDF
    base_iv: [u8; NONCE_SIZE],
    /// Atomic counter for sequence numbers
    counter: AtomicU64,
}

impl NonceGenerator {
    /// Create a new nonce generator with the given base IV.
    ///
    /// The counter starts at 0.
    pub fn new(base_iv: [u8; NONCE_SIZE]) -> Self {
        Self {
            base_iv,
            counter: AtomicU64::new(0),
        }
    }

    /// Create a nonce generator starting at a specific counter value.
    ///
    /// Useful for session resumption where the counter must not restart.
    pub fn with_counter(base_iv: [u8; NONCE_SIZE], start: u64) -> Self {
        Self {
            base_iv,
            counter: AtomicU64::new(start),
        }
    }

    /// Generate the next nonce and return it with the current sequence number.
    ///
    /// # Panics
    /// Panics if the counter overflows u64::MAX. At 1 billion nonces/sec,
    /// this would take ~584 years.
    pub fn next(&self) -> (u64, [u8; NONCE_SIZE]) {
        let seq = self.counter.fetch_add(1, Ordering::SeqCst);
        assert!(
            seq < u64::MAX,
            "Nonce counter overflow — session must be rekeyed"
        );
        let nonce = self.construct_nonce(seq);
        (seq, nonce)
    }

    /// Construct a nonce for a specific sequence number.
    ///
    /// Used by receivers to independently verify the expected nonce.
    ///
    /// ```text
    /// nonce[0..4]  = base_iv[0..4]  XOR 0x00000000
    /// nonce[4..12] = base_iv[4..12] XOR seq.to_be_bytes()
    /// ```
    pub fn construct_nonce(&self, sequence: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = self.base_iv;
        let seq_bytes = sequence.to_be_bytes(); // 8 bytes

        // XOR the last 8 bytes of the IV with the sequence number
        // (first 4 bytes remain as-is for extra differentiation)
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        nonce
    }

    /// Get the current counter value without incrementing.
    pub fn current_counter(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_uniqueness() {
        let iv = [0xAA; NONCE_SIZE];
        let nonce_gen = NonceGenerator::new(iv);

        let (seq0, nonce0) = nonce_gen.next();
        let (seq1, nonce1) = nonce_gen.next();
        let (seq2, nonce2) = nonce_gen.next();

        assert_eq!(seq0, 0);
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);

        // All nonces must be unique
        assert_ne!(nonce0, nonce1);
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce0, nonce2);
    }

    #[test]
    fn test_construct_nonce_deterministic() {
        let iv = [0xBB; NONCE_SIZE];
        let nonce_gen = NonceGenerator::new(iv);

        let nonce_42_a = nonce_gen.construct_nonce(42);
        let nonce_42_b = nonce_gen.construct_nonce(42);

        assert_eq!(nonce_42_a, nonce_42_b);
    }

    #[test]
    fn test_nonce_matches_construct() {
        let iv = [0xCC; NONCE_SIZE];
        let nonce_gen = NonceGenerator::new(iv);

        let (seq, nonce) = nonce_gen.next();
        let expected = nonce_gen.construct_nonce(seq);

        assert_eq!(nonce, expected);
    }

    #[test]
    fn test_different_ivs_different_nonces() {
        let gen1 = NonceGenerator::new([0xAA; NONCE_SIZE]);
        let gen2 = NonceGenerator::new([0xBB; NONCE_SIZE]);

        let (_, nonce1) = gen1.next();
        let (_, nonce2) = gen2.next();

        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_counter_starts_at_custom_value() {
        let nonce_gen = NonceGenerator::with_counter([0; NONCE_SIZE], 100);
        let (seq, _) = nonce_gen.next();
        assert_eq!(seq, 100);
    }

    #[test]
    fn test_zero_iv_produces_sequence_as_nonce() {
        let nonce_gen = NonceGenerator::new([0; NONCE_SIZE]);

        let (_, nonce) = nonce_gen.next(); // seq = 0
        assert_eq!(nonce, [0; NONCE_SIZE]);

        let (_, nonce) = nonce_gen.next(); // seq = 1
        let mut expected = [0u8; NONCE_SIZE];
        expected[11] = 1; // Last byte = seq in big-endian
        assert_eq!(nonce, expected);
    }
}
