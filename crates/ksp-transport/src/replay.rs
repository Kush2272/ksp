//! Sliding window replay protection for KSP.
//!
//! Implements the algorithm specified in RFC-0001 Section 14:
//! - 1024-bit sliding window bitmap
//! - Rejects duplicate and too-old packets
//! - O(1) check and update

use ksp_core::constants::REPLAY_WINDOW_SIZE;
use ksp_core::error::KspError;

/// Sliding window replay protection.
///
/// Maintains a bitmap of recently seen sequence numbers to detect
/// replayed packets. As defined in RFC-0001 Section 14.2:
///
/// - If `seq > highest_seq`: Accept and advance window.
/// - If `seq <= highest_seq - WINDOW_SIZE`: Reject (too old).
/// - If `seq` is within window: Check bit; reject if already seen.
pub struct ReplayWindow {
    /// The highest accepted sequence number.
    highest_seq: u64,
    /// Bitmap of 1024 bits (16 × u64) representing the window
    /// `[highest_seq - 1023, highest_seq]`.
    bitmap: [u64; 16],
}

impl ReplayWindow {
    /// Create a new replay window with no packets seen.
    pub fn new() -> Self {
        Self {
            highest_seq: 0,
            bitmap: [0u64; 16],
        }
    }

    /// Check if a sequence number is valid (not replayed, not too old)
    /// and record it if valid.
    ///
    /// Returns `Ok(())` if the packet should be accepted, or
    /// `Err(ReplayDetected)` if it should be rejected.
    pub fn check_and_update(&mut self, seq: u64) -> Result<(), KspError> {
        if seq == 0 && self.highest_seq == 0 && self.bitmap == [0u64; 16] {
            // First packet ever
            self.set_bit(0);
            return Ok(());
        }

        if seq > self.highest_seq {
            // New highest — advance the window
            let shift = seq - self.highest_seq;
            self.advance_window(shift);
            self.highest_seq = seq;
            self.set_bit(0); // Current position is always bit 0
            Ok(())
        } else if self.highest_seq - seq >= REPLAY_WINDOW_SIZE {
            // Too old — outside the window
            Err(KspError::ReplayDetected(seq))
        } else {
            // Within window — check the bit
            let offset = (self.highest_seq - seq) as usize;
            if self.get_bit(offset) {
                Err(KspError::ReplayDetected(seq))
            } else {
                self.set_bit(offset);
                Ok(())
            }
        }
    }

    /// Check if a sequence number would be accepted without recording it.
    pub fn would_accept(&self, seq: u64) -> bool {
        if seq > self.highest_seq {
            true
        } else if self.highest_seq - seq >= REPLAY_WINDOW_SIZE {
            false
        } else {
            let offset = (self.highest_seq - seq) as usize;
            !self.get_bit(offset)
        }
    }

    /// Get the highest seen sequence number.
    pub fn highest_sequence(&self) -> u64 {
        self.highest_seq
    }

    /// Advance the window by `shift` positions.
    fn advance_window(&mut self, shift: u64) {
        if shift >= REPLAY_WINDOW_SIZE {
            // Entire window is outdated — reset
            self.bitmap = [0u64; 16];
        } else {
            let shift = shift as usize;

            // Shift the bitmap right by `shift` bits
            let word_shift = shift / 64;
            let bit_shift = shift % 64;

            if word_shift > 0 {
                // Shift entire words
                for i in (0..16).rev() {
                    if i >= word_shift {
                        self.bitmap[i] = self.bitmap[i - word_shift];
                    } else {
                        self.bitmap[i] = 0;
                    }
                }
            }

            if bit_shift > 0 {
                // Shift remaining bits within words
                for i in (0..16).rev() {
                    self.bitmap[i] <<= bit_shift;
                    if i > 0 {
                        self.bitmap[i] |= self.bitmap[i - 1] >> (64 - bit_shift);
                    }
                }
            }
        }
    }

    /// Set a bit in the bitmap (offset 0 = highest_seq).
    fn set_bit(&mut self, offset: usize) {
        let word = offset / 64;
        let bit = offset % 64;
        if word < 16 {
            self.bitmap[word] |= 1u64 << bit;
        }
    }

    /// Get a bit from the bitmap.
    fn get_bit(&self, offset: usize) -> bool {
        let word = offset / 64;
        let bit = offset % 64;
        if word < 16 {
            (self.bitmap[word] & (1u64 << bit)) != 0
        } else {
            false
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequential_packets() {
        let mut window = ReplayWindow::new();

        for i in 0..100 {
            window.check_and_update(i).unwrap();
        }
    }

    #[test]
    fn test_replay_detected() {
        let mut window = ReplayWindow::new();

        window.check_and_update(1).unwrap();
        window.check_and_update(2).unwrap();
        window.check_and_update(3).unwrap();

        // Replay of packet 2
        assert!(matches!(
            window.check_and_update(2),
            Err(KspError::ReplayDetected(2))
        ));
    }

    #[test]
    fn test_out_of_order_within_window() {
        let mut window = ReplayWindow::new();

        window.check_and_update(1).unwrap();
        window.check_and_update(3).unwrap();
        window.check_and_update(2).unwrap(); // Out of order but within window
        window.check_and_update(5).unwrap();
        window.check_and_update(4).unwrap(); // Out of order but within window
    }

    #[test]
    fn test_too_old_rejected() {
        let mut window = ReplayWindow::new();

        // Advance to seq 2000
        window.check_and_update(2000).unwrap();

        // Packet 500 is way too old (2000 - 500 = 1500 > 1024)
        assert!(matches!(
            window.check_and_update(500),
            Err(KspError::ReplayDetected(500))
        ));
    }

    #[test]
    fn test_edge_of_window() {
        let mut window = ReplayWindow::new();

        window.check_and_update(1024).unwrap();

        // Sequence 1 is exactly at the edge (1024 - 1 = 1023 < 1024 window)
        window.check_and_update(1).unwrap();

        // Sequence 0 is just outside (1024 - 0 = 1024 >= 1024 window)
        assert!(matches!(
            window.check_and_update(0),
            Err(KspError::ReplayDetected(0))
        ));
    }

    #[test]
    fn test_large_gap() {
        let mut window = ReplayWindow::new();

        window.check_and_update(1).unwrap();
        window.check_and_update(5000).unwrap(); // Big jump

        // Packet 1 is now too old
        assert!(matches!(
            window.check_and_update(1),
            Err(KspError::ReplayDetected(1))
        ));

        // But 4500 should work (5000 - 4500 = 500 < 1024)
        window.check_and_update(4500).unwrap();
    }

    #[test]
    fn test_would_accept() {
        let mut window = ReplayWindow::new();

        window.check_and_update(5).unwrap();

        assert!(window.would_accept(6)); // New highest
        assert!(window.would_accept(3)); // Within window, unseen
        assert!(!window.would_accept(5)); // Already seen
    }

    #[test]
    fn test_highest_sequence() {
        let mut window = ReplayWindow::new();

        window.check_and_update(42).unwrap();
        assert_eq!(window.highest_sequence(), 42);

        window.check_and_update(100).unwrap();
        assert_eq!(window.highest_sequence(), 100);

        // Out-of-order doesn't change highest
        window.check_and_update(50).unwrap();
        assert_eq!(window.highest_sequence(), 100);
    }
}
