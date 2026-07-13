//! Window-based flow control for KSP.
//!
//! Implements connection-level flow control as defined in RFC-0001 Section 12.

use ksp_core::constants::DEFAULT_WINDOW_SIZE;
use ksp_core::error::KspError;

/// Connection-level flow control window.
///
/// Separate from per-stream flow control (handled in `stream.rs`).
/// Both levels must have available window for data to be sent.
pub struct ConnectionFlowControl {
    /// Bytes we can still send to the peer.
    pub send_window: u32,
    /// Bytes the peer can still send to us.
    pub recv_window: u32,
}

impl ConnectionFlowControl {
    pub fn new() -> Self {
        Self {
            send_window: DEFAULT_WINDOW_SIZE,
            recv_window: DEFAULT_WINDOW_SIZE,
        }
    }

    /// Consume send window when sending data.
    pub fn consume_send(&mut self, bytes: u32) -> Result<(), KspError> {
        if bytes > self.send_window {
            return Err(KspError::FlowControlError(format!(
                "connection send window exhausted: need {} have {}",
                bytes, self.send_window
            )));
        }
        self.send_window -= bytes;
        Ok(())
    }

    /// Increase send window (received WINDOW_UPDATE from peer).
    pub fn update_send(&mut self, increment: u32) {
        self.send_window = self.send_window.saturating_add(increment);
    }

    /// Consume receive window when receiving data.
    pub fn consume_recv(&mut self, bytes: u32) -> Result<(), KspError> {
        if bytes > self.recv_window {
            return Err(KspError::FlowControlError(format!(
                "connection recv window exceeded: {} > {}",
                bytes, self.recv_window
            )));
        }
        self.recv_window -= bytes;
        Ok(())
    }

    /// Increase receive window (we send WINDOW_UPDATE to peer).
    pub fn update_recv(&mut self, increment: u32) {
        self.recv_window = self.recv_window.saturating_add(increment);
    }

    /// Check if we should send a WINDOW_UPDATE to the peer.
    ///
    /// Sends an update when the window drops below half the default size.
    pub fn should_send_window_update(&self) -> bool {
        self.recv_window < DEFAULT_WINDOW_SIZE / 2
    }

    /// Calculate the window update increment to restore the default size.
    pub fn window_update_increment(&self) -> u32 {
        DEFAULT_WINDOW_SIZE - self.recv_window
    }
}

impl Default for ConnectionFlowControl {
    fn default() -> Self {
        Self::new()
    }
}
