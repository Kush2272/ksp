//! Keep-alive mechanism for KSP sessions.
//!
//! As defined in RFC-0001 Section 13.3.

use ksp_core::constants::{KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT};
use std::time::{Duration, Instant};

/// Tracks keep-alive state for a connection.
pub struct KeepaliveTracker {
    /// When we last sent a keep-alive.
    last_sent: Instant,
    /// When we last received any frame (keep-alive or data).
    last_received: Instant,
    /// Whether we're waiting for a KeepAliveAck.
    awaiting_ack: bool,
    /// When the outstanding keep-alive was sent (for timeout).
    ack_sent_at: Option<Instant>,
    /// Keepalive send interval.
    interval: Duration,
    /// Timeout for ack response.
    timeout: Duration,
}

impl KeepaliveTracker {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            last_sent: now,
            last_received: now,
            awaiting_ack: false,
            ack_sent_at: None,
            interval: KEEPALIVE_INTERVAL,
            timeout: KEEPALIVE_TIMEOUT,
        }
    }

    /// Check if it's time to send a keep-alive.
    pub fn should_send(&self) -> bool {
        !self.awaiting_ack && self.last_sent.elapsed() >= self.interval
    }

    /// Record that we sent a keep-alive.
    pub fn record_sent(&mut self) {
        let now = Instant::now();
        self.last_sent = now;
        self.awaiting_ack = true;
        self.ack_sent_at = Some(now);
    }

    /// Record that we received a KeepAliveAck.
    pub fn record_ack_received(&mut self) {
        self.awaiting_ack = false;
        self.ack_sent_at = None;
        self.last_received = Instant::now();
    }

    /// Record that we received any frame (resets inactivity timer).
    pub fn record_activity(&mut self) {
        self.last_received = Instant::now();
    }

    /// Check if the connection has timed out (no ack received in time).
    pub fn is_timed_out(&self) -> bool {
        if let Some(sent_at) = self.ack_sent_at {
            self.awaiting_ack && sent_at.elapsed() >= self.timeout
        } else {
            false
        }
    }

    /// Time since last received frame.
    pub fn idle_duration(&self) -> Duration {
        self.last_received.elapsed()
    }
}

impl Default for KeepaliveTracker {
    fn default() -> Self {
        Self::new()
    }
}
