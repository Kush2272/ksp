//! Stream multiplexing for KSP.
//!
//! HTTP/2-style bidirectional streaming as defined in RFC-0001 Section 11.

use ksp_core::constants::{DEFAULT_WINDOW_SIZE, MAX_STREAMS_PER_SESSION};
use ksp_core::error::KspError;

/// Stream state as defined in RFC-0001 Section 11.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream has been reserved but no data sent.
    Idle,
    /// Stream is open for bidirectional data.
    Open,
    /// We sent END_STREAM — can only receive.
    HalfClosedLocal,
    /// They sent END_STREAM — can only send.
    HalfClosedRemote,
    /// Stream is fully closed.
    Closed,
}

/// A logical stream within a KSP session.
///
/// Stream IDs follow RFC-0001 Section 11.2:
/// - 0 = connection-level control
/// - Odd = client-initiated
/// - Even = server-initiated
#[derive(Debug)]
pub struct KspStream {
    /// Stream identifier.
    pub id: u32,
    /// Current stream state.
    pub state: StreamState,
    /// Send-side flow control window (bytes we can still send).
    pub send_window: u32,
    /// Receive-side flow control window (bytes they can still send us).
    pub recv_window: u32,
    /// Stream priority (0 = highest, 255 = lowest).
    pub priority: u8,
}

impl KspStream {
    /// Create a new stream in Open state.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            state: StreamState::Open,
            send_window: DEFAULT_WINDOW_SIZE,
            recv_window: DEFAULT_WINDOW_SIZE,
            priority: 128, // default medium priority
        }
    }

    /// Whether this stream was initiated by the client (odd ID).
    pub fn is_client_initiated(&self) -> bool {
        self.id % 2 == 1
    }

    /// Whether data can be sent on this stream.
    pub fn can_send(&self) -> bool {
        matches!(
            self.state,
            StreamState::Open | StreamState::HalfClosedRemote
        )
    }

    /// Whether data can be received on this stream.
    pub fn can_recv(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
    }

    /// Transition: we sent END_STREAM.
    pub fn local_close(&mut self) -> Result<(), KspError> {
        self.state = match self.state {
            StreamState::Open => StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote => StreamState::Closed,
            _ => return Err(KspError::StreamClosed(self.id)),
        };
        Ok(())
    }

    /// Transition: they sent END_STREAM.
    pub fn remote_close(&mut self) -> Result<(), KspError> {
        self.state = match self.state {
            StreamState::Open => StreamState::HalfClosedRemote,
            StreamState::HalfClosedLocal => StreamState::Closed,
            _ => return Err(KspError::StreamClosed(self.id)),
        };
        Ok(())
    }

    /// Transition: StreamReset — force close.
    pub fn reset(&mut self) {
        self.state = StreamState::Closed;
    }

    /// Consume send window when sending data.
    pub fn consume_send_window(&mut self, bytes: u32) -> Result<(), KspError> {
        if bytes > self.send_window {
            return Err(KspError::FlowControlError(format!(
                "send window exhausted on stream {}: need {} have {}",
                self.id, bytes, self.send_window
            )));
        }
        self.send_window -= bytes;
        Ok(())
    }

    /// Increase send window (received WINDOW_UPDATE from peer).
    pub fn increase_send_window(&mut self, increment: u32) {
        self.send_window = self.send_window.saturating_add(increment);
    }

    /// Consume receive window when receiving data.
    pub fn consume_recv_window(&mut self, bytes: u32) -> Result<(), KspError> {
        if bytes > self.recv_window {
            return Err(KspError::FlowControlError(format!(
                "recv window exceeded on stream {}: {} > {}",
                self.id, bytes, self.recv_window
            )));
        }
        self.recv_window -= bytes;
        Ok(())
    }

    /// Increase receive window (we send WINDOW_UPDATE to peer).
    pub fn increase_recv_window(&mut self, increment: u32) {
        self.recv_window = self.recv_window.saturating_add(increment);
    }
}

/// Manages all streams within a session.
pub struct StreamManager {
    /// Active streams, keyed by stream ID.
    streams: std::collections::HashMap<u32, KspStream>,
    /// Next client-initiated stream ID (odd).
    next_client_id: u32,
    /// Next server-initiated stream ID (even).
    next_server_id: u32,
    /// Maximum concurrent streams.
    max_streams: u32,
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            streams: std::collections::HashMap::new(),
            next_client_id: 1,
            next_server_id: 2,
            max_streams: MAX_STREAMS_PER_SESSION,
        }
    }

    /// Open a new client-initiated stream.
    pub fn open_client_stream(&mut self) -> Result<u32, KspError> {
        self.check_stream_limit()?;
        let id = self.next_client_id;
        self.next_client_id += 2;
        self.streams.insert(id, KspStream::new(id));
        Ok(id)
    }

    /// Open a new server-initiated stream.
    pub fn open_server_stream(&mut self) -> Result<u32, KspError> {
        self.check_stream_limit()?;
        let id = self.next_server_id;
        self.next_server_id += 2;
        self.streams.insert(id, KspStream::new(id));
        Ok(id)
    }

    /// Get a mutable reference to a stream.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut KspStream, KspError> {
        self.streams.get_mut(&id).ok_or(KspError::StreamClosed(id))
    }

    /// Get a reference to a stream.
    pub fn get(&self, id: u32) -> Result<&KspStream, KspError> {
        self.streams.get(&id).ok_or(KspError::StreamClosed(id))
    }

    /// Remove a closed stream.
    pub fn remove(&mut self, id: u32) {
        self.streams.remove(&id);
    }

    /// Number of active (non-closed) streams.
    pub fn active_count(&self) -> usize {
        self.streams
            .values()
            .filter(|s| s.state != StreamState::Closed)
            .count()
    }

    fn check_stream_limit(&self) -> Result<(), KspError> {
        if self.active_count() as u32 >= self.max_streams {
            return Err(KspError::StreamLimitExceeded(self.max_streams));
        }
        Ok(())
    }
}

impl Default for StreamManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_lifecycle() {
        let mut stream = KspStream::new(1);
        assert_eq!(stream.state, StreamState::Open);
        assert!(stream.can_send());
        assert!(stream.can_recv());

        stream.local_close().unwrap();
        assert_eq!(stream.state, StreamState::HalfClosedLocal);
        assert!(!stream.can_send());
        assert!(stream.can_recv());

        stream.remote_close().unwrap();
        assert_eq!(stream.state, StreamState::Closed);
        assert!(!stream.can_send());
        assert!(!stream.can_recv());
    }

    #[test]
    fn test_stream_ids() {
        let mut mgr = StreamManager::new();

        let id1 = mgr.open_client_stream().unwrap();
        let id2 = mgr.open_client_stream().unwrap();
        let id3 = mgr.open_server_stream().unwrap();

        assert_eq!(id1, 1); // odd = client
        assert_eq!(id2, 3);
        assert_eq!(id3, 2); // even = server
    }

    #[test]
    fn test_flow_control() {
        let mut stream = KspStream::new(1);

        stream.consume_send_window(100).unwrap();
        assert_eq!(stream.send_window, DEFAULT_WINDOW_SIZE - 100);

        stream.increase_send_window(50);
        assert_eq!(stream.send_window, DEFAULT_WINDOW_SIZE - 50);
    }

    #[test]
    fn test_flow_control_exhausted() {
        let mut stream = KspStream::new(1);
        stream.send_window = 10;

        assert!(matches!(
            stream.consume_send_window(20),
            Err(KspError::FlowControlError(_))
        ));
    }

    #[test]
    fn test_stream_reset() {
        let mut stream = KspStream::new(1);
        stream.reset();
        assert_eq!(stream.state, StreamState::Closed);
    }
}
