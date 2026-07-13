//! Protocol version negotiation for KSP.
//!
//! Implements version encoding and negotiation as defined in RFC-0001 Section 5.

use crate::error::KspError;

/// A KSP protocol version, consisting of major and minor components.
///
/// Wire encoding: `(major << 4) | minor`, fitting in a single byte.
/// - `0x10` = v1.0
/// - `0x11` = v1.1
/// - `0x20` = v2.0
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl ProtocolVersion {
    /// Create a new protocol version.
    pub const fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// Encode this version into its single-byte wire representation.
    ///
    /// Format: `(major << 4) | minor`
    ///
    /// # Panics
    /// Panics if major or minor exceed 15 (4-bit max).
    pub const fn to_wire(&self) -> u8 {
        assert!(self.major <= 15, "major version must fit in 4 bits");
        assert!(self.minor <= 15, "minor version must fit in 4 bits");
        (self.major << 4) | self.minor
    }

    /// Decode a version from its single-byte wire representation.
    pub const fn from_wire(byte: u8) -> Self {
        Self {
            major: byte >> 4,
            minor: byte & 0x0F,
        }
    }

    /// Negotiate the highest mutually supported version.
    ///
    /// As specified in RFC-0001 Section 5.3:
    /// - The server selects the highest version that appears in both lists.
    /// - If no common version exists, returns `Err(VersionMismatch)`.
    ///
    /// Versions are compared by `(major, minor)` tuple ordering.
    pub fn negotiate(
        client_versions: &[ProtocolVersion],
        server_versions: &[ProtocolVersion],
    ) -> Result<ProtocolVersion, KspError> {
        let mut best: Option<ProtocolVersion> = None;

        for cv in client_versions {
            for sv in server_versions {
                if cv.major == sv.major && cv.minor == sv.minor {
                    match best {
                        None => best = Some(*cv),
                        Some(current_best) => {
                            if (cv.major, cv.minor) > (current_best.major, current_best.minor) {
                                best = Some(*cv);
                            }
                        }
                    }
                }
            }
        }

        best.ok_or(KspError::VersionMismatch)
    }

    /// Check if this version is compatible with another version.
    ///
    /// As per RFC-0001 Section 5.5:
    /// - Same major version = compatible (minor differences are backward-compatible)
    /// - Different major version = incompatible
    pub fn is_compatible_with(&self, other: &ProtocolVersion) -> bool {
        self.major == other.major
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl PartialOrd for ProtocolVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProtocolVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor).cmp(&(other.major, other.minor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_encoding() {
        let v10 = ProtocolVersion::new(1, 0);
        assert_eq!(v10.to_wire(), 0x10);
        assert_eq!(ProtocolVersion::from_wire(0x10), v10);

        let v11 = ProtocolVersion::new(1, 1);
        assert_eq!(v11.to_wire(), 0x11);

        let v20 = ProtocolVersion::new(2, 0);
        assert_eq!(v20.to_wire(), 0x20);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", ProtocolVersion::new(1, 0)), "1.0");
        assert_eq!(format!("{}", ProtocolVersion::new(2, 3)), "2.3");
    }

    #[test]
    fn test_negotiate_success() {
        let client = vec![
            ProtocolVersion::new(2, 0),
            ProtocolVersion::new(1, 1),
            ProtocolVersion::new(1, 0),
        ];
        let server = vec![ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 2)];

        let result = ProtocolVersion::negotiate(&client, &server).unwrap();
        assert_eq!(result, ProtocolVersion::new(1, 0));
    }

    #[test]
    fn test_negotiate_highest_common() {
        let client = vec![ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 1)];
        let server = vec![ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 1)];

        let result = ProtocolVersion::negotiate(&client, &server).unwrap();
        assert_eq!(result, ProtocolVersion::new(1, 1));
    }

    #[test]
    fn test_negotiate_no_common() {
        let client = vec![ProtocolVersion::new(2, 0)];
        let server = vec![ProtocolVersion::new(1, 0)];

        assert!(matches!(
            ProtocolVersion::negotiate(&client, &server),
            Err(KspError::VersionMismatch)
        ));
    }

    #[test]
    fn test_ordering() {
        let v10 = ProtocolVersion::new(1, 0);
        let v11 = ProtocolVersion::new(1, 1);
        let v20 = ProtocolVersion::new(2, 0);

        assert!(v10 < v11);
        assert!(v11 < v20);
        assert!(v10 < v20);
    }

    #[test]
    fn test_compatibility() {
        let v10 = ProtocolVersion::new(1, 0);
        let v11 = ProtocolVersion::new(1, 1);
        let v20 = ProtocolVersion::new(2, 0);

        assert!(v10.is_compatible_with(&v11));
        assert!(!v10.is_compatible_with(&v20));
    }
}
