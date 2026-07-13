//! Authentication methods for KSP.
//!
//! Supports multiple authentication strategies as defined in RFC-0001 Section 10.

use ksp_core::error::KspError;

/// Supported authentication methods.
///
/// Negotiated during the handshake — the server indicates required methods
/// and the client responds with credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// No authentication required (code 0x00)
    None,
    /// Username + password hash (code 0x01)
    Password {
        username: String,
        password_hash: Vec<u8>,
    },
    /// Pre-shared API key (code 0x02)
    ApiKey { key: Vec<u8> },
    /// Bearer token, e.g., JWT (code 0x03)
    Token { token: Vec<u8> },
    /// Mutual authentication via client certificate (code 0x04)
    MutualTls { client_cert_bytes: Vec<u8> },
}

impl AuthMethod {
    /// Wire code for this authentication method.
    pub fn code(&self) -> u8 {
        match self {
            AuthMethod::None => 0x00,
            AuthMethod::Password { .. } => 0x01,
            AuthMethod::ApiKey { .. } => 0x02,
            AuthMethod::Token { .. } => 0x03,
            AuthMethod::MutualTls { .. } => 0x04,
        }
    }

    /// Serialize the auth request payload (credentials).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.code());

        match self {
            AuthMethod::None => {}
            AuthMethod::Password {
                username,
                password_hash,
            } => {
                let user_bytes = username.as_bytes();
                buf.extend_from_slice(&(user_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(user_bytes);
                buf.extend_from_slice(&(password_hash.len() as u16).to_be_bytes());
                buf.extend_from_slice(password_hash);
            }
            AuthMethod::ApiKey { key } => {
                buf.extend_from_slice(&(key.len() as u16).to_be_bytes());
                buf.extend_from_slice(key);
            }
            AuthMethod::Token { token } => {
                buf.extend_from_slice(&(token.len() as u16).to_be_bytes());
                buf.extend_from_slice(token);
            }
            AuthMethod::MutualTls { client_cert_bytes } => {
                buf.extend_from_slice(&(client_cert_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(client_cert_bytes);
            }
        }

        buf
    }

    /// Deserialize an auth request from binary payload.
    pub fn deserialize(buf: &[u8]) -> Result<Self, KspError> {
        if buf.is_empty() {
            return Err(KspError::InvalidPacket("AuthMethod is empty".into()));
        }

        let code = buf[0];
        let data = &buf[1..];

        match code {
            0x00 => Ok(AuthMethod::None),
            0x01 => {
                // Password: username_len(2) + username + hash_len(2) + hash
                if data.len() < 2 {
                    return Err(KspError::InvalidPacket("Password auth truncated".into()));
                }
                let user_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                let mut pos = 2;
                if data.len() < pos + user_len + 2 {
                    return Err(KspError::InvalidPacket("Password auth truncated".into()));
                }
                let username = String::from_utf8(data[pos..pos + user_len].to_vec())
                    .map_err(|_| KspError::InvalidPacket("invalid UTF-8 in username".into()))?;
                pos += user_len;

                let hash_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                if data.len() < pos + hash_len {
                    return Err(KspError::InvalidPacket("Password auth truncated".into()));
                }
                let password_hash = data[pos..pos + hash_len].to_vec();

                Ok(AuthMethod::Password {
                    username,
                    password_hash,
                })
            }
            0x02 => {
                if data.len() < 2 {
                    return Err(KspError::InvalidPacket("ApiKey auth truncated".into()));
                }
                let key_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() < 2 + key_len {
                    return Err(KspError::InvalidPacket("ApiKey auth truncated".into()));
                }
                Ok(AuthMethod::ApiKey {
                    key: data[2..2 + key_len].to_vec(),
                })
            }
            0x03 => {
                if data.len() < 2 {
                    return Err(KspError::InvalidPacket("Token auth truncated".into()));
                }
                let token_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() < 2 + token_len {
                    return Err(KspError::InvalidPacket("Token auth truncated".into()));
                }
                Ok(AuthMethod::Token {
                    token: data[2..2 + token_len].to_vec(),
                })
            }
            0x04 => {
                if data.len() < 2 {
                    return Err(KspError::InvalidPacket("MutualTls auth truncated".into()));
                }
                let cert_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() < 2 + cert_len {
                    return Err(KspError::InvalidPacket("MutualTls auth truncated".into()));
                }
                Ok(AuthMethod::MutualTls {
                    client_cert_bytes: data[2..2 + cert_len].to_vec(),
                })
            }
            _ => Err(KspError::InvalidPacket(format!(
                "unknown auth method: 0x{:02X}",
                code
            ))),
        }
    }
}

/// Authentication result sent by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    /// Authentication succeeded
    Success,
    /// Authentication failed
    Failed,
}

impl AuthResult {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            AuthResult::Success => vec![0x01],
            AuthResult::Failed => vec![0x00],
        }
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, KspError> {
        if buf.is_empty() {
            return Err(KspError::InvalidPacket("AuthResult is empty".into()));
        }
        match buf[0] {
            0x01 => Ok(AuthResult::Success),
            0x00 => Ok(AuthResult::Failed),
            _ => Err(KspError::InvalidPacket("invalid auth result code".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_roundtrip() {
        let method = AuthMethod::None;
        let bytes = method.serialize();
        let deserialized = AuthMethod::deserialize(&bytes).unwrap();
        assert_eq!(deserialized, AuthMethod::None);
    }

    #[test]
    fn test_password_roundtrip() {
        let method = AuthMethod::Password {
            username: "kush".into(),
            password_hash: vec![0xAA; 32],
        };
        let bytes = method.serialize();
        let deserialized = AuthMethod::deserialize(&bytes).unwrap();
        assert_eq!(deserialized, method);
    }

    #[test]
    fn test_token_roundtrip() {
        let method = AuthMethod::Token {
            token: b"my.jwt.token".to_vec(),
        };
        let bytes = method.serialize();
        let deserialized = AuthMethod::deserialize(&bytes).unwrap();
        assert_eq!(deserialized, method);
    }

    #[test]
    fn test_api_key_roundtrip() {
        let method = AuthMethod::ApiKey {
            key: b"sk_live_1234567890".to_vec(),
        };
        let bytes = method.serialize();
        let deserialized = AuthMethod::deserialize(&bytes).unwrap();
        assert_eq!(deserialized, method);
    }

    #[test]
    fn test_auth_result_roundtrip() {
        assert_eq!(
            AuthResult::deserialize(&AuthResult::Success.serialize()).unwrap(),
            AuthResult::Success,
        );
        assert_eq!(
            AuthResult::deserialize(&AuthResult::Failed.serialize()).unwrap(),
            AuthResult::Failed,
        );
    }
}
