//! KSP Certificate system.
//!
//! Ed25519-signed certificates for server (and optionally client) authentication.
//! Defined in RFC-0001 Section 9.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use uuid::Uuid;

use ksp_core::constants::{ED25519_PUBLIC_KEY_SIZE, ED25519_SIGNATURE_SIZE};
use ksp_core::error::KspError;

/// A KSP certificate containing a public key, identity, and Ed25519 signature.
///
/// Wire format defined in RFC-0001 Section 9.1.
#[derive(Debug, Clone)]
pub struct KspCertificate {
    /// Certificate format version
    pub version: u8,
    /// Subject identifier (e.g., "ksp://myserver.com")
    pub subject: String,
    /// Ed25519 public key (32 bytes)
    pub public_key: [u8; ED25519_PUBLIC_KEY_SIZE],
    /// Issuer identifier (e.g., "self-signed" or CA name)
    pub issuer: String,
    /// Validity start (Unix timestamp, seconds)
    pub not_before: u64,
    /// Validity end (Unix timestamp, seconds)
    pub not_after: u64,
    /// Unique serial number (UUID)
    pub serial_number: [u8; 16],
    /// Ed25519 signature over all preceding fields
    pub signature: [u8; ED25519_SIGNATURE_SIZE],
}

impl KspCertificate {
    /// Generate a new self-signed certificate.
    ///
    /// Returns `(certificate, signing_key)`. The signing key should be
    /// stored securely — it's needed to prove ownership during handshake.
    pub fn generate_self_signed(subject: &str, validity_days: u32) -> (KspCertificate, SigningKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let not_before = now;
        let not_after = now + (validity_days as u64 * 86400);
        let serial_number = *Uuid::new_v4().as_bytes();

        let mut cert = KspCertificate {
            version: 1,
            subject: subject.to_string(),
            public_key,
            issuer: "self-signed".to_string(),
            not_before,
            not_after,
            serial_number,
            signature: [0u8; ED25519_SIGNATURE_SIZE], // placeholder
        };

        // Sign the certificate data
        let data_to_sign = cert.signable_bytes();
        let signature = signing_key.sign(&data_to_sign);
        cert.signature = signature.to_bytes();

        (cert, signing_key)
    }

    /// Get the bytes that are covered by the signature.
    ///
    /// This includes all fields except the signature itself.
    fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.push(self.version);

        // Subject (length-prefixed)
        let subject_bytes = self.subject.as_bytes();
        buf.extend_from_slice(&(subject_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(subject_bytes);

        // Public key
        buf.extend_from_slice(&self.public_key);

        // Issuer (length-prefixed)
        let issuer_bytes = self.issuer.as_bytes();
        buf.extend_from_slice(&(issuer_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(issuer_bytes);

        // Timestamps
        buf.extend_from_slice(&self.not_before.to_be_bytes());
        buf.extend_from_slice(&self.not_after.to_be_bytes());

        // Serial number
        buf.extend_from_slice(&self.serial_number);

        buf
    }

    /// Verify the certificate's signature against the issuer's public key.
    ///
    /// For self-signed certificates, the issuer key is the certificate's own public key.
    pub fn verify(
        &self,
        issuer_public_key: &[u8; ED25519_PUBLIC_KEY_SIZE],
    ) -> Result<(), KspError> {
        let verifying_key = VerifyingKey::from_bytes(issuer_public_key)
            .map_err(|e| KspError::CertificateError(format!("invalid public key: {}", e)))?;

        let signature = Signature::from_bytes(&self.signature);

        let data_to_verify = self.signable_bytes();
        verifying_key
            .verify(&data_to_verify, &signature)
            .map_err(|_| KspError::CertificateError("signature verification failed".into()))
    }

    /// Verify this certificate is self-signed (signature matches its own public key).
    pub fn verify_self_signed(&self) -> Result<(), KspError> {
        self.verify(&self.public_key)
    }

    /// Check if the certificate has expired.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.not_after
    }

    /// Check if the certificate is not yet valid.
    pub fn is_not_yet_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now < self.not_before
    }

    /// Full validation: check signature, expiration, and validity period.
    pub fn validate_self_signed(&self) -> Result<(), KspError> {
        if self.is_expired() {
            return Err(KspError::CertificateExpired);
        }
        if self.is_not_yet_valid() {
            return Err(KspError::CertificateError(
                "certificate not yet valid".into(),
            ));
        }
        self.verify_self_signed()
    }

    /// Serialize the certificate to binary format.
    ///
    /// Wire layout matches RFC-0001 Section 9.1.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.push(self.version);

        let subject_bytes = self.subject.as_bytes();
        buf.extend_from_slice(&(subject_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(subject_bytes);

        buf.extend_from_slice(&self.public_key);

        let issuer_bytes = self.issuer.as_bytes();
        buf.extend_from_slice(&(issuer_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(issuer_bytes);

        buf.extend_from_slice(&self.not_before.to_be_bytes());
        buf.extend_from_slice(&self.not_after.to_be_bytes());

        buf.extend_from_slice(&self.serial_number);

        buf.extend_from_slice(&self.signature);

        buf
    }

    /// Deserialize a certificate from binary format.
    pub fn deserialize(buf: &[u8]) -> Result<KspCertificate, KspError> {
        let mut pos = 0;

        if buf.len() < 1 {
            return Err(KspError::InvalidPacket("certificate too short".into()));
        }

        let version = buf[pos];
        pos += 1;

        // Subject
        if buf.len() < pos + 2 {
            return Err(KspError::InvalidPacket(
                "certificate truncated at subject length".into(),
            ));
        }
        let subject_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;

        if buf.len() < pos + subject_len {
            return Err(KspError::InvalidPacket(
                "certificate truncated at subject".into(),
            ));
        }
        let subject = String::from_utf8(buf[pos..pos + subject_len].to_vec())
            .map_err(|_| KspError::InvalidPacket("invalid UTF-8 in subject".into()))?;
        pos += subject_len;

        // Public key
        if buf.len() < pos + ED25519_PUBLIC_KEY_SIZE {
            return Err(KspError::InvalidPacket(
                "certificate truncated at public key".into(),
            ));
        }
        let mut public_key = [0u8; ED25519_PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(&buf[pos..pos + ED25519_PUBLIC_KEY_SIZE]);
        pos += ED25519_PUBLIC_KEY_SIZE;

        // Issuer
        if buf.len() < pos + 2 {
            return Err(KspError::InvalidPacket(
                "certificate truncated at issuer length".into(),
            ));
        }
        let issuer_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;

        if buf.len() < pos + issuer_len {
            return Err(KspError::InvalidPacket(
                "certificate truncated at issuer".into(),
            ));
        }
        let issuer = String::from_utf8(buf[pos..pos + issuer_len].to_vec())
            .map_err(|_| KspError::InvalidPacket("invalid UTF-8 in issuer".into()))?;
        pos += issuer_len;

        // Timestamps
        if buf.len() < pos + 16 {
            return Err(KspError::InvalidPacket(
                "certificate truncated at timestamps".into(),
            ));
        }
        let not_before = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let not_after = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Serial number
        if buf.len() < pos + 16 {
            return Err(KspError::InvalidPacket(
                "certificate truncated at serial".into(),
            ));
        }
        let mut serial_number = [0u8; 16];
        serial_number.copy_from_slice(&buf[pos..pos + 16]);
        pos += 16;

        // Signature
        if buf.len() < pos + ED25519_SIGNATURE_SIZE {
            return Err(KspError::InvalidPacket(
                "certificate truncated at signature".into(),
            ));
        }
        let mut signature = [0u8; ED25519_SIGNATURE_SIZE];
        signature.copy_from_slice(&buf[pos..pos + ED25519_SIGNATURE_SIZE]);

        Ok(KspCertificate {
            version,
            subject,
            public_key,
            issuer,
            not_before,
            not_after,
            serial_number,
            signature,
        })
    }
}

impl std::fmt::Display for KspCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "KSP Certificate v{} | Subject: {} | Issuer: {} | Serial: {}",
            self.version,
            self.subject,
            self.issuer,
            uuid::Uuid::from_bytes(self.serial_number),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_self_signed() {
        let (cert, _signing_key) = KspCertificate::generate_self_signed("ksp://test.local", 365);

        assert_eq!(cert.version, 1);
        assert_eq!(cert.subject, "ksp://test.local");
        assert_eq!(cert.issuer, "self-signed");

        // Should verify successfully
        cert.verify_self_signed().unwrap();
        cert.validate_self_signed().unwrap();
    }

    #[test]
    fn test_tampered_cert_fails_verification() {
        let (mut cert, _) = KspCertificate::generate_self_signed("ksp://test.local", 365);

        // Tamper with the subject
        cert.subject = "ksp://evil.local".to_string();

        // Verification should fail
        assert!(cert.verify_self_signed().is_err());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let (cert, _) = KspCertificate::generate_self_signed("ksp://roundtrip.test", 365);

        let bytes = cert.serialize();
        let deserialized = KspCertificate::deserialize(&bytes).unwrap();

        assert_eq!(deserialized.version, cert.version);
        assert_eq!(deserialized.subject, cert.subject);
        assert_eq!(deserialized.public_key, cert.public_key);
        assert_eq!(deserialized.issuer, cert.issuer);
        assert_eq!(deserialized.not_before, cert.not_before);
        assert_eq!(deserialized.not_after, cert.not_after);
        assert_eq!(deserialized.serial_number, cert.serial_number);
        assert_eq!(deserialized.signature, cert.signature);

        // Deserialized cert should still verify
        deserialized.verify_self_signed().unwrap();
    }

    #[test]
    fn test_not_expired() {
        let (cert, _) = KspCertificate::generate_self_signed("ksp://test.local", 365);
        assert!(!cert.is_expired());
        assert!(!cert.is_not_yet_valid());
    }

    #[test]
    fn test_display() {
        let (cert, _) = KspCertificate::generate_self_signed("ksp://display.test", 365);
        let display = format!("{}", cert);
        assert!(display.contains("ksp://display.test"));
        assert!(display.contains("self-signed"));
    }
}
