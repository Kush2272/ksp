# Security Policy

We take the security of the Kush Secure Protocol (KSP) seriously. This document outlines our vulnerability disclosure process, reporting coordinates, and security hardening decisions.

---

## 🎯 Supported Versions

Security updates are actively backported to the following releases:

| Version | Supported | Release Category |
| :--- | :--- | :--- |
| **v1.x** | ✅ | Stable Core |
| **v0.5.x** | ✅ | Hardening Release |
| **v0.1.x** - **v0.2.x** | ❌ | Legacy / Experimental |

---

## 🕵️ Reporting a Vulnerability

If you discover a security vulnerability (such as a protocol flaw, cryptographic weakness, memory safety issue, or denial-of-service vector), **please do not open a public issue**. Instead, follow this process:

1. **Submit a Confidential Report**: Send an encrypted email to **kush@example.com**.
2. **Encrypted Communication**: If possible, encrypt your email using our PGP public key:
   * **PGP Key ID**: `0x7F2A3B4C5D6E7F8A` (Placeholder fingerprint)
   * **Key Fingerprint**: `ABCD 1234 EF56 7890 12AB  CD34 EF56 7890 12AB CD34`
3. **Information to Include**:
   * Detailed description of the vulnerability.
   * Clear reproduction steps or proof-of-concept (PoC) code.
   * Assessment of the potential impact (CVSS rating estimation, if possible).

### Our Timeline Commitments
* **Acknowledge receipt**: Within 24-48 hours.
* **Triage assessment**: Within 5 business days.
* **Fix & Release Advisory**: Within 30 to 60 days, depending on severity and coordination with consumers.

---

## 🔒 Security Hardening Decisions

KSP is designed with defensive programming and cryptographic best practices:

* **Zero-copy boundary parsing** using structured byte buffers (`bytes` crate).
* **Deterministic counter nonces** to eliminate AEAD encryption failures due to collision.
* **Immediate Zeroization** of private keys and Diffie-Hellman secrets via `zeroize::Zeroize` to protect against side-channel memory reads.
* **Replay-attack mitigation** through sequence numbers validated against an active sliding bitmap.
