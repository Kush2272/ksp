# Changelog

All notable changes to the Kush Secure Protocol (KSP) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Proposal for post-quantum hybrid key exchange (ML-KEM + X25519) integration design.
- Plans for custom CLI helper tool (`ksp-cli`).

## [0.1.0] - 2026-07-13

### Added
- Initial protocol specification in `spec/RFC-0001-ksp-v1.md`.
- Core packet binary serialization and deserialization engine in `ksp-core`.
- Cryptographic primitive implementation in `ksp-crypto` leveraging X25519 Diffie-Hellman, HKDF-SHA256, and AEAD (AES-256-GCM / ChaCha20-Poly1305).
- Handshake state machine implementation in `ksp-handshake`.
- Keepalive protocol and sliding-window replay protection in `ksp-transport`.
- High-level client and server async loops in `ksp-client` and `ksp-server`.
- Integration test suite validating end-to-end packet encryption, handshake, and transport functionality.
- Performance benchmark harness using Criterion.
- Wireshark dissector plugin written in Lua.
- Docker configuration and Docker Compose environment.
