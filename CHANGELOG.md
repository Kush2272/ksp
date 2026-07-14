# Changelog

All notable changes to the Kush Secure Protocol (KSP) and KSP CLI ecosystem will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.0] - 2026-07-15

### Added
- **Interactive CLI**: Production-ready command-line toolkit (`ksp-cli`) with over 50 specialized subcommands and rich ANSI terminal graphics.
- **Secure File Transfer**: High-speed, chunked, encrypted file transfer harness (`ksp transfer send` / `ksp transfer receive`) with cryptographic verification.
- **Benchmark Suite**: Criterion-based and live CLI stress benchmark engine (`ksp benchmark`) supporting latency jitter and throughput simulation.
- **Terminal Dashboard**: Real-time curses-style visual dashboard (`ksp dashboard`) monitoring packet pipelines, bandwidth, and session health.
- **Packet Capture & Inspection**: Deep packet capture (`ksp capture`, `ksp inspect`) with binary hex dumping and protocol field verification.
- **Wireshark Dissector**: Lua plugin engine (`ksp wireshark`) for seamless packet dissection and analysis inside Wireshark.
- **Replay & Attack Simulation**: Advanced sliding-window replay protection testing (`ksp replay`, `ksp attack`) to verify resistance against MITM/replay attacks.
- **Secure Proxy & Gateway**: Lightweight reverse proxy and TLS/KSP gateway modes (`ksp proxy`, `ksp gateway`).
- **Session & Stream Managers**: Multiplexed stream control (`ksp session`, `ksp stream`) handling concurrency and keepalive frames.
- **Configuration & Profiles System**: Hierarchical YAML/TOML configuration management (`ksp config`, `ksp profile`) with environment variable overrides.
- **Certificate Management**: Self-signed Ed25519/X25519 certificate generation and verification (`ksp cert gen`, `ksp cert verify`).
- **RFC Explorer**: Interactive protocol specification inspection (`ksp rfc`, `ksp rfc search`) built directly into the terminal.
- **Interactive Shell Mode**: Stateful REPL command prompt (`ksp chat`, `ksp shell`) with history tracking and auto-completion.
- **Documentation & Command Search**: Global command documentation viewer (`ksp docs`, `ksp info`, `ksp doctor`).
- **Structured JSON & Matrix Outputs**: Script-friendly JSON output (`--json`) across all diagnostic commands and fun `ksp matrix` screen saver.
- **Easter Eggs & Visual Enhancements**: `ksp coffee`, `ksp dance` (Rickroll), and `ksp journey` 3D ASCII packet pipeline visualizer.
- **Core Protocol Specification**: Comprehensive specification in `spec/RFC-0001-ksp-v1.md`.
- **Cryptographic Engine**: `ksp-crypto` leveraging X25519 Diffie-Hellman, HKDF-SHA256, and ChaCha20-Poly1305/AES-256-GCM.

### Improved
- **Better Installer**: Zero-dependency cross-platform one-liner installer scripts (`install.ps1`, `install.sh`) hosted on `kspprotocol.dev` with automatic architecture detection and PATH management.
- **Faster Startup**: Optimized asynchronous tokio event loops yielding sub-millisecond CLI initialization times.
- **Improved Benchmark UI**: Live histogram rendering and detailed latency percentiles (p50, p95, p99) inside terminal benchmark reports.
- **Better Diagnostics**: Enhanced `ksp doctor` health check covering network interfaces, firewall rules, local certificate permissions, and DNS resolution.

### Fixed
- **Windows Installer & Uninstaller Improvements**: Resolved Windows file-lock access denied (`os error 5`) issues via automated scheduled background cleanup (`cmd.exe timeout`).
- **Better Error Messages**: Human-readable, actionable error messages with direct troubleshooting hints and links across all subcommands.
