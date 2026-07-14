# 🔐 KSP (Kush Secure Protocol) & KSP CLI

<div align="center">

[![CI Status](https://github.com/Kush2272/ksp/workflows/CI/badge.svg)](https://github.com/Kush2272/ksp/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org)
[![Release](https://img.shields.io/badge/Release-v0.1.0-blue.svg)](https://www.kspprotocol.dev/download)
[![Downloads](https://img.shields.io/badge/Downloads-10k%2B-green.svg)](https://www.kspprotocol.dev/download)
[![Official Website](https://img.shields.io/badge/🌐_Website-kspprotocol.dev-6366f1.svg)](https://www.kspprotocol.dev)
[![Discord Community](https://img.shields.io/badge/💬_Discord-Join_Community-5865f2.svg)](https://www.kspprotocol.dev/community)
[![Documentation](https://img.shields.io/badge/📚_Docs-All_50%2B_Commands-00e5ff.svg)](https://www.kspprotocol.dev/docs/cli-reference)

<br />

**A Production-Grade, Cryptographically Hardened Application-Layer Protocol & CLI Toolkit Built in Rust**

[Official Website](https://www.kspprotocol.dev) · [All 50+ CLI Commands](https://www.kspprotocol.dev/docs/cli-reference) · [RFC Specification](spec/RFC-0001-ksp-v1.md) · [Security Policy](SECURITY.md) · [Contributing Guide](CONTRIBUTING.md)

</div>

---

## ❓ What is KSP?

Traditional protocols like HTTPS (HTTP/2 or HTTP/3 over TLS 1.3/QUIC) rely on extensive historical features—complex X.509 certificate chains, massive cipher suites, text-header parsing overhead, and backward-compatibility hooks. 

**KSP (Kush Secure Protocol)** is an application-layer protocol and high-performance toolkit designed from scratch in Rust for low-latency, secure, multiplexed communication. It isolates transport, session state, AEAD encryption, and cryptographic handshakes into decoupled, highly verifiable components.

Accompanied by **KSP CLI (`ksp-cli`)**, engineers and developers gain over 50 specialized commands to send packets, inspect wire frames, benchmark real-world throughput, transfer encrypted files, and dissect traffic natively or inside Wireshark.

---

## 🚀 Quick Install

Install the official pre-built `ksp` binary globally onto your system using our verified one-liner scripts (hosted directly on `kspprotocol.dev` with zero external third-party dependencies):

### Windows (PowerShell)
```powershell
irm https://www.kspprotocol.dev/install.ps1 | iex
```

### Linux & macOS (Terminal)
```bash
curl -fsSL https://www.kspprotocol.dev/install.sh | sh
```

### Rust Cargo
```bash
# From inside the local workspace source checkout:
cargo install --path crates/ksp-cli --force --locked
```

---

## 💻 Hello World (Rust SDK)

Integrating KSP into your async Rust application is clean and intuitive:

### Client Example
```rust
use ksp_client::KspClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect and execute cryptographic X25519 Diffie-Hellman handshake
    let mut client = KspClient::connect("127.0.0.1:9876").await?;
    println!("Session established! Session ID: {}", client.session_id());

    // Send encrypted binary payload over multiplexed stream 1
    client.send(1, b"Hello, secure KSP server!").await?;

    // Receive decrypted response
    let response = client.receive(1).await?;
    println!("Received: {}", String::from_utf8_lossy(&response));

    Ok(())
}
```

---

## ⚡ 50+ Production CLI Features

The `ksp` binary provides an all-in-one suite of protocol utilities:

| Command Category | Key Subcommands | Purpose |
| :--- | :--- | :--- |
| **Diagnostics & Health** | `ksp doctor`, `ksp ping`, `ksp info` | Verify network interfaces, firewall rules, and end-to-end connectivity. |
| **Interactive REPL** | `ksp chat`, `ksp shell` | Stateful interactive terminal session with auto-completion and command history. |
| **Secure File Transfer** | `ksp transfer send`, `ksp transfer receive` | Chunked, encrypted file transfer over KSP streams with real-time SHA256 verification. |
| **Traffic & Packet Analysis** | `ksp capture`, `ksp inspect`, `ksp wireshark` | Capture binary packets, format hex dumps, and export Lua plugins for Wireshark. |
| **Performance Benchmarking** | `ksp benchmark`, `ksp benchmark live` | Run latency jitter tests, throughput stress simulations, and ASCII histograms. |
| **Live Visual Dashboard** | `ksp dashboard` | Real-time terminal monitoring of packet pipelines, bandwidth rates, and session pools. |
| **Proxy & Gateway Modes** | `ksp proxy`, `ksp gateway` | Launch reverse proxies and protocol bridges handling high-concurrency client pools. |
| **Replay & Attack Testing** | `ksp replay`, `ksp attack` | Validate sliding-window replay protection by simulating out-of-order MITM frames. |
| **Certificate Management** | `ksp cert gen`, `ksp cert verify` | Generate self-signed Ed25519/X25519 cryptographic identity pairs. |
| **Protocol Specification** | `ksp rfc`, `ksp rfc search` | Search and inspect the official KSP RFC specification directly in your terminal. |

---

## 📂 Examples Repository

Explore runnable, production-grade templates inside the [`examples/`](examples/) directory:
- [`examples/chat/`](examples/chat/) — Multi-user encrypted chat server and terminal client.
- [`examples/transfer/`](examples/transfer/) — High-speed chunked file sender and receiver with resume support.
- [`examples/proxy/`](examples/proxy/) — Reverse proxy routing KSP packets across backend server instances.
- [`examples/gateway/`](examples/gateway/) — Protocol bridge converting HTTP/WebSocket requests into KSP frames.
- [`examples/dashboard/`](examples/dashboard/) — Custom metrics exporter interfacing with `ksp dashboard`.
- [`examples/benchmark/`](examples/benchmark/) — Automated performance testing harness and CSV report generator.

---

## 📚 Documentation & Governance

We maintain strict governance and documentation standards:

| Document | Description |
| :--- | :--- |
| **[CHANGELOG.md](CHANGELOG.md)** | Detailed record of all new features, enhancements, and bug fixes across versions. |
| **[SECURITY.md](SECURITY.md)** | Vulnerability reporting procedures, supported versions, and cryptographic guarantees. |
| **[CONTRIBUTING.md](CONTRIBUTING.md)** | Development environment setup, building, testing, pull request rules, and code style. |
| **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** | Community standards adhering to the Contributor Covenant. |
| **[RFC Specification](spec/RFC-0001-ksp-v1.md)** | Binary layout, header fields, cryptographic handshakes, and transport mechanics. |

---

## 🗺️ Project Roadmap

- [x] **CLI Engine (`ksp-cli`)** — ✓ Complete (50+ commands & interactive shell)
- [x] **Protocol Core (`ksp-core`, `ksp-crypto`)** — ✓ Complete (X25519, HKDF, ChaCha20/AES-GCM)
- [x] **Rust & SDK Implementations** — ✓ Complete (Async Tokio client/server loops)
- [x] **Developer Portal (`kspprotocol.dev`)** — ✓ Complete (Live interactive tools & reference)
- [ ] **KSP Browser Extension** — 🔄 In Progress (Developer Preview early 2027)
- [ ] **VS Code Extension** — 📅 Planned (Interactive packet visualizer inside IDE)
- [ ] **Language Bindings** — 📅 Planned (Python, Go, and TypeScript native FFI SDKs)
- [ ] **Cloud Gateway** — 📅 Planned (Managed edge routing and global keepalive mesh)

---

## 🤝 Contributing & Discussions

We welcome contributions from protocol engineers, cryptographers, and Rust developers!
1. Check out [CONTRIBUTING.md](CONTRIBUTING.md) to set up your local development environment.
2. Join our **[GitHub Discussions](https://github.com/Kush2272/ksp/discussions)** to share ideas, ask questions, or showcase your projects built on KSP!

<div align="center">
  <sub>Built with ❤️ by Kush and the KSP Open Source Community. Released under the MIT License.</sub>
</div>
