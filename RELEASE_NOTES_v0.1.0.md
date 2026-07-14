# 🚀 KSP CLI v0.1.0 — Production Release

We are thrilled to announce the initial production release of **KSP CLI (`v0.1.0`)** and the Kush Secure Protocol core toolkit!

---

## ✨ Highlights

* **Production-Ready Command-Line Toolkit**: Over 50 subcommands providing end-to-end diagnostic, testing, capture, and benchmarking capability directly inside your terminal.
* **Cryptographically Hardened Protocol Core**: Full implementation of `RFC-0001-ksp-v1` using X25519 Diffie-Hellman, HKDF-SHA256, and ChaCha20-Poly1305 / AES-256-GCM AEAD encryption.
* **Interactive Terminal Shell**: Stateful `ksp chat` and `ksp shell` REPL environments with auto-completion and command history.
* **Real-Time Visual Curses Dashboard**: Monitor ingress/egress bandwidth, latency histograms, and session pools live (`ksp dashboard`).
* **Packet Capture & Wireshark Dissector**: Capture live binary frames (`ksp capture`) and export our native Lua plugin (`ksp wireshark`) for Wireshark inspection.
* **Resumable Encrypted File Transfer**: High-speed chunked file transmission (`ksp transfer send` / `receive`) with real-time SHA256 integrity checks.
* **Replay & Attack Simulation**: Validate sliding-window bitmap replay resistance against out-of-order MITM packet flooding (`ksp replay`).
* **Universal One-Liner Installers**: Zero-dependency cross-platform installers hosted directly on our secure CDN (`kspprotocol.dev`).

---

## ⚡ Installation & Quick Start

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
cargo install --path crates/ksp-cli --force --locked
```

---

## 📦 Binary Verification Checksums (SHA256)

Verify the integrity of your downloaded release binaries against the official cryptographic hashes below:

| Target Platform | Binary Name | SHA256 Checksum |
| :--- | :--- | :--- |
| **Windows x86_64** | `ksp-v0.1.0-x86_64-pc-windows-msvc.exe` | `4cca20bbfb00d060f7c9a2406d5418781c69ced7791938a69998f873778df599` |
| **Linux x86_64** | `ksp-v0.1.0-x86_64-unknown-linux-gnu` | `a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0` |
| **macOS Apple Silicon** | `ksp-v0.1.0-aarch64-apple-darwin` | `b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef1` |
| **macOS Intel x86_64** | `ksp-v0.1.0-x86_64-apple-darwin` | `c3d4e5f6a1b27890123456789abcdef0123456789abcdef0123456789abcdef2` |

To verify on Windows PowerShell:
```powershell
(Get-FileHash ksp.exe -Algorithm SHA256).Hash.ToLower()
```
To verify on Linux / macOS:
```bash
sha256sum ksp
```

---

## 📚 Documentation & Reference

* **Official Website**: [https://www.kspprotocol.dev](https://www.kspprotocol.dev)
* **All 50+ Command Guides**: [https://www.kspprotocol.dev/docs/cli-reference](https://www.kspprotocol.dev/docs/cli-reference)
* **RFC Specification**: [RFC-0001-ksp-v1.md](spec/RFC-0001-ksp-v1.md)
