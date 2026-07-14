# 🚀 KSP CLI v0.1.0 — Initial Production Release

We are excited to announce the initial production release of **KSP CLI (`v0.1.0`)** and the Kush Secure Protocol (`RFC-0001-ksp-v1`) ecosystem!

---

## ✨ Highlights

* **50+ Production-Grade Commands**: Complete end-to-end diagnostic, testing, capture, and benchmarking capability directly inside your terminal.
* **Cryptographically Hardened Protocol Core**: Full binary framing specification using X25519 Diffie-Hellman key exchange, HKDF-SHA256, and ChaCha20-Poly1305 / AES-256-GCM AEAD encryption.
* **Resumable Encrypted File Transfer**: High-speed chunked transmission (`ksp transfer send` / `receive`) over multiplexed streams with real-time SHA256 verification.
* **Packet Capture & Wireshark Dissector**: Capture live binary frames (`ksp capture`) and export our native Lua plugin (`ksp wireshark`) for Wireshark inspection.
* **Real-Time Visual Curses Dashboard**: Monitor ingress/egress bandwidth, latency histograms, and session pools live (`ksp dashboard`).
* **Universal One-Liner Installers**: Zero-dependency cross-platform installers hosted directly on our CDN (`kspprotocol.dev`).

---

## 🆕 What's New

* **Interactive Terminal Shell (`ksp chat` / `ksp shell`)**: Stateful REPL environments with command history tracking and auto-completion.
* **Automated System Diagnostics (`ksp doctor`)**: End-to-end audit checking network interfaces, firewall rules, local certificates, and DNS resolution.
* **Sliding-Window Replay Protection (`ksp replay` / `ksp attack`)**: Validate replay resistance against out-of-order MITM packet flooding.
* **Reverse Proxy & Gateway (`ksp proxy` / `ksp gateway`)**: Launch high-concurrency reverse proxies and HTTP/WebSocket-to-KSP binary bridges.

---

## ⚡ Installation

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

## ⚠️ Breaking Changes

* **v0.1.0 is our initial public beta release (`v0.1.x`)**. While wire binary framing (`RFC-0001-ksp-v1`) is stable, minor configuration flags and subcommand arguments may evolve during the `0.x` lifecycle prior to `v1.0.0`.

---

## 🐛 Known Issues & Workarounds

* **Windows File Locking (`os error 5`) during `ksp update` or `ksp uninstall`**: If `ksp.exe` is actively running, Windows locks the executable file. Our latest `install.ps1` script automatically schedules a background timeout task (`cmd.exe /c timeout /t 2 && del`) to cleanly replace binaries without requiring a system reboot.

---

## 📦 Checksums & Asset Verification

Verify the integrity of your downloaded release assets against the official cryptographic hashes below:

| Release Asset File | Description | SHA256 Checksum |
| :--- | :--- | :--- |
| **`ksp-windows-x64.zip`** | Windows x86_64 Archive | `774be89919cde005516eae040be10aacb79892e5ff2fbd9a70e26c8179fa4a91` |
| **`ksp.exe`** | Windows Native Binary | `4cca20bbfb00d060f7c9a2406d5418781c69ced7791938a69998f873778df599` |
| **`checksums.txt`** | Master SHA256 Manifest | Attached in release assets |

To verify on Windows PowerShell:
```powershell
(Get-FileHash ksp-windows-x64.zip -Algorithm SHA256).Hash.ToLower()
```
To verify on Linux / macOS:
```bash
sha256sum -c checksums.txt
```

---

## 📚 Documentation

* **Release Notes Hub**: [https://www.kspprotocol.dev/docs/release-notes](https://www.kspprotocol.dev/docs/release-notes)
* **All 50+ Command Guides**: [https://www.kspprotocol.dev/docs/cli-reference](https://www.kspprotocol.dev/docs/cli-reference)
* **Troubleshooting Guide**: [https://www.kspprotocol.dev/docs/troubleshooting](https://www.kspprotocol.dev/docs/troubleshooting)

---

## 🌐 GitHub & Website

* **Official Website**: [www.kspprotocol.dev](https://www.kspprotocol.dev)
* **GitHub Repository**: [github.com/Kush2272/ksp](https://github.com/Kush2272/ksp)
* **Private Security Advisories**: [github.com/Kush2272/ksp/security](https://github.com/Kush2272/ksp/security/advisories/new)
