# KSP Benchmarks & Performance Metrics

This document lists reproducible benchmark results for the Kush Secure Protocol (KSP) v1.0. 
Benchmarks were executed using [Criterion](https://crates.io/crates/criterion) on the local host machine:

### Test Environment
* **CPU**: 13th Gen Intel(R) Core(TM) i7-13650HX
* **OS**: Windows 11 Home (Build 22631)
* **Rust version**: v1.96.1 (stable-x86_64-pc-windows-msvc)
* **Mode**: Release Mode (`--release`)
* **Benchmarking Harness**: Criterion 0.5.1

---

## 📊 Summary of Metrics

| Metric | KSP | Notes / Details |
|:---|:---|:---|
| **Handshake Latency** | `76.0 µs` (0.076 ms) | Ephemeral X25519 DH + Key Derivation (HKDF-SHA256) |
| **1KB Serialization** | `41.4 ns` | Header construction and big-endian encoding |
| **1KB Deserialization** | `65.9 ns` | Parser performance and signature checks |
| **Throughput (AES-256-GCM)** | `1,770 MB/s` | Single-core decryption throughput (64 KB payloads) |
| **Throughput (ChaCha20-Poly1305)** | `1,310 MB/s` | Single-core encryption throughput (64 KB payloads) |

---

## 📈 Detailed Benchmark Results

### 1. Handshake Micro-benchmarks

The handshake benchmark measures the time taken to complete the cryptographic operations required during key exchange and identity verification:
1. Client generates ephemeral X25519 keypair and client random.
2. Server generates ephemeral keypair, server random.
3. Both compute the X25519 shared secret and derive keys via HKDF-SHA256.

```
handshake/ksp_handshake_setup
                        time:   [75.498 µs 76.000 µs 76.534 µs]
```

*Conclusion*: A single CPU thread can perform ~13,150 complete cryptographic handshakes per second.

### 2. Encryption and Decryption Throughput (AEAD)

We measure the single-threaded throughput of `encrypt` and `decrypt` operations using different payload sizes (1 KB, 64 KB, 1 MB).

#### AES-256-GCM (Hardware Accelerated via AES-NI)
- **1 KB Encryption**: `824.37 ns` (~1,213 MB/s)
- **1 KB Decryption**: `918.40 ns` (~1,088 MB/s)
- **64 KB Encryption**: `37.91 µs` (~1,728 MB/s)
- **64 KB Decryption**: `36.84 µs` (~1,778 MB/s)
- **1 MB Encryption**: `1.06 ms` (~986 MB/s)
- **1 MB Decryption**: `1.08 ms` (~964 MB/s)

#### ChaCha20-Poly1305 (Software-Fallback Suite)
- **1 KB Encryption**: `1.98 µs` (~505 MB/s)
- **64 KB Encryption**: `49.74 µs` (~1,316 MB/s)
- **1 MB Encryption**: `1.24 ms` (~840 MB/s)

---

## 🛠️ How to Reproduce Benchmarks

Ensure your Rust toolchain and Visual Studio Build Tools are installed, then run Criterion benchmarks:

```powershell
# Setup cargo on PATH
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

# Run all benchmark targets using a temp directory to avoid IDE file-locks
cargo bench --target-dir C:\Users\kush\AppData\Local\Temp\ksp_target
```
