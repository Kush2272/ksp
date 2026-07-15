# 💡 KSP Code & CLI Examples (`examples/`)

Welcome to the **Kush Secure Protocol (KSP)** examples directory! This collection provides runnable, real-world templates and code samples demonstrating how to build high-performance distributed systems using KSP and the `ksp` CLI.

---

## 🚀 Available Examples

| Directory | Name | Description |
| :--- | :--- | :--- |
| **[`chat/`](chat/)** | **Encrypted Multi-User Chat** | Full-duplex terminal chat room utilizing KSP session management and X25519 DH key exchange. |
| **[`transfer/`](transfer/)** | **Resumable File Transfer** | High-speed chunked file transfer with post-transfer SHA-256 integrity verification over KSP multiplexed streams. |
| **[`proxy/`](proxy/)** | **Secure Reverse Proxy** | Load-balancing KSP reverse proxy forwarding encrypted client frames across multiple backend worker pools. |
| **[`gateway/`](gateway/)** | **HTTP / WebSocket Bridge** | Protocol bridge translating incoming WebSocket frames into low-latency KSP binary packets. |
| **[`dashboard/`](dashboard/)** | **Telemetry Exporter** | Custom telemetry harness reporting live bandwidth rates, latency jitter, and stream health into `ksp dashboard`. |
| **[`benchmark/`](benchmark/)** | **Automated Stress Harness** | Automated stress-testing script and Criterion benchmark harness exporting latency histograms (`p50`, `p95`, `p99`). |

---

## 🛠️ Running the Examples

### Using the `ksp` CLI directly
You can instantly run and test these patterns from your terminal:
```bash
# Start an interactive chat session
ksp chat --peer 127.0.0.1:9876 --nick Alice

# Run the benchmark harness against a local target
ksp benchmark --target 127.0.0.1:9876 --streams 16 --duration 10s

# Launch the visual curses-style dashboard
ksp dashboard --interval 500ms
```

### Compiling Rust SDK code
To run the native Rust FFI examples inside these directories:
```bash
# Run the chat server example
cargo run --example chat_server -- --port 9876

# Run the reverse proxy load balancer
cargo run --example reverse_proxy -- --bind 127.0.0.1:8080 --backends 127.0.0.1:9001,127.0.0.1:9002
```

---

## 💬 Have an Example to Add?
If you've built a novel architecture or application using KSP, open a Pull Request following our [CONTRIBUTING.md](../CONTRIBUTING.md) guidelines!
