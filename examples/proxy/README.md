# 🔀 Secure KSP Reverse Proxy (`examples/proxy/`)

Demonstrates how to build a high-concurrency KSP reverse proxy load balancer in Rust.

## Architecture
- **Inbound Listeners**: Accepts encrypted client sessions on port `8080`.
- **Backend Pool**: Maintains active persistent keepalive pools to worker nodes `127.0.0.1:9001` and `127.0.0.1:9002`.
- **Zero-Copy Forwarding**: Decouples header verification from payload copying, yielding ultra-low forwarding latency (< 50 microseconds).

## Quick CLI Testing
```bash
# Launch proxy with round-robin balancing across backend workers
ksp proxy --bind 127.0.0.1:8080 --backends 127.0.0.1:9001,127.0.0.1:9002 --strategy round-robin
```
