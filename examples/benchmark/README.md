# 📈 Automated Performance & Stress Harness (`examples/benchmark/`)

Automated stress testing scripts and Criterion benchmarks for evaluating KSP throughput and latency under heavy concurrency.

## Benchmarks Included
1. **Handshake Jitter**: Measures time required to perform X25519 DH key generation, HKDF derivation, and state transition across 10,000 concurrent iterations.
2. **Bulk Payload Throughput**: Measures max throughput (GB/s) when streaming 1 MB ChaCha20-Poly1305 encrypted chunks across loopback interfaces.
3. **Replay Window Stress**: Verifies sliding bitmap lookup performance when subjected to out-of-order MITM packet flooding.

## Quick CLI Testing
```bash
# Run interactive stress test across 64 concurrent streams for 15 seconds
ksp benchmark --target 127.0.0.1:9876 --streams 64 --duration 15s --export results.json

# Run Rust Criterion benchmark suite directly
cargo bench --workspace
```
