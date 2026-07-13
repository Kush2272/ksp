# KSP Project Roadmap

This document outlines the strategic milestones and technical roadmap for the **Kush Secure Protocol (KSP)**. The roadmap covers hardening, usability improvements, standardization, and experimental cryptography features.

---

## 📍 Milestones

### Milestone 1: Automated Hardening & CLI Tools (v0.2.0)
*Target: Q3 2026*

* **Automated Fuzz Testing**: Add `cargo-fuzz` targets for parsing boundaries, handshakes, and packet payload deserialization to eliminate panic pathways.
* **Command Line Interface (`ksp-cli`)**: Implement a developer-friendly CLI client/server helper to debug handshakes, print statistics, and dissect local connections.
* **Metrics & Tracing**: Integrate `metrics` crate for Prometheus exports and enhance `tracing` instrumentation across the handshake state machine.

### Milestone 2: Post-Quantum Cryptography & Flow Optimization (v0.5.0)
*Target: Q4 2026*

* **Hybrid PQC Handshake**: Integrate post-quantum key encapsulation mechanism (ML-KEM-768 combined with classical X25519) to future-proof session keys against quantum decryption.
* **Multiplexed Streams**: Full-duplex streams similar to QUIC, isolating stream-level head-of-line blocking while running over a single secure connection.
* **Flow Control**: Implement byte-level stream flow control and connection-wide sliding flow windows.

### Milestone 3: Production Readiness & Audits (v1.0.0)
*Target: Q2 2027*

* **Third-Party Cryptographic Audit**: Engage external specialists to audit `ksp-crypto` and `ksp-handshake` state machine logic.
* **Formal RFC Publication**: Stabilize RFC-0001, publish in a highly readable format with formal protocol verification models (e.g., using ProVerif or Tamarin Prover).
* **Stable APIs & ABI Compatibility**: Guarantee API stability for `ksp-client` and `ksp-server` with backward compatibility guarantees.

---

## 🔮 Future Explorations (Long Term)

* **UDP Transport Option**: Port the KSP state machine to run over UDP as a QUIC alternative, implementing congestion control (BBR/CUBIC) directly in user space.
* **WebAssembly Target**: Compile `ksp-client` to WASM to allow secure, native KSP communication from browsers via WebSockets/WebTransport proxies.
* **Formal Verification**: Formally verify the state machine transitions in the `ksp-handshake` crate.
