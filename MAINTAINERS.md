# Project Maintainers

This document lists the active maintainers of Kush Secure Protocol (KSP) and describes the project governance structure.

---

## 👥 Active Maintainers

* **Kush (@Kush2272)**
  * Role: Project Founder & Lead Architect
  * Focus: Core engine, protocol specification, handshake design, security reviews
  * Contact: `kush@example.com`

---

## 🏛️ Governance

KSP is currently operated as a BDFL (Benevolent Dictator for Life) model, driven by open community contribution and consensus.

### RFC Design Process
For major changes to the protocol wire format, handshake, or threat model:
1. File an issue outlining the motivation.
2. Submit a draft RFC in `spec/` detailing the design.
3. Establish discussion and consensus with the maintainers and community.
4. Merge the RFC before implementing.

### Contribution Reviews
All code modifications must be reviewed and approved by at least one active maintainer. High-sensitivity components (like `ksp-crypto` and `ksp-handshake`) require a detailed review regarding cryptographic correctness and memory safety checks.
