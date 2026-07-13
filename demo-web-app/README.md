# KSP Interactive Protocol Explorer

The KSP (Kush Secure Protocol) Interactive Explorer is an educational protocol visualizer, packet builder, and testing console written in Vanilla ES6 JavaScript, HTML5, and CSS3. It is designed to run entirely client-side in sandboxed browser spaces without any external frameworks or compilation tasks.

---

## 🏗️ Architecture & Core Modules

The application is structured using standard ES modules to decouple concerns, matching KSP's actual architectural layout:

* **[index.html](file:///c:/Users/kush/Desktop/HTTPS/ksp/demo-web-app/index.html)**: Declares the dashboard grids, timeline structures, chat consoles, and SVG benchmark dashboard.
* **[style.css](file:///c:/Users/kush/Desktop/HTTPS/ksp/demo-web-app/style.css)**: Implements glassmorphic styling, neon glows, responsive cards, and keyframe transitions.
* **[app.js](file:///c:/Users/kush/Desktop/HTTPS/ksp/demo-web-app/app.js)**: Coordinative entry point. Directs sub-modules, handles tab panels, links visual triggers, and interprets CLI developer console inputs.
* **[ksp-simulator.js](file:///c:/Users/kush/Desktop/HTTPS/ksp/demo-web-app/ksp-simulator.js)**: Simulates KSP protocol rules, state machines, sequence numbers tracking, sliding window buffers, and multiplexed stream registries.
* **[crypto-simulator.js](file:///c:/Users/kush/Desktop/HTTPS/ksp/demo-web-app/crypto-simulator.js)**: Mock cryptographic functions simulating X25519 public/private keys exchanges, HKDF-SHA256 labels expansion, Ed25519 cert signatures binding, and XOR-based reversible AEAD encryption.
* **[packet-parser.js](file:///c:/Users/kush/Desktop/HTTPS/ksp/demo-web-app/packet-parser.js)**: Big-endian network-order binary serialization structure. Enforces sizing checks (e.g. OOM prevention limit verification).
* **[wireshark.js](file:///c:/Users/kush/Desktop/HTTPS/ksp/demo-web-app/wireshark.js)**: Decodes and pretty-prints packet bytes. Implements interactive links between hex dump offsets and parsed tree fields on hover.
* **[benchmark.js](file:///c:/Users/kush/Desktop/HTTPS/ksp/demo-web-app/benchmark.js)**: Generates and redraws glowing SVG benchmark representations of latency and throughput columns.
* **[animations.js](file:///c:/Users/kush/Desktop/HTTPS/ksp/demo-web-app/animations.js)**: Handles 60fps packet animations, encryption stage step displays, and visual threat vectors triggers.

---

## 🎨 Visual Visualizations and Threat Auditing

### 1. Interactive Handshake Setup
Visualizes version and capability exchange, ephemeral public keys agreement, self-signed certificate binding (MITM check), shared secret derivation, and Finished transcript HMAC calculation.

### 2. Wireshark Hex Inspector (Link Highlighting)
Hovering over any line of the hex dump highlights the parsed field name on the right. Hovering over a parsed tree element (like `Stream ID`) highlights the exact bytes representing that field in the hex dump.

### 3. Attack Simulators
* **MITM**: Attacker injects fake keys $\to$ Server signatures validation fails $\to$ Handshake aborted.
* **Replay Attack**: Attacker replays Sequence #42 $\to$ Server sliding window bitmap check fails $\to$ Packet rejected.
* **Downgrade Attack**: Attacker modifies version header in ClientHello $\to$ Finished MAC transcript check fails $\to$ Session aborted.
* **Memory DoS**: Attacker sends header claim for 4GB payload length $\to$ Immediately rejected before buffer allocation.
