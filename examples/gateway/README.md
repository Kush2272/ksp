# 🌐 HTTP / WebSocket to KSP Gateway Bridge (`examples/gateway/`)

This example demonstrates bridging traditional web traffic (HTTP requests and WebSockets from browser clients) into binary KSP frames.

## How it Works
1. **Web Bridge Protocol**: Browser clients connect via standard WebSocket over TLS (`wss://`).
2. **Binary Framing Translation**: The gateway wraps incoming JSON payload data into binary KSP packet structures.
3. **Internal Mesh Routing**: Packets are routed over persistent X25519-authenticated internal KSP channels.

## Quick CLI Testing
```bash
# Start bridge gateway listening for WebSocket connections on port 3001
ksp gateway --ws-bind 127.0.0.1:3001 --ksp-target 127.0.0.1:9876
```
