# 💬 Encrypted Multi-User Chat (`examples/chat/`)

This example demonstrates how to create a multi-user, real-time encrypted chat server and terminal client using KSP.

## Key Concepts Demonstrated
- **Authenticated Handshakes**: Every joining client executes an X25519 Diffie-Hellman handshake before being allowed into the chat room.
- **Multiplexed Streams**: Stream `1` is reserved for broadcast chat messages, while Stream `2` handles user presence notifications (join/leave).
- **Replay Protection**: Prevents malicious actors from capturing and replaying previous chat packets.

## Quick CLI Testing
```bash
# Terminal 1: Launch the KSP server
ksp daemon start --bind 127.0.0.1:9876

# Terminal 2: Join as Alice
ksp chat --peer 127.0.0.1:9876 --nick Alice

# Terminal 3: Join as Bob
ksp chat --peer 127.0.0.1:9876 --nick Bob
```
