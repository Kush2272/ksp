# 📦 High-Speed Resumable File Transfer (`examples/transfer/`)

This example illustrates how to stream large binary files securely using KSP's multiplexed stream architecture.

## Key Features
- **Chunked Framing**: Files are broken down into 64 KB encrypted payload chunks sent across Stream `10`.
- **Integrity Verification**: The sender calculates an end-to-end SHA256 digest transmitted in the metadata header (Stream `9`).
- **Resumability**: If a network interruption occurs, the receiver reports the last successfully verified offset, and the transfer resumes without retransmitting early chunks.

## Quick CLI Testing
```bash
# Terminal 1: Start receiving on port 9876
ksp transfer receive --bind 127.0.0.1:9876 --out ./received_archive.zip

# Terminal 2: Send a file
ksp transfer send --peer 127.0.0.1:9876 --file ./large_dataset.tar.gz
```
