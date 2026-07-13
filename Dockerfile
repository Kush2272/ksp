# Stage 1: Build the Rust binaries
FROM rust:1.80-slim AS builder

WORKDIR /usr/src/ksp
COPY . .

# Install build dependencies (C/C++ linker and dependencies)
RUN apt-get update && apt-get install -y pkg-config libssl-dev build-essential && rm -rf /var/lib/apt/lists/*

# Build in release mode
RUN cargo build --release --workspace

# Stage 2: Runner
FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /usr/src/ksp/target/release/ksp-server /app/ksp-server
COPY --from=builder /usr/src/ksp/target/release/ksp-client /app/ksp-client

EXPOSE 9876

CMD ["./ksp-server"]
