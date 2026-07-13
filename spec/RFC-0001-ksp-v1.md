# RFC-0001: Kush Secure Protocol (KSP) Version 1.0

```
Status:     Draft
Author:     Kush
Created:    2026-07-08
Version:    1.0
```

---

## 1. Abstract

The Kush Secure Protocol (KSP) is a custom, binary-encoded, application-layer protocol designed for secure, low-latency, multiplexed communication over TCP. KSP provides authenticated encryption, forward secrecy, stream multiplexing, replay protection, and session resumption.

KSP is NOT a replacement for TLS/HTTPS. It is a purpose-built protocol optimized for scenarios requiring tight control over framing, encryption, and multiplexing — with clearly documented design decisions and measured performance characteristics.

### 1.1 Design Goals

1. **Security First** — Authenticated encryption (AEAD), forward secrecy via ephemeral key exchange, replay protection, and certificate-based authentication.
2. **Binary Efficiency** — Compact binary wire format with zero text parsing overhead.
3. **Multiplexed Streams** — Multiple logical streams over a single TCP connection (inspired by HTTP/2).
4. **Negotiation** — Version and capability negotiation to ensure forward compatibility.
5. **Simplicity** — A minimal, understandable protocol that avoids the complexity of TLS while implementing its core security properties.
6. **Observability** — Designed for inspection via custom Wireshark dissector and CLI tooling.

### 1.2 Non-Goals

- Replacing TLS, HTTPS, or any production security protocol.
- Browser-native support (KSP operates via a bridge extension).
- Backward compatibility with any existing protocol.

---

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

| Term | Definition |
|:---|:---|
| **Endpoint** | A participant in a KSP connection (client or server). |
| **Session** | A stateful, encrypted connection between two endpoints, identified by a Session ID. |
| **Stream** | A bidirectional logical channel within a session, identified by a Stream ID. |
| **Frame** | A single KSP packet on the wire, consisting of a header, optional encrypted payload, and authentication tag. |
| **Handshake** | The initial exchange of messages to establish a session, negotiate parameters, and derive encryption keys. |
| **Cipher Suite** | The combination of key exchange, AEAD algorithm, and hash function used for a session. |
| **AEAD** | Authenticated Encryption with Associated Data. |
| **AAD** | Additional Authenticated Data — the packet header, authenticated but not encrypted. |
| **Forward Secrecy** | The property that compromise of long-term keys does not compromise past session keys. |

---

## 3. Architecture Overview

### 3.1 Protocol Stack

```
┌─────────────────────────────────┐
│       Application Layer         │  ← User data, RPC calls, file transfers
├─────────────────────────────────┤
│     KSP Stream Layer            │  ← Multiplexing, flow control, priority
├─────────────────────────────────┤
│     KSP Session Layer           │  ← Session mgmt, replay protection, keepalive
├─────────────────────────────────┤
│     KSP Encryption Layer        │  ← AEAD encrypt/decrypt, key management
├─────────────────────────────────┤
│     KSP Handshake Layer         │  ← Key exchange, auth, negotiation
├─────────────────────────────────┤
│     KSP Framing Layer           │  ← Binary packet serialization/deserialization
├─────────────────────────────────┤
│     TCP                         │  ← Reliable, ordered byte stream
├─────────────────────────────────┤
│     IP                          │  ← Network routing
└─────────────────────────────────┘
```

### 3.2 Layer Responsibilities

| Layer | Responsibility |
|:---|:---|
| **Framing** | Serialize/deserialize binary packets. Length-prefixed framing over TCP. |
| **Handshake** | Version negotiation, capability negotiation, key exchange, authentication. |
| **Encryption** | AEAD encryption/decryption of payloads. Nonce management. AAD construction. |
| **Session** | Session state, replay window, keepalive, session resumption. |
| **Stream** | Stream lifecycle, flow control, priority, multiplexing. |

### 3.3 Connection Lifecycle

```
TCP Connect → Handshake → [Authenticated Encrypted Session] → Graceful Close
                 │
                 ├── Version Negotiation
                 ├── Capability Negotiation
                 ├── Key Exchange (X25519)
                 ├── Certificate Verification
                 ├── Authentication
                 └── Handshake Verification
```

---

## 4. Packet Format

### 4.1 Wire Format

All multi-byte integers are encoded in **big-endian** (network byte order). All KSP frames share a common header format.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Version     |     Type      |            Flags              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload Length                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                        Session ID                             |
|                        (16 bytes)                             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Stream ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      Sequence Number                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                          Nonce                                |
|                        (12 bytes)                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Encrypted Payload                         |
|                       (variable)                              |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Authentication Tag                         |
|                        (16 bytes)                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.2 Header Fields

| Field | Offset | Size | Description |
|:---|:---|:---|:---|
| Version | 0 | 1 byte | Protocol version. High nibble = major, low nibble = minor. `0x10` = v1.0 |
| Type | 1 | 1 byte | Packet type code (see Section 4.3) |
| Flags | 2 | 2 bytes | Bitfield flags (see Section 4.4) |
| Payload Length | 4 | 4 bytes | Length of the Encrypted Payload in bytes (max 16,777,216 = 16 MB) |
| Session ID | 8 | 16 bytes | UUID v4 identifying the session. All zeros during initial ClientHello. |
| Stream ID | 24 | 4 bytes | Stream identifier. 0 = connection-level control frame. |
| Sequence Number | 28 | 8 bytes | Monotonically increasing per-session counter. |
| Nonce | 36 | 12 bytes | AEAD nonce used to encrypt this packet's payload. |

**Total header size: 48 bytes**

Following the header:
- **Encrypted Payload**: Variable length, as specified by Payload Length.
- **Authentication Tag**: 16 bytes. AEAD authentication tag covering both the header (as AAD) and the payload.

### 4.3 Packet Types

| Code | Name | Direction | Description |
|:---|:---|:---|:---|
| `0x01` | ClientHello | C→S | Initiate handshake with version/capability proposal |
| `0x02` | ServerHello | S→C | Server's selected version/capabilities + ephemeral key |
| `0x03` | KeyExchange | C→S | Client's key exchange contribution |
| `0x04` | Certificate | S→C | Server's KSP certificate |
| `0x05` | AuthRequest | C→S | Client authentication credentials (encrypted) |
| `0x06` | AuthResponse | S→C | Authentication result (encrypted) |
| `0x07` | HandshakeFinish | Both | Handshake verification (encrypted) |
| `0x10` | Data | Both | Application data (encrypted) |
| `0x11` | DataAck | Both | Acknowledgement of received data |
| `0x20` | StreamOpen | Both | Open a new stream |
| `0x21` | StreamData | Both | Data on a specific stream |
| `0x22` | StreamClose | Both | Gracefully close a stream |
| `0x23` | StreamReset | Both | Abruptly terminate a stream |
| `0x30` | KeepAlive | Both | Connection liveness probe |
| `0x31` | KeepAliveAck | Both | Response to KeepAlive |
| `0x32` | WindowUpdate | Both | Flow control window increase |
| `0x33` | GoAway | Both | Graceful connection shutdown |
| `0x40` | SessionResume | C→S | Request to resume a previous session |
| `0x41` | SessionTicket | S→C | Encrypted session ticket for future resumption |
| `0xFF` | Error | Both | Error notification |

### 4.4 Flags

| Bit | Name | Description |
|:---|:---|:---|
| 0 | `COMPRESSED` | Payload was compressed before encryption |
| 1 | `ENCRYPTED` | Payload is encrypted (MUST be set after handshake) |
| 2 | `FRAGMENTED` | This frame is part of a fragmented message |
| 3 | `END_STREAM` | Last frame for this stream (half-close) |
| 4 | `ACK` | This frame is an acknowledgement |
| 5 | `PRIORITY` | Frame contains priority information |
| 6 | `PADDED` | Payload includes padding bytes |
| 7–15 | Reserved | MUST be zero. Receivers MUST ignore unknown flags. |

### 4.5 Constraints

- Payload Length MUST NOT exceed 16,777,216 bytes (16 MB).
- Receivers MUST reject frames with unknown Version values by sending an Error frame with code `VERSION_MISMATCH`.
- Receivers MUST reject frames with Payload Length exceeding the maximum by sending an Error frame with code `FRAME_SIZE_ERROR`.
- The Authentication Tag MUST be validated before processing the payload. If validation fails, the receiver MUST discard the frame silently (no error response — prevents oracle attacks).

---

## 5. Version Negotiation

### 5.1 Overview

KSP supports version negotiation to allow protocol evolution without breaking existing deployments.

### 5.2 Client Proposal

The ClientHello payload includes a list of supported protocol versions, ordered by client preference (most preferred first):

```
ClientHello.supported_versions = [
    ProtocolVersion { major: 2, minor: 0 },
    ProtocolVersion { major: 1, minor: 1 },
    ProtocolVersion { major: 1, minor: 0 },
]
```

### 5.3 Server Selection

The server MUST select the highest version that appears in both the client's list and the server's supported versions. If no common version exists, the server MUST respond with an Error frame containing code `VERSION_MISMATCH` and close the connection.

### 5.4 Version Encoding

The Version field in the packet header encodes the negotiated version: `(major << 4) | minor`. Thus `0x10` = v1.0, `0x11` = v1.1, `0x20` = v2.0.

### 5.5 Version Compatibility Rules

- Minor version increments (e.g., 1.0 → 1.1) MUST be backward compatible. A v1.1 server MUST be able to serve v1.0 clients.
- Major version increments (e.g., 1.x → 2.0) MAY introduce breaking changes to the wire format.

---

## 6. Capability Negotiation

### 6.1 Overview

Capabilities allow endpoints to advertise and negotiate optional features without changing the protocol version.

### 6.2 Capability Encoding

Capabilities are encoded as a 32-bit bitfield:

| Bit | Capability | Description |
|:---|:---|:---|
| 0 | `AES_256_GCM` | Supports AES-256-GCM cipher suite |
| 1 | `CHACHA20_POLY1305` | Supports ChaCha20-Poly1305 cipher suite |
| 2 | `COMPRESSION_ZSTD` | Supports zstd payload compression |
| 3 | `MULTIPLEXING` | Supports stream multiplexing |
| 4 | `POST_QUANTUM` | Supports hybrid post-quantum key exchange |
| 5 | `STREAMING` | Supports bidirectional streaming |
| 6 | `SESSION_RESUMPTION` | Supports session ticket-based resumption |
| 7 | `MUTUAL_AUTH` | Supports mutual (client) authentication |
| 8 | `FILE_TRANSFER` | Supports optimized file transfer mode |
| 9–31 | Reserved | MUST be zero |

### 6.3 Negotiation Algorithm

1. Client sends its capability bitfield in ClientHello.
2. Server computes the intersection: `negotiated = client_caps & server_caps`.
3. For cipher suite selection (bits 0–1), the server MUST select exactly one. Server preference order: AES-256-GCM (if both support it and hardware AES is available), otherwise ChaCha20-Poly1305.
4. At least one cipher suite MUST be mutually supported, or the server MUST reject the connection.
5. Server sends the negotiated capabilities in ServerHello.

### 6.4 Required Capabilities

All implementations MUST support at least one of `AES_256_GCM` or `CHACHA20_POLY1305`. All other capabilities are OPTIONAL.

---

## 7. Handshake Protocol

### 7.1 Overview

The KSP handshake establishes a session by:
1. Negotiating protocol version and capabilities
2. Performing ephemeral key exchange (X25519)
3. Verifying the server's identity (certificate)
4. Optionally authenticating the client
5. Deriving session encryption keys
6. Verifying that both sides derived identical keys

### 7.2 Message Sequence

```
Client                                            Server
  │                                                  │
  │──── [1] ClientHello ───────────────────────────→│
  │     Version=0x10, SessionID=zeros                │
  │     Payload (plaintext):                         │
  │       supported_versions: [1.0]                  │
  │       capabilities: 0x0000007F                   │
  │       client_random: [32 bytes]                  │
  │       ephemeral_public_key: [32 bytes]           │
  │                                                  │
  │←─── [2] ServerHello ────────────────────────────│
  │     Payload (plaintext):                         │
  │       selected_version: 1.0                      │
  │       selected_capabilities: 0x00000023          │
  │       server_random: [32 bytes]                  │
  │       ephemeral_public_key: [32 bytes]           │
  │       session_id: [16 bytes]                     │
  │                                                  │
  │←─── [3] Certificate ───────────────────────────│
  │     Payload (plaintext):                         │
  │       server_certificate: KspCertificate         │
  │       binding_signature: [64 bytes] (Ed25519)    │
  │                                                  │
  │     [Client verifies certificate signature]      │
  │     [Client verifies certificate expiration]     │
  │     [Client verifies binding_signature over      │
  │      client_random || server_random ||           │
  │      client_pubkey || server_pubkey]             │
  │     [Both compute: shared_secret = X25519(       │
  │       my_ephemeral_secret, their_ephemeral_pub)] │
  │     [Both derive session keys via HKDF]          │
  │                                                  │
  │  ═══════ ALL FURTHER MESSAGES ENCRYPTED ═══════  │
  │                                                  │
  │──── [4] AuthRequest (encrypted) ───────────────→│
  │     auth_method: Token                           │
  │     credentials: [encrypted token bytes]         │
  │                                                  │
  │←─── [5] AuthResponse (encrypted) ──────────────│
  │     status: Success                              │
  │                                                  │
  │──── [6] HandshakeFinish (encrypted) ───────────→│
  │     verify_data: HMAC-SHA256(                    │
  │       session_key,                               │
  │       hash(all_handshake_messages))              │
  │                                                  │
  │←─── [7] HandshakeFinish (encrypted) ───────────│
  │     verify_data: HMAC-SHA256(                    │
  │       session_key,                               │
  │       hash(all_handshake_messages))              │
  │                                                  │
  │  ══════ SESSION ESTABLISHED ═══════════════════  │
```

### 7.3 Handshake State Machine

```
              ┌──────────┐
              │   INIT   │
              └────┬─────┘
                   │ send/recv ClientHello
              ┌────▼─────┐
              │  HELLO    │
              └────┬─────┘
                   │ send/recv ServerHello
              ┌────▼─────┐
              │ KEY_EXCH  │
              └────┬─────┘
                   │ recv Certificate, compute shared secret
              ┌────▼─────┐
              │ CERT_VRFY │
              └────┬─────┘
                   │ send/recv AuthRequest/AuthResponse
              ┌────▼─────┐
              │   AUTH    │
              └────┬─────┘
                   │ send/recv HandshakeFinish
              ┌────▼─────┐
              │ FINISHED  │
              └────┬─────┘
                   │ verify_data matches
              ┌────▼─────┐
              │ESTABLISHED│
              └──────────┘

    Any state ──── error ────→ FAILED
    Any state ──── timeout ──→ FAILED
```

### 7.4 Timeout

- The complete handshake MUST complete within 10 seconds (configurable).
- If the handshake does not complete within the timeout, both sides MUST close the TCP connection.

### 7.5 Downgrade Prevention

The HandshakeFinish `verify_data` is computed over the entire handshake transcript. This ensures that any modification of ClientHello or ServerHello (e.g., by a MITM downgrading the cipher suite) will be detected.

---

## 8. Encryption

### 8.1 Cipher Suites

KSP v1.0 supports two cipher suites:

| ID | Name | Key Exchange | AEAD | Hash |
|:---|:---|:---|:---|:---|
| `0x01` | `KSP_X25519_AES256GCM_SHA256` | X25519 | AES-256-GCM | SHA-256 |
| `0x02` | `KSP_X25519_CHACHA20POLY1305_SHA256` | X25519 | ChaCha20-Poly1305 | SHA-256 |

### 8.2 Key Exchange

KSP uses X25519 Elliptic Curve Diffie-Hellman for key exchange.

1. Both client and server generate **ephemeral** X25519 keypairs.
2. Public keys are exchanged during ClientHello and ServerHello.
3. Shared secret: `shared_secret = X25519(my_ephemeral_private, their_ephemeral_public)`
4. Ephemeral private keys MUST be securely erased after computing the shared secret.
5. A new ephemeral keypair MUST be generated for each session (**forward secrecy**).

### 8.3 Key Derivation

Session keys are derived from the shared secret using HKDF-SHA256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)):

```
salt = client_random || server_random  (64 bytes)
PRK = HKDF-Extract(salt, shared_secret)

client_write_key = HKDF-Expand(PRK, "ksp1 client write key", 32)
server_write_key = HKDF-Expand(PRK, "ksp1 server write key", 32)
client_write_iv  = HKDF-Expand(PRK, "ksp1 client write iv",  12)
server_write_iv  = HKDF-Expand(PRK, "ksp1 server write iv",  12)
```

- `client_write_key` is used by the client to encrypt and by the server to decrypt.
- `server_write_key` is used by the server to encrypt and by the client to decrypt.
- IVs are used for nonce construction (see Section 8.4).

### 8.4 Nonce Construction

The 12-byte AEAD nonce is constructed by XORing the per-direction IV with the sequence number:

```
nonce = write_iv XOR (sequence_number padded to 12 bytes, left-padded with zeros)
```

This mirrors the TLS 1.3 nonce construction ([RFC 8446 §5.3](https://www.rfc-editor.org/rfc/rfc8446#section-5.3)).

- The nonce is included in the packet header for the receiver's convenience but MUST also be independently verified by the receiver using its own sequence counter.
- If the received nonce does not match the expected nonce (from `write_iv XOR expected_seq`), the frame MUST be discarded.

### 8.5 AEAD Construction

```
ciphertext, tag = AEAD-Encrypt(
    key   = write_key,
    nonce = constructed_nonce,
    aad   = packet_header_bytes[0..48],   // Entire 48-byte header
    plaintext = payload
)
```

The AAD includes the entire packet header. This authenticates all header fields (version, type, flags, session ID, stream ID, sequence number, nonce) without encrypting them, preventing header tampering.

### 8.6 Decryption Failure

If AEAD decryption fails (tag mismatch), the receiver:
1. MUST discard the frame silently.
2. MUST NOT send any error response (prevents oracle attacks).
3. SHOULD increment an internal failure counter.
4. MAY close the connection if the failure counter exceeds a threshold (default: 10).

---

## 9. Certificate System

### 9.1 Certificate Format

KSP certificates are binary-encoded:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Cert Version (1 byte)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Subject Length (2 bytes)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Subject (variable, UTF-8)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Public Key (32 bytes, Ed25519)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Issuer Length (2 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Issuer (variable, UTF-8)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Not Before (8 bytes, Unix timestamp seconds)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Not After (8 bytes, Unix timestamp seconds)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Serial Number (16 bytes, UUID)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Signature (64 bytes, Ed25519)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 9.2 Signature

The signature covers all certificate fields except the signature itself, serialized in the order above. Signed using Ed25519.

- **Self-signed certificates**: The signing key corresponds to the Public Key in the certificate.
- **CA-signed certificates**: The signing key belongs to the issuer. Trust is established by possessing the issuer's public key.

### 9.3 Validation

Receivers MUST perform the following checks:
1. Verify the Ed25519 signature against the issuer's public key.
2. Check that the current time is between `not_before` and `not_after`.
3. Check that the subject matches the expected server identity.
4. If using a trust store, verify the issuer chain.

### 9.4 Certificate Pinning

Clients MAY implement certificate pinning by storing the expected server public key and rejecting connections whose certificate does not match.

### 9.5 Key Exchange Binding

To prevent Man-in-the-Middle (MITM) attacks where a malicious third-party intercepts the ephemeral key exchange and forwards the server's certificate, KSP requires binding the server's identity cryptographically to the handshake key exchange.

1. The server MUST compute an Ed25519 signature over the following concatenated data using the private key corresponding to its certificate's public key:
   `client_random || server_random || client_ephemeral_public_key || server_ephemeral_public_key` (total 128 bytes of data)
2. This 64-byte signature is appended to the serialized certificate in the `Certificate` handshake packet payload.
3. The client MUST verify this signature using the server's public key from the certificate. If verification fails, the client MUST immediately abort the handshake.

---

## 10. Authentication

### 10.1 Supported Methods

| Method | Code | Description |
|:---|:---|:---|
| None | `0x00` | No authentication required |
| Password | `0x01` | Username + Argon2id password hash |
| API Key | `0x02` | Pre-shared API key |
| Token | `0x03` | Bearer token (e.g., JWT) |
| Mutual | `0x04` | Client presents its own KSP certificate |

### 10.2 Auth Flow

Authentication occurs **after** the encrypted channel is established (post-key-exchange). This ensures credentials are never sent in plaintext.

1. Server indicates required auth method(s) in ServerHello capabilities.
2. Client sends AuthRequest with chosen method and encrypted credentials.
3. Server validates and responds with AuthResponse (Success or Failure).
4. On failure, the server MAY allow retry (configurable max attempts, default: 3).
5. After max retries, the server MUST close the connection.

### 10.3 Credential Protection

- Password authentication uses Argon2id hashing. The server stores only the hash.
- API keys are compared in constant time to prevent timing attacks.
- Tokens are validated against the server's token verification logic.
- All credentials are encrypted under the session keys before transmission.

### 10.4 Mutual Authentication

When `MUTUAL_AUTH` is negotiated:
1. After ServerHello, the server sends a CertificateRequest.
2. The client responds with its own Certificate frame.
3. The server verifies the client certificate.

---

## 11. Streaming and Multiplexing

### 11.1 Overview

KSP supports multiple concurrent bidirectional streams over a single session, inspired by HTTP/2's stream model.

### 11.2 Stream Identifiers

- Stream ID 0: Reserved for connection-level control frames (KeepAlive, GoAway, WindowUpdate on connection level).
- **Odd** Stream IDs (1, 3, 5, ...): Client-initiated streams.
- **Even** Stream IDs (2, 4, 6, ...): Server-initiated streams.
- Maximum concurrent streams per session: 256 (configurable).

### 11.3 Stream Lifecycle

```
                     ┌──────┐
           send/recv │      │ recv/send
          StreamOpen │ IDLE │ StreamOpen
                     │      │
                     └──┬───┘
                        │
                     ┌──▼───┐
          send/recv  │      │
          StreamData │ OPEN │
                     │      │
                     └──┬───┘
                   ┌────┴────┐
            send   │         │ recv
         END_STREAM│         │END_STREAM
              ┌────▼───┐ ┌───▼────┐
              │HALF    │ │HALF    │
              │CLOSED  │ │CLOSED  │
              │(local) │ │(remote)│
              └────┬───┘ └───┬────┘
                   │  recv   │ send
                   │END_STREAM END_STREAM
                   │         │
                   └────┬────┘
                     ┌──▼───┐
                     │CLOSED│
                     └──────┘

    Any state ── StreamReset ──→ CLOSED
```

### 11.4 Stream Data

- Application data is sent as StreamData frames with the appropriate Stream ID.
- Large messages MAY be fragmented across multiple frames using the `FRAGMENTED` flag.
- The final fragment MUST have the `FRAGMENTED` flag cleared (or `END_STREAM` set).

---

## 12. Flow Control

### 12.1 Overview

KSP implements window-based flow control at both the connection level and per-stream level. This prevents a fast sender from overwhelming a slow receiver.

### 12.2 Windows

- **Initial window size**: 65,535 bytes (configurable during handshake).
- Each byte of payload data consumed reduces the sender's window.
- Receivers send WindowUpdate frames to increase the sender's window.

### 12.3 WindowUpdate Frame

Payload of a WindowUpdate frame:
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Window Size Increment (4 bytes)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Stream ID = 0: Connection-level window update.
- Stream ID > 0: Stream-level window update.
- Window Size Increment MUST be > 0 and MUST NOT overflow the maximum window size (2^31 - 1).

### 12.4 Backpressure

When a sender's window reaches zero, it MUST NOT send further data frames until a WindowUpdate is received. Control frames (KeepAlive, WindowUpdate, GoAway) are exempt from flow control.

---

## 13. Session Management

### 13.1 Session State

A session maintains:
- Session ID (16 bytes, UUID v4)
- Negotiated version and capabilities
- Client and server write keys + IVs
- Sequence number counters (one per direction)
- Replay window state
- Active streams table
- Flow control windows
- Keepalive timer state

### 13.2 Session Timeout

- Sessions timeout after 1 hour (3600 seconds) of inactivity (configurable).
- Inactivity = no frames sent or received.
- Keepalive frames reset the inactivity timer.

### 13.3 Keepalive

- Keepalive frames are sent every 30 seconds (configurable).
- If no KeepAliveAck is received within 10 seconds, the connection is considered dead.
- Keepalive frames use Stream ID 0 and have an empty payload.

### 13.4 Session Resumption

1. At session establishment, the server MAY send a SessionTicket containing encrypted session state.
2. The ticket is encrypted with a server-side ticket key (rotated periodically).
3. On reconnection, the client sends a SessionResume frame containing the ticket.
4. If valid, the server restores the session keys without a full handshake.
5. Resumed sessions still perform a fresh key exchange for forward secrecy, but skip authentication.

### 13.5 Graceful Shutdown

1. The initiator sends a GoAway frame.
2. GoAway payload includes the last processed Stream ID.
3. Both sides stop creating new streams.
4. Existing streams are allowed to complete.
5. Once all streams are closed, the TCP connection is closed.

---

## 14. Replay Protection

### 14.1 Overview

KSP uses a sliding-window algorithm to detect and reject replayed packets. Each direction has an independent replay window.

### 14.2 Algorithm

- Maintain: `highest_seq` (the highest accepted sequence number) and a bitmap of 1024 bits representing sequence numbers `[highest_seq - 1023, highest_seq]`.
- On receiving a frame with sequence number `seq`:
  1. If `seq > highest_seq`: Accept. Advance the window and set the bit.
  2. If `seq <= highest_seq - 1024`: Reject. Too old.
  3. If `seq` is within the window: Check the bit. If set, reject (replay). If clear, accept and set the bit.

### 14.3 Sequence Number Overflow

Sequence numbers are 64-bit unsigned integers. At 1 billion packets per second, overflow would take ~584 years. No special handling is required. If an implementation detects imminent overflow, it SHOULD renegotiate the session.

---

## 15. Error Handling

### 15.1 Error Codes

| Code | Name | Level | Description |
|:---|:---|:---|:---|
| `0x00` | `NO_ERROR` | — | Graceful close, no error |
| `0x01` | `PROTOCOL_ERROR` | Connection | Generic protocol violation |
| `0x02` | `INTERNAL_ERROR` | Connection | Implementation fault |
| `0x03` | `FLOW_CONTROL_ERROR` | Connection/Stream | Flow control limit exceeded |
| `0x04` | `STREAM_CLOSED` | Stream | Frame received for closed stream |
| `0x05` | `FRAME_SIZE_ERROR` | Connection | Frame exceeds maximum size |
| `0x06` | `AUTH_FAILED` | Connection | Authentication rejected |
| `0x07` | `HANDSHAKE_TIMEOUT` | Connection | Handshake exceeded time limit |
| `0x08` | `VERSION_MISMATCH` | Connection | No common protocol version |
| `0x09` | `REPLAY_DETECTED` | Connection | Replayed packet detected |
| `0x0A` | `CERT_EXPIRED` | Connection | Server certificate has expired |
| `0x0B` | `CERT_INVALID` | Connection | Certificate signature invalid |
| `0x0C` | `CAPABILITY_MISMATCH` | Connection | No common cipher suite |
| `0x0D` | `STREAM_LIMIT` | Stream | Maximum streams exceeded |
| `0x0E` | `SESSION_EXPIRED` | Connection | Session has timed out |

### 15.2 Error Frame Payload

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Error Code (4 bytes)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Additional Data Length (2 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Additional Data (variable, UTF-8, optional)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 15.3 Error Behavior

- **Connection-level errors**: Sender MUST send GoAway after the Error frame and close the connection.
- **Stream-level errors**: Only the affected stream is reset. Other streams continue.
- **Encryption errors**: MUST NOT generate error responses (see Section 8.6).

---

## 16. Security Considerations

### 16.1 Threat Model

KSP is designed to protect against:
- **Eavesdropping**: All post-handshake traffic is encrypted with AEAD.
- **Tampering**: AEAD authentication tag covers both header and payload.
- **Replay attacks**: Sliding window replay protection on sequence numbers.
- **MITM attacks**: Certificate-based server authentication; optional mutual auth.
- **Downgrade attacks**: Handshake transcript verification in HandshakeFinish.
- **Nonce reuse**: Counter-based nonce construction with overflow detection.

### 16.2 Known Limitations

- KSP does NOT provide protection against traffic analysis (packet sizes and timing are observable).
- Self-signed certificates require out-of-band key distribution or pinning.
- The certificate system is simplified compared to X.509; it does not support certificate revocation lists (CRLs) or OCSP.

### 16.3 Implementation Requirements

- Implementations MUST use constant-time comparison for all secret data.
- Implementations MUST securely erase (zeroize) ephemeral private keys after use.
- Implementations MUST use a cryptographically secure random number generator.
- Implementations SHOULD NOT provide detailed decryption error messages to remote peers.

---

## 17. Future Versions

### 17.1 Planned Extensions

| RFC | Feature | Status |
|:---|:---|:---|
| RFC-0002 | Advanced streaming (priority, dependency trees) | Planned |
| RFC-0003 | Post-quantum hybrid key exchange (X25519 + ML-KEM 768) | Planned |
| RFC-0004 | UDP transport and DTLS-like operation | Planned |
| RFC-0005 | 0-RTT session resumption | Planned |
| RFC-0006 | Hardware Security Module (HSM) integration | Planned |

### 17.2 Versioning Policy

- New packet types can be added in minor versions.
- New capability bits can be added in minor versions.
- Changes to the header format require a major version increment.
- Implementations MUST ignore unknown packet types and capability bits (forward compatibility).

---

## Appendix A: Wire Example

### A.1 ClientHello Packet (Hex)

```
10                              # Version: 1.0
01                              # Type: ClientHello
00 00                           # Flags: none
00 00 00 52                     # Payload Length: 82 bytes
00 00 00 00 00 00 00 00         # Session ID: all zeros (new session)
00 00 00 00 00 00 00 00
00 00 00                        # Stream ID: 0
00 00 00 00 00 00 00 01         # Sequence: 1
xx xx xx xx xx xx xx xx         # Nonce: 12 bytes
xx xx xx xx                     #
                                # --- Payload (plaintext) ---
10                              # supported_versions count: 1
10                              # version: 1.0
00 00 00 7F                     # capabilities: 0x7F
xx...(32 bytes)                 # client_random
xx...(32 bytes)                 # ephemeral_public_key
                                # --- No Auth Tag for plaintext handshake ---
```

### A.2 Encrypted Data Packet (Hex)

```
10                              # Version: 1.0
10                              # Type: Data
00 02                           # Flags: ENCRYPTED
00 00 00 20                     # Payload Length: 32 bytes
xx...(16 bytes)                 # Session ID
00 00 00 01                     # Stream ID: 1
00 00 00 00 00 00 00 2A         # Sequence: 42
xx...(12 bytes)                 # Nonce
xx...(32 bytes)                 # Encrypted Payload
xx...(16 bytes)                 # Authentication Tag (AEAD)
```

---

## Appendix B: Constants

| Constant | Value |
|:---|:---|
| Default Port | 9876/tcp |
| Max Payload Size | 16,777,216 bytes (16 MB) |
| Header Size | 48 bytes |
| Auth Tag Size | 16 bytes |
| Handshake Timeout | 10 seconds |
| Keepalive Interval | 30 seconds |
| Keepalive Timeout | 10 seconds |
| Session Timeout | 3600 seconds (1 hour) |
| Max Streams Per Session | 256 |
| Initial Window Size | 65,535 bytes |
| Replay Window Size | 1024 packets |

---

*End of RFC-0001*
