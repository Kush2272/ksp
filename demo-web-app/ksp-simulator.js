/**
 * KSP Simulator Module (ksp-simulator.js)
 * Manages protocol state machines, sessions, multiplexed streams, flow control windows, and simulated network nodes.
 */

const ConnectionState = {
    DISCONNECTED: 'DISCONNECTED',
    HELLO: 'HELLO',
    CERTIFICATE: 'CERTIFICATE',
    AUTHENTICATED: 'AUTHENTICATED',
    ESTABLISHED: 'ESTABLISHED',
    CLOSED: 'CLOSED'
};

const PacketType = {
    ClientHello: 0x01,
    ServerHello: 0x02,
    Certificate: 0x04,
    AuthRequest: 0x05,
    AuthResponse: 0x06,
    HandshakeFinish: 0x07,
    Data: 0x10,
    DataAck: 0x11,
    StreamOpen: 0x20,
    StreamData: 0x21,
    StreamClose: 0x22,
    StreamReset: 0x23,
    KeepAlive: 0x30,
    KeepAliveAck: 0x31,
    WindowUpdate: 0x32,
    GoAway: 0x33,
    SessionResume: 0x40,
    SessionTicket: 0x41,
    Error: 0xFF
};

const PacketTypeName = Object.fromEntries(
    Object.entries(PacketType).map(([name, val]) => [val, name])
);

const Flags = {
    COMPRESSED: 0b0000_0000_0000_0001,
    ENCRYPTED:  0b0000_0000_0000_0010,
    FRAGMENTED: 0b0000_0000_0000_0100,
    END_STREAM: 0b0000_0000_0000_1000,
    ACK:        0b0000_0000_0001_0000,
    PRIORITY:   0b0000_0000_0010_0000,
    PADDED:     0b0000_0000_0100_0000
};

const ErrorCode = {
    NoError: 0x00,
    ProtocolError: 0x01,
    InternalError: 0x02,
    FlowControlError: 0x03,
    StreamClosed: 0x04,
    FrameSizeError: 0x05,
    AuthFailed: 0x06,
    HandshakeTimeout: 0x07,
    VersionMismatch: 0x08,
    ReplayDetected: 0x09,
    CertExpired: 0x0A,
    CertInvalid: 0x0B,
    CapabilityMismatch: 0x0C,
    StreamLimit: 0x0D,
    SessionExpired: 0x0E
};

const ErrorCodeName = Object.fromEntries(
    Object.entries(ErrorCode).map(([name, val]) => [val, name])
);

class KspStream {
    constructor(id, priority = 0) {
        this.id = id;
        this.state = 'IDLE'; // IDLE, OPEN, HALF_CLOSED_LOCAL, HALF_CLOSED_REMOTE, CLOSED
        this.sendWindow = 65535;
        this.recvWindow = 65535;
        this.priority = priority;
    }

    open() {
        this.state = 'OPEN';
    }

    closeLocal() {
        if (this.state === 'OPEN') {
            this.state = 'HALF_CLOSED_LOCAL';
        } else if (this.state === 'HALF_CLOSED_REMOTE') {
            this.state = 'CLOSED';
        }
    }

    closeRemote() {
        if (this.state === 'OPEN') {
            this.state = 'HALF_CLOSED_REMOTE';
        } else if (this.state === 'HALF_CLOSED_LOCAL') {
            this.state = 'CLOSED';
        }
    }

    reset() {
        this.state = 'CLOSED';
    }
}

class KspSessionState {
    constructor(sessionId) {
        this.id = sessionId;
        this.state = ConnectionState.DISCONNECTED;
        this.cipherSuite = 'KSP_X25519_AES256GCM_SHA256';
        this.capabilities = ['AES_256_GCM', 'MULTIPLEXING', 'STREAMING'];
        this.packetsCount = 0;
        this.bytesCount = 0;
        
        // Replay window state (1024-packet bitmap model)
        this.replayHighestSeq = 0n;
        this.replayWindow = new Set(); 

        this.keepaliveInterval = 30; // seconds
        this.streams = new Map();
        
        this.handshakeStart = 0;
        this.handshakeDuration = 0; // ms
    }

    updateReplayWindow(seq) {
        if (seq <= 0n) return false;
        
        // Sequence too old check (below sliding window lower boundary)
        if (seq <= this.replayHighestSeq - 1024n) {
            return false;
        }

        if (this.replayWindow.has(seq.toString())) {
            return false; // Duplicate sequence (Replay detected!)
        }

        this.replayWindow.add(seq.toString());

        if (seq > this.replayHighestSeq) {
            this.replayHighestSeq = seq;
            // Clean up window entries that fell out of range (sliding window eviction)
            const minAllowed = this.replayHighestSeq - 1024n;
            for (const existing of this.replayWindow) {
                if (BigInt(existing) <= minAllowed) {
                    this.replayWindow.delete(existing);
                }
            }
        }
        return true;
    }

    createStream(id, priority = 0) {
        if (this.streams.size >= 256) {
            throw new Error("Stream limit exceeded");
        }
        const stream = new KspStream(id, priority);
        this.streams.set(id, stream);
        return stream;
    }
}
