/**
 * Packet Parser Module (packet-parser.js)
 * Implements binary wire formatting, field layouts, packet reconstruction, and validation.
 */

// Byte ranges definitions for Wireshark highlight maps
const FieldByteRanges = {
    version: { start: 0, end: 1, label: "Version (1 Byte)" },
    type: { start: 1, end: 2, label: "Packet Type (1 Byte)" },
    flags: { start: 2, end: 4, label: "Flags (2 Bytes)" },
    payloadLen: { start: 4, end: 8, label: "Payload Length (4 Bytes)" },
    sessionId: { start: 8, end: 24, label: "Session ID (16 Bytes)" },
    streamId: { start: 24, end: 28, label: "Stream ID (4 Bytes)" },
    sequence: { start: 28, end: 36, label: "Sequence Number (8 Bytes)" },
    nonce: { start: 36, end: 48, label: "Nonce (12 Bytes)" },
    payload: { start: 48, end: -1, label: "Encrypted Payload (Variable)" }, // End is dynamic
    tag: { start: -1, end: -1, label: "Authentication Tag (16 Bytes)" } // Position is dynamic
};

class KspPacket {
    constructor(fields) {
        this.version = fields.version ?? 0x10; // Default v1.0
        this.type = fields.type ?? PacketType.Data;
        this.flags = fields.flags ?? 0;
        this.payloadLen = fields.payloadLen ?? 0;
        this.sessionId = fields.sessionId ?? new Uint8Array(16);
        this.streamId = fields.streamId ?? 0;
        this.sequence = BigInt(fields.sequence ?? 0n);
        this.nonce = fields.nonce ?? new Uint8Array(12);
        this.payload = fields.payload ?? new Uint8Array(0);
        this.tag = fields.tag ?? new Uint8Array(16);
    }

    // Convert structured packet into binary Uint8Array (big-endian)
    serialize() {
        // Enforce maximum payload check (Memory DoS prevention)
        const MAX_PAYLOAD_SIZE = 16777216; // 16 MB
        if (this.payloadLen > MAX_PAYLOAD_SIZE) {
            throw new Error(`Frame size error: Payload length ${this.payloadLen} exceeds protocol maximum of 16MB.`);
        }

        const totalSize = 48 + this.payload.length + this.tag.length;
        const out = new Uint8Array(totalSize);

        out[0] = this.version;
        out[1] = this.type;
        
        // Flags (2 bytes, big-endian)
        out[2] = (this.flags >> 8) & 0xFF;
        out[3] = this.flags & 0xFF;

        // Payload Length (4 bytes, big-endian)
        out[4] = (this.payloadLen >> 24) & 0xFF;
        out[5] = (this.payloadLen >> 16) & 0xFF;
        out[6] = (this.payloadLen >> 8) & 0xFF;
        out[7] = this.payloadLen & 0xFF;

        // Session ID (16 bytes)
        out.set(this.sessionId, 8);

        // Stream ID (4 bytes, big-endian)
        out[24] = (this.streamId >> 24) & 0xFF;
        out[25] = (this.streamId >> 16) & 0xFF;
        out[26] = (this.streamId >> 8) & 0xFF;
        out[27] = this.streamId & 0xFF;

        // Sequence Number (8 bytes, big-endian)
        for (let i = 0; i < 8; i++) {
            out[28 + i] = Number((this.sequence >> BigInt((7 - i) * 8)) & 0xFFn);
        }

        // Nonce (12 bytes)
        out.set(this.nonce, 36);

        // Payload
        out.set(this.payload, 48);

        // Tag (trailing 16 bytes)
        out.set(this.tag, 48 + this.payload.length);

        return out;
    }

    // Parse bytes into a structured KspPacket
    static deserialize(bytes) {
        if (bytes.length < 64) {
            throw new Error("Frame size error: packet size too small");
        }

        const version = bytes[0];
        const type = bytes[1];
        const flags = (bytes[2] << 8) | bytes[3];
        const payloadLen = (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
        
        // Enforce maximum payload check (Memory DoS prevention)
        const MAX_PAYLOAD_SIZE = 16777216; // 16 MB
        if (payloadLen > MAX_PAYLOAD_SIZE) {
            throw new Error(`Frame size error: Payload length ${payloadLen} exceeds protocol maximum of 16MB.`);
        }

        const sessionId = bytes.slice(8, 24);
        const streamId = (bytes[24] << 24) | (bytes[25] << 16) | (bytes[26] << 8) | bytes[27];
        
        let sequence = 0n;
        for (let i = 0; i < 8; i++) {
            sequence = (sequence << 8n) | BigInt(bytes[28 + i]);
        }

        const nonce = bytes.slice(36, 48);
        
        if (bytes.length < 48 + payloadLen + 16) {
            throw new Error("Frame size error: payload truncated");
        }

        const payload = bytes.slice(48, 48 + payloadLen);
        const tag = bytes.slice(48 + payloadLen, 48 + payloadLen + 16);

        return new KspPacket({
            version,
            type,
            flags,
            payloadLen,
            sessionId,
            streamId,
            sequence,
            nonce,
            payload,
            tag
        });
    }
}
