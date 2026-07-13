/**
 * Cryptographic Simulator Module (crypto-simulator.js)
 * Implements mock X25519 ECDH key generation, HKDF key derivation, Ed25519 certificate verification, and XOR-based reversible AEAD encryption.
 */

// Helper to convert string to bytes
function stringToBytes(str) {
    return new TextEncoder().encode(str);
}

// Helper to convert bytes to string
function bytesToString(bytes) {
    return new TextDecoder().decode(bytes);
}

// Convert byte array to hexadecimal string
function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Convert hexadecimal string to byte array
function hexToBytes(hex) {
    if (hex.length % 2 !== 0) hex = '0' + hex;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

// Generates simple cryptographic mock keys
class X25519Keypair {
    constructor() {
        // Mock private key
        this.privateKey = new Uint8Array(32);
        crypto.getRandomValues(this.privateKey);
        
        // Mock public key derived from private key (simple byte mapping for simulation)
        this.publicKey = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            this.publicKey[i] = this.privateKey[i] ^ 0xAA;
        }
    }

    // ECDH Shared secret computation
    diffieHellman(peerPublicKey) {
        const shared = new Uint8Array(32);
        // Verify all-zero weak keys
        let isZero = true;
        for (let i = 0; i < 32; i++) {
            if (peerPublicKey[i] !== 0) isZero = false;
        }
        if (isZero) {
            throw new Error("Weak key exchange rejected: peer public key is all zeros");
        }

        for (let i = 0; i < 32; i++) {
            shared[i] = this.privateKey[i] ^ peerPublicKey[31 - i];
        }
        return shared;
    }
}

// KspCertificate representation
class KspCertificate {
    constructor(subject) {
        this.version = 0x01;
        this.subject = subject;
        this.publicKey = new Uint8Array(32);
        crypto.getRandomValues(this.publicKey);
        this.issuer = "KSP Self-Signed Root CA";
        this.notBefore = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
        this.notAfter = Math.floor(Date.now() / 1000) + 365 * 24 * 3600; // 1 year later
        this.serialNumber = new Uint8Array(16);
        crypto.getRandomValues(this.serialNumber);
        
        // Mock signature (Ed25519)
        this.signature = new Uint8Array(64);
        crypto.getRandomValues(this.signature);
    }

    serialize() {
        const subjectBytes = stringToBytes(this.subject);
        const issuerBytes = stringToBytes(this.issuer);
        const size = 1 + 32 + 8 + 8 + 16 + 64 + subjectBytes.length + issuerBytes.length;
        const out = new Uint8Array(size);

        out[0] = this.version;
        out.set(this.publicKey, 1);
        out.set(this.serialNumber, 33);
        
        // Write timestamps
        const view = new DataView(out.buffer);
        view.setUint32(49, this.notBefore >> 32);
        view.setUint32(53, this.notBefore & 0xFFFFFFFF);
        view.setUint32(57, this.notAfter >> 32);
        view.setUint32(61, this.notAfter & 0xFFFFFFFF);

        out.set(this.signature, 65);
        out.set(subjectBytes, 129);
        out.set(issuerBytes, 129 + subjectBytes.length);

        return out;
    }
}

// Reversible XOR AEAD Crypto Engine for Dissection
class AEADCrypto {
    static deriveKeys(clientRandom, serverRandom, sharedSecret) {
        // Concatenate keys
        const seed = new Uint8Array(clientRandom.length + serverRandom.length + sharedSecret.length);
        seed.set(clientRandom, 0);
        seed.set(serverRandom, clientRandom.length);
        seed.set(sharedSecret, clientRandom.length + serverRandom.length);

        // Simple mock HKDF expansion
        const clientWriteKey = seed.slice(0, 32);
        const serverWriteKey = seed.slice(32, 64);
        const clientWriteIv = seed.slice(64, 76);
        const serverWriteIv = seed.slice(76, 88);

        return { clientWriteKey, serverWriteKey, clientWriteIv, serverWriteIv };
    }

    // Encrypt method using TLS 1.3 sequence-IV XOR construction
    static encrypt(key, iv, sequence, plaintext) {
        const nonce = new Uint8Array(12);
        nonce.set(iv);
        for (let i = 0; i < 8; i++) {
            const seqByte = Number((BigInt(sequence) >> BigInt(i * 8)) & 0xFFn);
            nonce[11 - i] ^= seqByte;
        }

        const ciphertext = new Uint8Array(plaintext.length);
        for (let i = 0; i < plaintext.length; i++) {
            ciphertext[i] = plaintext[i] ^ key[i % 32] ^ nonce[i % 12];
        }

        // Mock 16-byte authentication tag
        const tag = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            tag[i] = key[i % 32] ^ nonce[i % 12] ^ (plaintext.length & 0xFF);
        }

        return { ciphertext, tag, nonce };
    }

    // Decrypt method
    static decrypt(key, iv, sequence, ciphertext, tag, nonce) {
        // Verify mock tag
        const expectedTag = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            expectedTag[i] = key[i % 32] ^ nonce[i % 12] ^ (ciphertext.length & 0xFF);
        }

        for (let i = 0; i < 16; i++) {
            if (tag[i] !== expectedTag[i]) {
                throw new Error("Decryption failed: integrity authentication tag mismatch");
            }
        }

        const plaintext = new Uint8Array(ciphertext.length);
        for (let i = 0; i < ciphertext.length; i++) {
            plaintext[i] = ciphertext[i] ^ key[i % 32] ^ nonce[i % 12];
        }

        return plaintext;
    }
}
