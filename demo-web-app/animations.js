/**
 * Animations Module (animations.js)
 * Implements 60fps packet animations, state updates, and visual attack/mitigation simulations.
 */

// Simple helper to sleep
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

class ProtocolAnimator {
    constructor(packetBusEl, nodeClientEl, nodeServerEl) {
        this.bus = packetBusEl;
        this.clientNode = nodeClientEl;
        this.serverNode = nodeServerEl;
    }

    // Animate packet dot movement with custom labels and colors
    async sendPacket(direction, label) {
        this.bus.innerText = label || "Packet";
        this.bus.style.display = 'block';

        // Apply visual accents based on Stream ID or Packet Type
        if (label && label.includes("Stream 1")) {
            this.bus.style.borderColor = "var(--accent-blue)";
            this.bus.style.boxShadow = "0 0 12px var(--shadow-blue)";
        } else if (label && label.includes("Stream 3")) {
            this.bus.style.borderColor = "var(--accent-purple)";
            this.bus.style.boxShadow = "0 0 12px rgba(216, 0, 255, 0.4)";
        } else if (label && label.includes("Stream 5")) {
            this.bus.style.borderColor = "var(--accent-green)";
            this.bus.style.boxShadow = "0 0 12px var(--shadow-green)";
        } else {
            this.bus.style.borderColor = "var(--accent-blue)";
            this.bus.style.boxShadow = "0 0 12px var(--shadow-blue)";
        }
        
        if (direction === 'c2s') {
            this.bus.style.animation = 'packet-left-to-right 0.8s cubic-bezier(0.25, 1, 0.5, 1) forwards';
            await sleep(800);
        } else {
            this.bus.style.animation = 'packet-right-to-left 0.8s cubic-bezier(0.25, 1, 0.5, 1) forwards';
            await sleep(800);
        }
        
        this.bus.style.display = 'none';
    }

    // Animate standard encryption flow stages (10-step pipeline)
    async animateEncryptionPipeline(stagesContainer, text, callbackStage) {
        stagesContainer.innerHTML = "";
        stagesContainer.style.display = "block";
        
        const textBytes = new TextEncoder().encode(text);
        const bytesStr = "[" + Array.from(textBytes).join(", ") + "]";

        const steps = [
            { id: 'plaintext', label: '1. Plaintext Input', data: `"${text}"` },
            { id: 'utf8', label: '2. UTF-8 Encoding', data: `Bytes: ${bytesStr}` },
            { id: 'serialize', label: '3. Serializer', data: 'Prepping 48-Byte binary header fields' },
            { id: 'nonce', label: '4. Nonce Construction', data: 'Salt XOR sequence counter' },
            { id: 'aead', label: '5. AEAD Encrypt', data: 'Executing AES-256-GCM hardware cipher' },
            { id: 'ciphertext', label: '6. Ciphertext Output', data: 'Derived binary ciphertext bytes' },
            { id: 'packet', label: '7. Packet Assembly', data: 'Concatenating Header + Ciphertext + Tag' },
            { id: 'transmit', label: '8. Transmit (Wire)', data: 'Sending over simulated TCP channel' },
            { id: 'decrypt', label: '9. AEAD Decrypt', data: 'Verifying Tag and decrypting payload' },
            { id: 'recovered', label: '10. Recovered Plaintext', data: `Plaintext: "${text}"` }
        ];

        for (const step of steps) {
            const stepEl = document.createElement('div');
            stepEl.className = 'animation-pipeline-step glow-blue';
            stepEl.innerHTML = `<strong>${step.label}</strong>: <span>${step.data}</span>`;
            stagesContainer.appendChild(stepEl);
            if (callbackStage) callbackStage(step.id);
            await sleep(400);
        }
        
        await sleep(1500); // Leave visible longer so it is readable
        stagesContainer.style.display = "none";
    }

    // Animate MITM attack simulation
    async animateMitmAttack(overlayContainer) {
        overlayContainer.innerHTML = `
            <div class="attack-banner red-glow">
                <h3>⚠️ Active MITM Attack Detected</h3>
                <p>Attacker tries to intercept Client ephemeral public key and forward a compromised public key.</p>
                <div class="attack-visualization">
                    <span class="node-icon">💻 Client</span> ──🔑 Client_Pub──→ <span class="node-icon red">😈 Attacker</span> ──🔑 Compromised_Pub──→ <span class="node-icon">🖥️ Server</span>
                </div>
                <p class="mitigation-detail">
                    <strong>KSP Mitigation (Section 9.5)</strong>: Server signs the ephemeral randoms and keys using its verified certificate. Client verifies the signature. 
                    <span class="status-reject">Verification Failed! Handshake Aborted.</span>
                </p>
            </div>
        `;
        overlayContainer.style.display = 'flex';
        await sleep(4000);
        overlayContainer.style.display = 'none';
    }

    // Animate Replay attack simulation
    async animateReplayAttack(overlayContainer) {
        overlayContainer.innerHTML = `
            <div class="attack-banner red-glow">
                <h3>⚠️ Packet Replay Attack Detected</h3>
                <p>Attacker intercepts a valid historical data packet (Sequence #42) and re-sends it to the Server.</p>
                <div class="attack-visualization">
                    <span class="node-icon">😈 Attacker</span> ──📦 Captured Packet (Seq #42)──→ <span class="node-icon">🖥️ Server</span>
                </div>
                <p class="mitigation-detail">
                    <strong>KSP Mitigation (Section 14)</strong>: Server checks its 1024-packet sliding window bitmap. Sequence #42 is already marked.
                    <span class="status-reject">Replay Detected! Packet Silently Rejected.</span>
                </p>
            </div>
        `;
        overlayContainer.style.display = 'flex';
        await sleep(4000);
        overlayContainer.style.display = 'none';
    }

    // Animate Downgrade attack simulation
    async animateDowngradeAttack(overlayContainer) {
        overlayContainer.innerHTML = `
            <div class="attack-banner red-glow">
                <h3>⚠️ Cipher Downgrade Attack Detected</h3>
                <p>Attacker intercepts ClientHello to strip out AES-256-GCM and force a weak/disabled cipher suite.</p>
                <div class="attack-visualization">
                    <span class="node-icon">💻 Client (AES & ChaCha)</span> ──📦 Proposals──→ <span class="node-icon red">😈 Attacker (strips AES)</span> ──📦 Modified Proposals──→ <span class="node-icon">🖥️ Server (ChaCha only)</span>
                </div>
                <p class="mitigation-detail">
                    <strong>KSP Mitigation (Section 7.5)</strong>: Handshake transcript integrity check. The Finished MAC computed over the transcript fails to match.
                    <span class="status-reject">Transcript Verification Mismatch! Handshake Terminated.</span>
                </p>
            </div>
        `;
        overlayContainer.style.display = 'flex';
        await sleep(4500);
        overlayContainer.style.display = 'none';
    }

    // Animate Malformed Frame attack simulation
    async animateMalformedAttack(overlayContainer) {
        overlayContainer.innerHTML = `
            <div class="attack-banner red-glow">
                <h3>⚠️ Malformed Frame Parsing Rejection</h3>
                <p>Attacker sends a packet containing randomized bytes, corrupted version codes, or mismatched layout flags.</p>
                <div class="attack-visualization">
                    <span class="node-icon red">😈 Attacker</span> ──📦 Corrupted Binary Bytes──→ <span class="node-icon">🖥️ Server</span>
                </div>
                <p class="mitigation-detail">
                    <strong>KSP Mitigation (Section 4.2)</strong>: Enforces strict length verification and zero-copy packet header schema validation.
                    <span class="status-reject">Frame Parsing Failed! ProtocolError Triggered. Connection Terminated.</span>
                </p>
            </div>
        `;
        overlayContainer.style.display = 'flex';
        await sleep(4000);
        overlayContainer.style.display = 'none';
    }

    // Animate Nonce Reuse attack simulation
    async animateNonceReuseAttack(overlayContainer) {
        overlayContainer.innerHTML = `
            <div class="attack-banner red-glow">
                <h3>⚠️ Nonce Reuse Cryptographic Rejection</h3>
                <p>Attacker injects a data packet utilizing a previously observed nonce to bypass encryption bounds.</p>
                <div class="attack-visualization">
                    <span class="node-icon red">😈 Attacker</span> ──🔑 Repeated Nonce (IV XOR Seq)──→ <span class="node-icon">🖥️ Server</span>
                </div>
                <p class="mitigation-detail">
                    <strong>KSP Mitigation (Section 8.4)</strong>: Enforces TLS 1.3-style sequence-to-IV XOR nonces that are checked against the replay window. If replay window is bypassed, AEAD decryption fails.
                    <span class="status-reject">AEAD Decryption Mismatch! Authentication Tag Validation Failed.</span>
                </p>
            </div>
        `;
        overlayContainer.style.display = 'flex';
        await sleep(4500);
        overlayContainer.style.display = 'none';
    }
}
