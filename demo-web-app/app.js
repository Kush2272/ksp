/**
 * Main Application Orchestrator (app.js)
 * Implements main state coordination, command line palettes, user triggers, and module bindings.
 */


// DOM Element Selections
const landingPage = document.getElementById('landing-page');
const btnLaunchExplorer = document.getElementById('btn-launch-explorer');
const btnStartSimulation = document.getElementById('btn-start-simulation');
const btnOpenBenchmarks = document.getElementById('btn-open-benchmarks');
const btnShowLanding = document.getElementById('btn-show-landing');

const btnHandshake = document.getElementById('btn-handshake');
const btnReset = document.getElementById('btn-reset');
const stateBadge = document.getElementById('state-badge');
const clientNode = document.getElementById('node-client');
const serverNode = document.getElementById('node-server');

const handshakeTimeline = document.getElementById('handshake-timeline-box');
const certBindingPanel = document.getElementById('cert-binding-panel');
const certSigBox = document.getElementById('cert-sig-box');

const tabChat = document.getElementById('tab-chat');
const tabBuilder = document.getElementById('tab-builder');
const tabCaptures = document.getElementById('tab-captures');
const paneChat = document.getElementById('pane-chat');
const paneBuilder = document.getElementById('pane-builder');
const paneCaptures = document.getElementById('pane-captures');

const chatBox = document.getElementById('chat-box');
const chatInput = document.getElementById('chat-input-field');
const btnSendChat = document.getElementById('btn-send-chat');

const btnEncryptDemo = document.getElementById('btn-encrypt-demo');
const encryptionDemoInput = document.getElementById('encryption-demo-input');
const pipelineFlowSteps = document.getElementById('pipeline-flow-steps');

const consoleLogs = document.getElementById('console-logs');
const consoleInput = document.getElementById('console-input');

const dashboardSessionId = document.getElementById('stat-session-id');
const dashboardCipher = document.getElementById('stat-cipher');
const dashboardHandshakeTime = document.getElementById('stat-handshake-time');
const dashboardPackets = document.getElementById('stat-packets');
const dashboardBytes = document.getElementById('stat-bytes');
const dashboardStreams = document.getElementById('stat-streams');

const attackOverlay = document.getElementById('attack-overlay');

// Module Instances
const dissector = new WiresharkDissector(
    document.getElementById('wireshark-hex'),
    document.getElementById('wireshark-tree')
);

const benchmarkDash = new BenchmarkDashboard(
    'latency-chart-container',
    'throughput-chart-container',
    'bench-stats-container'
);

const animator = new ProtocolAnimator(
    document.getElementById('packet-bus'),
    clientNode,
    serverNode
);

// Global States
let activeSession = null;
let clientDH = null;
let serverDH = null;
let clientRandom = null;
let serverRandom = null;
let sharedSecret = null;
let derivedKeys = null;
let capturedPacketsList = [];
let sampleCaptures = [];
let nextSequenceClient = 1n;
let nextSequenceServer = 1n;

// Initialize Layout and Benchmarks
benchmarkDash.init();

// --- Landing Page Transitions ---
btnLaunchExplorer.addEventListener('click', () => landingPage.style.display = 'none');
btnStartSimulation.addEventListener('click', async () => {
    landingPage.style.display = 'none';
    await runFullHandshake();
});
btnOpenBenchmarks.addEventListener('click', () => {
    landingPage.style.display = 'none';
    document.querySelector('.column-right').scrollIntoView({ behavior: 'smooth' });
});
btnShowLanding.addEventListener('click', () => landingPage.style.display = 'flex');

// --- Tab Swapper Panels ---
function switchTab(activeTab, activePane) {
    [tabChat, tabBuilder, tabCaptures].forEach(t => t.classList.remove('active'));
    [paneChat, paneBuilder, paneCaptures].forEach(p => p.classList.remove('active'));
    activeTab.classList.add('active');
    activePane.classList.add('active');
}
tabChat.addEventListener('click', () => switchTab(tabChat, paneChat));
tabBuilder.addEventListener('click', () => switchTab(tabBuilder, paneBuilder));
tabCaptures.addEventListener('click', () => switchTab(tabCaptures, paneCaptures));

// --- Benchmark Size Selector Toggles ---
document.querySelectorAll('.btn-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.btn-toggle').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        benchmarkDash.drawCharts(btn.getAttribute('data-size'));
    });
});

// --- Protocol Stack layered clicks ---
const layerDefs = {
    framing: "<strong>KSP Framing Layer</strong>: Big-endian network-order binary serializer. Restricts packet structures to 48-byte headers and enforces length bounds to mitigate memory exhaustion vectors.",
    handshake: "<strong>KSP Handshake Layer</strong>: Implements version negotiation, capability intersection, ephemeral keys exchange, identity signatures validation, and transcript Finished HMAC validations.",
    encryption: "<strong>KSP Encryption Layer</strong>: Enforces authenticated encryption using AES-256-GCM or ChaCha20-Poly1305. Nonce derived by IV XOR sequence number to prevent reuse.",
    session: "<strong>KSP Session Layer</strong>: Manages sequence allocations, sliding window replay verification (1024-packet boundary), keepalive probes, and ticket resumption.",
    stream: "<strong>KSP Stream Layer</strong>: Handles multiplexed streams (odd client, even server) and implements window-based backpressure flow control."
};
document.querySelectorAll('.stack-layer').forEach(layerEl => {
    layerEl.addEventListener('click', () => {
        document.querySelectorAll('.stack-layer').forEach(l => l.classList.remove('active'));
        layerEl.classList.add('active');
        const layerKey = layerEl.getAttribute('data-layer');
        document.getElementById('stack-definition-box').innerHTML = layerDefs[layerKey];
    });
});

// --- Handshake Timeline Step Clicker ---
document.querySelectorAll('.timeline-step').forEach(stepEl => {
    stepEl.addEventListener('click', () => {
        stepEl.classList.toggle('expanded');
    });
});

// --- Reset connection ---
function resetState() {
    activeSession = null;
    clientDH = null;
    serverDH = null;
    clientRandom = null;
    serverRandom = null;
    sharedSecret = null;
    derivedKeys = null;
    capturedPacketsList = [];
    nextSequenceClient = 1n;
    nextSequenceServer = 1n;

    // Reset UI indicators
    stateBadge.className = 'state-indicator status-disconnected';
    stateBadge.innerText = 'DISCONNECTED';
    document.querySelectorAll('.state-node').forEach(node => node.classList.remove('active'));
    document.getElementById('sm-disconnected').classList.add('active');
    
    document.querySelectorAll('.timeline-step').forEach(s => s.classList.remove('active', 'expanded'));
    document.querySelector('.cert-box').classList.remove('active');
    certSigBox.classList.remove('active');
    document.querySelector('.trusted-box').classList.remove('active');

    chatInput.disabled = true;
    chatInput.placeholder = "Establish handshake to enable chat...";
    btnSendChat.disabled = true;
    btnHandshake.disabled = false;
    
    chatBox.innerHTML = "";
    document.getElementById('sample-packet-list').innerHTML = "";

    dashboardSessionId.innerText = "-";
    dashboardCipher.innerText = "-";
    dashboardHandshakeTime.innerText = "-";
    dashboardPackets.innerText = "0";
    dashboardBytes.innerText = "0 B";
    dashboardStreams.innerText = "0";

    dissector.hexPanel.innerHTML = '<div style="color: var(--text-secondary); text-align: center; margin-top: 4rem; font-style: italic;">Select a packet or capture to inspect.</div>';
    dissector.treePanel.innerHTML = '<div style="color: var(--text-secondary); text-align: center; margin-top: 4rem; font-style: italic;">Select a packet or capture to inspect.</div>';
}
btnReset.addEventListener('click', resetState);

// --- Complete handshaking pipeline ---
async function runFullHandshake() {
    resetState();
    btnHandshake.disabled = true;
    
    const startTime = performance.now();
    
    // Initial State Node hello
    document.getElementById('sm-disconnected').classList.remove('active');
    document.getElementById('sm-hello').classList.add('active');
    stateBadge.className = 'state-indicator status-hello';
    stateBadge.innerText = 'HELLO';

    // 1. ClientHello
    clientRandom = new Uint8Array(32);
    crypto.getRandomValues(clientRandom);
    clientDH = new X25519Keypair();

    const clientHello = new KspPacket({
        type: PacketType.ClientHello,
        payloadLen: 32,
        payload: clientRandom,
        nonce: clientDH.publicKey.slice(0, 12) // simulate nonce header
    });
    
    document.querySelector('.timeline-step[data-step="client-hello"]').classList.add('active');
    capturedPacketsList.push({ packet: clientHello });
    dissector.dissect(clientHello);
    await animator.sendPacket('c2s', 'ClientHello');

    // 2. ServerHello
    serverRandom = new Uint8Array(32);
    crypto.getRandomValues(serverRandom);
    serverDH = new X25519Keypair();
    const sessionId = new Uint8Array(16);
    crypto.getRandomValues(sessionId);

    const serverHello = new KspPacket({
        type: PacketType.ServerHello,
        sessionId,
        payloadLen: 32,
        payload: serverRandom,
        nonce: serverDH.publicKey.slice(0, 12)
    });

    document.querySelector('.timeline-step[data-step="server-hello"]').classList.add('active');
    capturedPacketsList.push({ packet: serverHello });
    dissector.dissect(serverHello);
    await animator.sendPacket('s2c', 'ServerHello');

    // 3. Certificate & Signature verification
    document.getElementById('sm-hello').classList.remove('active');
    document.getElementById('sm-certificate').classList.add('active');
    stateBadge.className = 'state-indicator status-certificate';
    stateBadge.innerText = 'CERTIFICATE';

    const serverCert = new KspCertificate("ksp://localhost-server");
    const certBytes = serverCert.serialize();
    const certPacket = new KspPacket({
        type: PacketType.Certificate,
        sessionId,
        payloadLen: certBytes.length,
        payload: certBytes
    });

    document.querySelector('.timeline-step[data-step="certificate"]').classList.add('active');
    document.querySelector('.cert-box').classList.add('active');
    await sleep(400);
    certSigBox.classList.add('active');
    await sleep(400);
    document.querySelector('.trusted-box').classList.add('active');

    capturedPacketsList.push({ packet: certPacket });
    dissector.dissect(certPacket);
    await animator.sendPacket('s2c', 'Certificate');

    // 4. ECDH Calculation
    document.querySelector('.timeline-step[data-step="ecdh"]').classList.add('active');
    sharedSecret = clientDH.diffieHellman(serverDH.publicKey);
    await sleep(400);

    // 5. HKDF keys derived
    document.querySelector('.timeline-step[data-step="hkdf"]').classList.add('active');
    derivedKeys = AEADCrypto.deriveKeys(clientRandom, serverRandom, sharedSecret);
    await sleep(400);

    // Initializing state simulator
    activeSession = new KspSessionState(sessionId);
    activeSession.state = ConnectionState.AUTHENTICATED;
    
    // 6. Encrypted Auth request
    document.getElementById('sm-certificate').classList.remove('active');
    document.getElementById('sm-authenticated').classList.add('active');
    stateBadge.className = 'state-indicator status-authenticated';
    stateBadge.innerText = 'AUTHENTICATED';
    document.querySelector('.timeline-step[data-step="auth"]').classList.add('active');

    const authCreds = stringToBytes("API_TOKEN_XYZ_123");
    const encryptedAuth = AEADCrypto.encrypt(derivedKeys.clientWriteKey, derivedKeys.clientWriteIv, 1n, authCreds);
    const authPacket = new KspPacket({
        type: PacketType.AuthRequest,
        sessionId,
        flags: Flags.ENCRYPTED,
        payloadLen: encryptedAuth.ciphertext.length,
        payload: encryptedAuth.ciphertext,
        nonce: encryptedAuth.nonce,
        tag: encryptedAuth.tag,
        sequence: 1n
    });

    capturedPacketsList.push({ packet: authPacket, decryptedPayload: "API_TOKEN_XYZ_123" });
    dissector.dissect(authPacket, "API_TOKEN_XYZ_123");
    await animator.sendPacket('c2s', 'AuthRequest');

    // Auth Response
    const authResBytes = new Uint8Array([0x01]);
    const encryptedAuthRes = AEADCrypto.encrypt(derivedKeys.serverWriteKey, derivedKeys.serverWriteIv, 1n, authResBytes);
    const authResPacket = new KspPacket({
        type: PacketType.AuthResponse,
        sessionId,
        flags: Flags.ENCRYPTED,
        payloadLen: encryptedAuthRes.ciphertext.length,
        payload: encryptedAuthRes.ciphertext,
        nonce: encryptedAuthRes.nonce,
        tag: encryptedAuthRes.tag,
        sequence: 1n
    });
    capturedPacketsList.push({ packet: authResPacket, decryptedPayload: "Success" });
    dissector.dissect(authResPacket, "Success");
    await animator.sendPacket('s2c', 'AuthResponse');

    // 7. Finished Handshake
    document.querySelector('.timeline-step[data-step="finished"]').classList.add('active');
    
    const clientFinish = new KspPacket({
        type: PacketType.HandshakeFinish,
        sessionId,
        flags: Flags.ENCRYPTED,
        payloadLen: 16,
        payload: randomBytes(16),
        sequence: 2n
    });
    capturedPacketsList.push({ packet: clientFinish, decryptedPayload: "Transcript Checked" });
    dissector.dissect(clientFinish, "Transcript Checked");
    await animator.sendPacket('c2s', 'ClientFinished');

    const serverFinish = new KspPacket({
        type: PacketType.HandshakeFinish,
        sessionId,
        flags: Flags.ENCRYPTED,
        payloadLen: 16,
        payload: randomBytes(16),
        sequence: 2n
    });
    capturedPacketsList.push({ packet: serverFinish, decryptedPayload: "Transcript Checked" });
    dissector.dissect(serverFinish, "Transcript Checked");
    await animator.sendPacket('s2c', 'ServerFinished');

    // Handshake Established State
    const duration = performance.now() - startTime;
    activeSession.handshakeDuration = duration;
    activeSession.state = ConnectionState.ESTABLISHED;

    document.getElementById('sm-authenticated').classList.remove('active');
    document.getElementById('sm-established').classList.add('active');
    stateBadge.className = 'state-indicator status-established';
    stateBadge.innerText = 'ESTABLISHED';

    // Populate dashboard statistics
    dashboardSessionId.innerText = bytesToHex(sessionId).slice(0, 16).toUpperCase() + "...";
    dashboardCipher.innerText = activeSession.cipherSuite;
    dashboardHandshakeTime.innerText = duration.toFixed(2) + " ms";
    dashboardPackets.innerText = capturedPacketsList.length.toString();
    
    let totalBytes = capturedPacketsList.reduce((acc, curr) => acc + curr.packet.serialize().length, 0);
    dashboardBytes.innerText = totalBytes + " B";
    
    activeSession.createStream(1);
    dashboardStreams.innerText = activeSession.streams.size;

    // Enable Secure Chat Interface
    chatInput.disabled = false;
    chatInput.placeholder = "Send secure message...";
    btnSendChat.disabled = false;

    writeConsole(`Connected! Handshake completed in ${duration.toFixed(2)}ms. DerivedKeys established.`);
}

btnHandshake.addEventListener('click', runFullHandshake);


function randomBytes(len) {
    const b = new Uint8Array(len);
    crypto.getRandomValues(b);
    return b;
}

// --- Live secure Chat client-server echoing ---
async function handleSendChatMessage() {
    const text = chatInput.value.trim();
    if (!text || !activeSession) return;

    chatInput.value = "";

    const streamSelect = document.getElementById('chat-stream-select');
    const streamId = parseInt(streamSelect.value);

    // Pick stream-specific labels and accent tags colors
    let streamLabel = `Stream ${streamId}`;
    let accentColor = "var(--accent-blue)";
    let bgStyle = "";

    if (streamId === 3) {
        accentColor = "var(--accent-purple)";
        bgStyle = "background-color: #2b0b3e; border: 1px solid rgba(216, 0, 255, 0.25);";
    } else if (streamId === 5) {
        accentColor = "var(--accent-green)";
        bgStyle = "background-color: #0b2214; border: 1px solid rgba(0, 255, 170, 0.25);";
    }

    // Register active stream dynamically in session state registry
    if (!activeSession.streams.has(streamId)) {
        activeSession.createStream(streamId);
        dashboardStreams.innerText = activeSession.streams.size;
    }

    // 1. Client sends message
    const clientBubble = document.createElement('div');
    clientBubble.className = 'message-bubble client';
    clientBubble.style.cssText = bgStyle;
    clientBubble.innerHTML = `
        <div>${text}</div>
        <div class="message-meta">
            <span style="color: ${accentColor}; font-weight: 600;">💻 Stream ${streamId} Sent</span>
            <span style="color: var(--accent-green);">AES-GCM</span>
        </div>
    `;
    chatBox.appendChild(clientBubble);
    chatBox.scrollTop = chatBox.scrollHeight;

    const payloadBytes = stringToBytes(text);
    const seq = nextSequenceClient;
    nextSequenceClient += 1n;

    const encrypted = AEADCrypto.encrypt(derivedKeys.clientWriteKey, derivedKeys.clientWriteIv, seq, payloadBytes);
    const packet = new KspPacket({
        type: PacketType.StreamData,
        sessionId: activeSession.id,
        flags: Flags.ENCRYPTED,
        streamId: streamId,
        sequence: seq,
        payloadLen: encrypted.ciphertext.length,
        payload: encrypted.ciphertext,
        nonce: encrypted.nonce,
        tag: encrypted.tag
    });

    capturedPacketsList.push({ packet, decryptedPayload: text });
    dissector.dissect(packet, text);
    
    // Dashboard update
    activeSession.packetsCount = capturedPacketsList.length;
    dashboardPackets.innerText = activeSession.packetsCount;
    let totalBytes = capturedPacketsList.reduce((acc, curr) => acc + curr.packet.serialize().length, 0);
    dashboardBytes.innerText = totalBytes + " B";

    await animator.sendPacket('c2s', streamLabel);

    // 2. Server decrypts and sends reply Echo
    await sleep(200);

    const replyText = `Echo: ${text}`;
    const replyBytes = stringToBytes(replyText);
    const replySeq = nextSequenceServer;
    nextSequenceServer += 1n;

    const encryptedReply = AEADCrypto.encrypt(derivedKeys.serverWriteKey, derivedKeys.serverWriteIv, replySeq, replyBytes);
    const replyPacket = new KspPacket({
        type: PacketType.StreamData,
        sessionId: activeSession.id,
        flags: Flags.ENCRYPTED,
        streamId: streamId,
        sequence: replySeq,
        payloadLen: encryptedReply.ciphertext.length,
        payload: encryptedReply.ciphertext,
        nonce: encryptedReply.nonce,
        tag: encryptedReply.tag
    });

    capturedPacketsList.push({ packet: replyPacket, decryptedPayload: replyText });
    dissector.dissect(replyPacket, replyText);

    // Dashboard update
    activeSession.packetsCount = capturedPacketsList.length;
    dashboardPackets.innerText = activeSession.packetsCount;
    totalBytes = capturedPacketsList.reduce((acc, curr) => acc + curr.packet.serialize().length, 0);
    dashboardBytes.innerText = totalBytes + " B";

    await animator.sendPacket('s2c', streamLabel + " Echo");

    // Render Server bubble
    const serverBubble = document.createElement('div');
    serverBubble.className = 'message-bubble server';
    serverBubble.style.cssText = bgStyle;
    serverBubble.innerHTML = `
        <div>${replyText}</div>
        <div class="message-meta">
            <span style="color: ${accentColor}; font-weight: 600;">🖥️ Stream ${streamId} Reply</span>
            <span style="color: var(--accent-green);">AES-GCM</span>
        </div>
    `;
    chatBox.appendChild(serverBubble);
    chatBox.scrollTop = chatBox.scrollHeight;
}

btnSendChat.addEventListener('click', handleSendChatMessage);
chatInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleSendChatMessage();
});

// --- Encryption pipeline demo ---
btnEncryptDemo.addEventListener('click', async () => {
    const text = encryptionDemoInput.value.trim();
    if (!text) return;

    btnEncryptDemo.disabled = true;
    
    // Run pipeline animations
    await animator.animateEncryptionPipeline(pipelineFlowSteps, text, (stageId) => {
        // Log in console
        writeConsole(`Encryption pipeline: processing step "${stageId}"`);
    });

    btnEncryptDemo.disabled = false;
});

// --- Custom Packet Builder ---
const btnGeneratePacket = document.getElementById('btn-generate-packet');
btnGeneratePacket.addEventListener('click', () => {
    const typeHex = document.getElementById('builder-type').value;
    const streamId = parseInt(document.getElementById('builder-stream').value);
    const payloadText = document.getElementById('builder-payload').value;
    
    let flagsVal = 0;
    if (document.getElementById('flag-encrypted').checked) flagsVal |= Flags.ENCRYPTED;
    if (document.getElementById('flag-compressed').checked) flagsVal |= Flags.COMPRESSED;
    if (document.getElementById('flag-endstream').checked) flagsVal |= Flags.END_STREAM;
    if (document.getElementById('flag-fragmented').checked) flagsVal |= Flags.FRAGMENTED;

    const payloadBytes = stringToBytes(payloadText);
    const sessionBytes = activeSession ? activeSession.id : new Uint8Array(16);
    
    const packet = new KspPacket({
        type: parseInt(typeHex),
        flags: flagsVal,
        streamId,
        sequence: activeSession ? nextSequenceClient : 1n,
        payloadLen: payloadBytes.length,
        payload: payloadBytes,
        sessionId: sessionBytes
    });

    capturedPacketsList.push({ packet, decryptedPayload: payloadText });
    dissector.dissect(packet, payloadText);
    writeConsole(`Packet Builder: Generated custom packet Type=${PacketTypeName[packet.type]}, size=${packet.serialize().length} bytes.`);
    
    // Switch to chat tab to view
    switchTab(tabChat, paneChat);
});

// --- Threat simulator attacks triggers ---
document.querySelectorAll('.btn-threat').forEach(btn => {
    btn.addEventListener('click', async () => {
        const attackType = btn.getAttribute('data-attack');
        
        if (attackType === 'mitm') {
            await animator.animateMitmAttack(attackOverlay);
        } else if (attackType === 'replay') {
            await animator.animateReplayAttack(attackOverlay);
        } else if (attackType === 'downgrade') {
            await animator.animateDowngradeAttack(attackOverlay);
        }
    });
});

// Memory DoS triggers
document.getElementById('btn-attack-dos').addEventListener('click', async () => {
    attackOverlay.innerHTML = `
        <div class="attack-banner red-glow">
            <h3>⚠️ Memory Amplification DoS Attack</h3>
            <p>Attacker sends a framing header claim for 4GB payload length to cause server OOM.</p>
            <div class="attack-visualization">
                <span class="node-icon red">😈 Attacker</span> ──📦 PayloadLen: 4,294,967,295 Bytes──→ <span class="node-icon">🖥️ Server</span>
            </div>
            <p class="mitigation-detail">
                <strong>KSP Mitigation (Section 4.5)</strong>: Server checks header value against limit constraints (MAX_PAYLOAD_SIZE = 16MB) before buffer allocation.
                <span class="status-reject">Oversized payload rejected! Connection immediately terminated.</span>
            </p>
        </div>
    `;
    attackOverlay.style.display = 'flex';
    await sleep(4000);
    attackOverlay.style.display = 'none';
});

// --- Simulated CLI Console Palette Interpreter ---
function writeConsole(text) {
    const line = document.createElement('div');
    line.innerText = `[${new Date().toLocaleTimeString()}] ${text}`;
    consoleLogs.appendChild(line);
    consoleLogs.scrollTop = consoleLogs.scrollHeight;
}

consoleInput.addEventListener('keypress', async (e) => {
    if (e.key === 'Enter') {
        const cmd = consoleInput.value.trim().toLowerCase();
        consoleInput.value = "";

        writeConsole(`ksp> ${cmd}`);

        if (cmd === 'help') {
            writeConsole("Commands: connect, disconnect, send <msg>, benchmark <size>, capture, clear");
        } else if (cmd === 'connect') {
            await runFullHandshake();
        } else if (cmd === 'disconnect') {
            resetState();
            writeConsole("Session closed.");
        } else if (cmd.startsWith('send ')) {
            if (!activeSession) {
                writeConsole("Error: Not connected.");
            } else {
                chatInput.value = cmd.substring(5);
                await handleSendChatMessage();
            }
        } else if (cmd.startsWith('benchmark ')) {
            const size = cmd.substring(10).toUpperCase();
            if (["1KB", "64KB", "1MB"].includes(size)) {
                benchmarkDash.drawCharts(size);
                writeConsole(`Benchmarks loaded for ${size}`);
            } else {
                writeConsole("Usage: benchmark 1KB | 64KB | 1MB");
            }
        } else if (cmd === 'capture') {
            writeConsole(`Active capturing session: ${capturedPacketsList.length} frames logged.`);
        } else if (cmd === 'clear') {
            consoleLogs.innerHTML = "";
        } else {
            writeConsole(`Unknown command "${cmd}". Type "help" for options.`);
        }
    }
});

// --- Sample capture loaders ---
document.getElementById('btn-load-sample-1').addEventListener('click', () => {
    // Generate mock capture packets
    const p1 = new KspPacket({ type: PacketType.ClientHello, sequence: 0n });
    const p2 = new KspPacket({ type: PacketType.ServerHello, sequence: 0n });
    const p3 = new KspPacket({ type: PacketType.Certificate, sequence: 0n });
    
    renderSamplePackets([p1, p2, p3]);
});

document.getElementById('btn-load-sample-2').addEventListener('click', () => {
    const p1 = new KspPacket({ type: PacketType.Data, sequence: 42n });
    const p2 = new KspPacket({ type: PacketType.Data, sequence: 42n }); // replayed
    
    renderSamplePackets([p1, p2]);
});

function renderSamplePackets(packets) {
    const listEl = document.getElementById('sample-packet-list');
    listEl.innerHTML = "";

    packets.forEach((p, idx) => {
        const item = document.createElement('div');
        item.className = 'packet-item handshake';
        item.innerHTML = `
            <span>[Sample Frame #${idx + 1}] ${PacketTypeName[p.type]}</span>
            <span class="badge blue">CAPTURE</span>
        `;
        item.addEventListener('click', () => {
            dissector.dissect(p);
        });
        listEl.appendChild(item);
    });
}
