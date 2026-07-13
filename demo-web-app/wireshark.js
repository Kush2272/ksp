/**
 * Wireshark Dissector Module (wireshark.js)
 * Implements the interactive hex/tree panels, highlighting mapping bounds between fields and byte-offsets.
 */

class WiresharkDissector {
    constructor(hexPanelEl, treePanelEl) {
        this.hexPanel = hexPanelEl;
        this.treePanel = treePanelEl;
        this.activePacket = null;
        this.activeBytes = null;
    }

    // Load and render a packet
    dissect(packet, decryptedPayload = null) {
        this.activePacket = packet;
        const bytes = packet.serialize();
        this.activeBytes = bytes;

        // Render Hex Dump
        this.renderHexPanel(bytes);
        // Render Parsing Tree
        this.renderTreePanel(packet, decryptedPayload);
        // Bind hover events
        this.bindEvents();
    }

    // Render left panel hex dump
    renderHexPanel(bytes) {
        let html = "";
        const payloadStart = 48;
        const payloadEnd = 48 + this.activePacket.payloadLen;

        for (let i = 0; i < bytes.length; i += 16) {
            const chunk = bytes.slice(i, i + 16);
            const offsetStr = i.toString(16).padStart(4, '0').toUpperCase();
            
            let hexPart = "";
            let asciiPart = "";

            for (let j = 0; j < 16; j++) {
                const byteIdx = i + j;
                if (byteIdx < bytes.length) {
                    const b = bytes[byteIdx];
                    const hexVal = b.toString(16).padStart(2, '0').toUpperCase();
                    
                    // Determine syntax coloring group
                    let colorClass = "header-byte";
                    if (byteIdx >= payloadStart && byteIdx < payloadEnd) {
                        colorClass = "payload-byte";
                    } else if (byteIdx >= payloadEnd) {
                        colorClass = "tag-byte";
                    }

                    hexPart += `<span class="hex-byte ${colorClass}" data-index="${byteIdx}">${hexVal}</span> `;
                    asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
                } else {
                    hexPart += "   ";
                }
            }

            html += `<div class="hex-line"><span class="offset-label">${offsetStr}</span>  ${hexPart}  <span class="ascii-chars">${asciiPart}</span></div>`;
        }

        this.hexPanel.innerHTML = html;
    }

    // Render right panel tree
    renderTreePanel(packet, decryptedPayload) {
        const payloadStart = 48;
        const payloadEnd = 48 + packet.payloadLen;

        let flagsList = [];
        for (const [fName, fVal] of Object.entries(Flags)) {
            if ((packet.flags & fVal) !== 0) {
                flagsList.push(fName);
            }
        }
        const flagsStr = flagsList.length > 0 ? flagsList.join(" | ") : "NONE";

        let isEncrypted = (packet.flags & Flags.ENCRYPTED) !== 0;
        let payloadText = isEncrypted ? bytesToHex(packet.payload).slice(0, 16) + "..." : bytesToString(packet.payload);
        if (isEncrypted && decryptedPayload) {
            payloadText = `"${decryptedPayload}" [Decrypted]`;
        }

        this.treePanel.innerHTML = `
            <div class="tree-root active-tree-root">▼ Kush Secure Protocol (KSP) Frame</div>
            <div class="tree-node">
                <div class="tree-field" data-field="version">├─ Version: <span>1.0 (0x${packet.version.toString(16).padStart(2, '0').toUpperCase()})</span></div>
                <div class="tree-field" data-field="type">├─ Type: <span>${PacketTypeName[packet.type]} (0x${packet.type.toString(16).padStart(2, '0').toUpperCase()})</span></div>
                <div class="tree-field" data-field="flags">├─ Flags: <span>0x${packet.flags.toString(16).padStart(4, '0').toUpperCase()} (${flagsStr})</span></div>
                <div class="tree-field" data-field="payloadLen">├─ Payload Length: <span>${packet.payloadLen} bytes</span></div>
                <div class="tree-field" data-field="sessionId">├─ Session ID: <span>0x${bytesToHex(packet.sessionId).toUpperCase()}</span></div>
                <div class="tree-field" data-field="streamId">├─ Stream ID: <span>${packet.streamId}</span></div>
                <div class="tree-field" data-field="sequence">├─ Sequence Number: <span>${packet.sequence}</span></div>
                <div class="tree-field" data-field="nonce">├─ Nonce: <span>0x${bytesToHex(packet.nonce).toUpperCase()}</span></div>
                <div class="tree-field" data-field="payload" data-start="${payloadStart}" data-end="${payloadEnd}">├─ Encrypted Payload: <span>${payloadText}</span></div>
                <div class="tree-field" data-field="tag" data-start="${payloadEnd}" data-end="${payloadEnd + 16}">└─ Authentication Tag: <span>0x${bytesToHex(packet.tag).toUpperCase()}</span></div>
            </div>
        `;
    }

    // Hover-highlight linking between hex dump and tree nodes
    bindEvents() {
        const hexPanel = this.hexPanel;
        const treePanel = this.treePanel;
        const payloadStart = 48;
        const payloadEnd = 48 + this.activePacket.payloadLen;

        // Tree Field Hover -> Highlight hex bytes
        const treeFields = treePanel.querySelectorAll('.tree-field');
        treeFields.forEach(fieldEl => {
            fieldEl.addEventListener('mouseenter', () => {
                const fieldName = fieldEl.getAttribute('data-field');
                let start = 0;
                let end = 0;

                if (fieldName === 'payload') {
                    start = payloadStart;
                    end = payloadEnd;
                } else if (fieldName === 'tag') {
                    start = payloadEnd;
                    end = payloadEnd + 16;
                } else {
                    const range = FieldByteRanges[fieldName];
                    start = range.start;
                    end = range.end;
                }

                // Highlight all matching index elements
                hexPanel.querySelectorAll('.hex-byte').forEach(byteEl => {
                    const idx = parseInt(byteEl.getAttribute('data-index'));
                    if (idx >= start && idx < end) {
                        byteEl.classList.add('highlight-byte');
                    }
                });
                fieldEl.classList.add('highlight-field');
            });

            fieldEl.addEventListener('mouseleave', () => {
                hexPanel.querySelectorAll('.hex-byte').forEach(byteEl => {
                    byteEl.classList.remove('highlight-byte');
                });
                fieldEl.classList.remove('highlight-field');
            });
        });

        // Hex Byte Hover -> Highlight corresponding Tree Field
        const hexBytes = hexPanel.querySelectorAll('.hex-byte');
        hexBytes.forEach(byteEl => {
            byteEl.addEventListener('mouseenter', () => {
                const idx = parseInt(byteEl.getAttribute('data-index'));
                let fieldName = "";

                // Check payload and tag dynamic bounds
                if (idx >= payloadStart && idx < payloadEnd) {
                    fieldName = "payload";
                } else if (idx >= payloadEnd && idx < payloadEnd + 16) {
                    fieldName = "tag";
                } else {
                    // Check static fields
                    for (const [name, range] of Object.entries(FieldByteRanges)) {
                        if (name !== 'payload' && name !== 'tag') {
                            if (idx >= range.start && idx < range.end) {
                                fieldName = name;
                                break;
                            }
                        }
                    }
                }

                // Highlight the matching tree field node
                const targetField = treePanel.querySelector(`.tree-field[data-field="${fieldName}"]`);
                if (targetField) {
                    targetField.classList.add('highlight-field');
                    // Highlight the byte itself
                    byteEl.classList.add('highlight-byte');
                }
            });

            byteEl.addEventListener('mouseleave', () => {
                treePanel.querySelectorAll('.tree-field').forEach(el => el.classList.remove('highlight-field'));
                byteEl.classList.remove('highlight-byte');
            });
        });
    }
}
