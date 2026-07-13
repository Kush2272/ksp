-- KSP Protocol Wireshark Dissector
-- Kush Secure Protocol v1.0
--
-- Installation:
--   Copy this file to your Wireshark personal plugins directory.
--   Find it via: Help → About Wireshark → Folders → Personal Plugins
--
-- Usage:
--   1. Start a KSP server and client
--   2. Capture traffic on the KSP port (default: 9876)
--   3. Packets will be decoded as "KSP" in the protocol column

-- Create the protocol object
local ksp_proto = Proto("ksp", "Kush Secure Protocol")

-- ═══════════════════════════════════════════════════════════════
-- Protocol Fields
-- ═══════════════════════════════════════════════════════════════

-- Header fields
local f_version = ProtoField.uint8("ksp.version", "Version", base.HEX)
local f_version_major = ProtoField.uint8("ksp.version.major", "Major", base.DEC)
local f_version_minor = ProtoField.uint8("ksp.version.minor", "Minor", base.DEC)

local f_type = ProtoField.uint8("ksp.type", "Packet Type", base.HEX, {
    [0x01] = "ClientHello",
    [0x02] = "ServerHello",
    [0x03] = "KeyExchange",
    [0x04] = "Certificate",
    [0x05] = "AuthRequest",
    [0x06] = "AuthResponse",
    [0x07] = "HandshakeFinish",
    [0x10] = "Data",
    [0x11] = "DataAck",
    [0x20] = "StreamOpen",
    [0x21] = "StreamData",
    [0x22] = "StreamClose",
    [0x23] = "StreamReset",
    [0x30] = "KeepAlive",
    [0x31] = "KeepAliveAck",
    [0x32] = "WindowUpdate",
    [0x33] = "GoAway",
    [0x40] = "SessionResume",
    [0x41] = "SessionTicket",
    [0xFF] = "Error",
})

local f_flags = ProtoField.uint16("ksp.flags", "Flags", base.HEX)
local f_flag_compressed = ProtoField.bool("ksp.flags.compressed", "Compressed", 16, nil, 0x0001)
local f_flag_encrypted = ProtoField.bool("ksp.flags.encrypted", "Encrypted", 16, nil, 0x0002)
local f_flag_fragmented = ProtoField.bool("ksp.flags.fragmented", "Fragmented", 16, nil, 0x0004)
local f_flag_end_stream = ProtoField.bool("ksp.flags.end_stream", "End Stream", 16, nil, 0x0008)
local f_flag_ack = ProtoField.bool("ksp.flags.ack", "ACK", 16, nil, 0x0010)
local f_flag_priority = ProtoField.bool("ksp.flags.priority", "Priority", 16, nil, 0x0020)
local f_flag_padded = ProtoField.bool("ksp.flags.padded", "Padded", 16, nil, 0x0040)

local f_payload_length = ProtoField.uint32("ksp.payload_length", "Payload Length", base.DEC)

local f_session_id = ProtoField.bytes("ksp.session_id", "Session ID")
local f_session_id_str = ProtoField.string("ksp.session_id_str", "Session ID (UUID)")

local f_stream_id = ProtoField.uint32("ksp.stream_id", "Stream ID", base.DEC)
local f_sequence = ProtoField.uint64("ksp.sequence", "Sequence Number", base.DEC)
local f_nonce = ProtoField.bytes("ksp.nonce", "Nonce")

-- Payload and tag
local f_payload = ProtoField.bytes("ksp.payload", "Encrypted Payload")
local f_auth_tag = ProtoField.bytes("ksp.auth_tag", "Authentication Tag")

-- Handshake-specific fields
local f_num_versions = ProtoField.uint8("ksp.hello.num_versions", "Number of Versions", base.DEC)
local f_capabilities = ProtoField.uint32("ksp.hello.capabilities", "Capabilities", base.HEX)
local f_client_random = ProtoField.bytes("ksp.hello.client_random", "Client Random")
local f_server_random = ProtoField.bytes("ksp.hello.server_random", "Server Random")
local f_ephemeral_key = ProtoField.bytes("ksp.hello.ephemeral_key", "Ephemeral Public Key")

-- Register all fields
ksp_proto.fields = {
    f_version, f_version_major, f_version_minor,
    f_type,
    f_flags, f_flag_compressed, f_flag_encrypted, f_flag_fragmented,
    f_flag_end_stream, f_flag_ack, f_flag_priority, f_flag_padded,
    f_payload_length,
    f_session_id, f_session_id_str,
    f_stream_id,
    f_sequence,
    f_nonce,
    f_payload,
    f_auth_tag,
    f_num_versions, f_capabilities,
    f_client_random, f_server_random,
    f_ephemeral_key,
}

-- ═══════════════════════════════════════════════════════════════
-- Color Filters (applied via Wireshark coloring rules)
-- ═══════════════════════════════════════════════════════════════

-- Packet type categories for coloring
local function get_packet_category(ptype)
    if ptype >= 0x01 and ptype <= 0x07 then
        return "Handshake"
    elseif ptype >= 0x10 and ptype <= 0x11 then
        return "Data"
    elseif ptype >= 0x20 and ptype <= 0x23 then
        return "Stream"
    elseif ptype >= 0x30 and ptype <= 0x33 then
        return "Control"
    elseif ptype >= 0x40 and ptype <= 0x41 then
        return "Session"
    elseif ptype == 0xFF then
        return "Error"
    else
        return "Unknown"
    end
end

-- Format a 16-byte buffer as a UUID string
local function bytes_to_uuid(buf, offset)
    if buf:len() < offset + 16 then
        return "invalid"
    end

    local hex = ""
    for i = 0, 15 do
        hex = hex .. string.format("%02x", buf(offset + i, 1):uint())
    end

    return string.format("%s-%s-%s-%s-%s",
        string.sub(hex, 1, 8),
        string.sub(hex, 9, 12),
        string.sub(hex, 13, 16),
        string.sub(hex, 17, 20),
        string.sub(hex, 21, 32))
end

-- ═══════════════════════════════════════════════════════════════
-- Dissector Function
-- ═══════════════════════════════════════════════════════════════

function ksp_proto.dissector(tvb, pinfo, tree)
    -- Minimum header size is 48 bytes
    if tvb:len() < 48 then
        return 0
    end

    -- Set protocol column
    pinfo.cols.protocol:set("KSP")

    -- Create protocol tree
    local subtree = tree:add(ksp_proto, tvb(), "Kush Secure Protocol")

    -- ─── Parse Header ───────────────────────────────────────────

    -- Version (1 byte)
    local version_byte = tvb(0, 1):uint()
    local version_major = bit.rshift(version_byte, 4)
    local version_minor = bit.band(version_byte, 0x0F)
    local version_tree = subtree:add(f_version, tvb(0, 1))
    version_tree:add(f_version_major, version_major)
    version_tree:add(f_version_minor, version_minor)
    version_tree:append_text(string.format(" (v%d.%d)", version_major, version_minor))

    -- Packet Type (1 byte)
    local ptype = tvb(1, 1):uint()
    subtree:add(f_type, tvb(1, 1))

    -- Set info column
    local category = get_packet_category(ptype)
    local type_name = ""
    local type_names = {
        [0x01] = "ClientHello", [0x02] = "ServerHello", [0x03] = "KeyExchange",
        [0x04] = "Certificate", [0x05] = "AuthRequest", [0x06] = "AuthResponse",
        [0x07] = "HandshakeFinish", [0x10] = "Data", [0x11] = "DataAck",
        [0x20] = "StreamOpen", [0x21] = "StreamData", [0x22] = "StreamClose",
        [0x23] = "StreamReset", [0x30] = "KeepAlive", [0x31] = "KeepAliveAck",
        [0x32] = "WindowUpdate", [0x33] = "GoAway",
        [0x40] = "SessionResume", [0x41] = "SessionTicket", [0xFF] = "Error",
    }
    type_name = type_names[ptype] or string.format("Unknown(0x%02X)", ptype)
    pinfo.cols.info:set(string.format("KSP %s [%s]", type_name, category))

    -- Flags (2 bytes)
    local flags_val = tvb(2, 2):uint()
    local flags_tree = subtree:add(f_flags, tvb(2, 2))
    flags_tree:add(f_flag_compressed, tvb(2, 2))
    flags_tree:add(f_flag_encrypted, tvb(2, 2))
    flags_tree:add(f_flag_fragmented, tvb(2, 2))
    flags_tree:add(f_flag_end_stream, tvb(2, 2))
    flags_tree:add(f_flag_ack, tvb(2, 2))
    flags_tree:add(f_flag_priority, tvb(2, 2))
    flags_tree:add(f_flag_padded, tvb(2, 2))

    -- Payload Length (4 bytes)
    local payload_length = tvb(4, 4):uint()
    subtree:add(f_payload_length, tvb(4, 4))

    -- Session ID (16 bytes)
    subtree:add(f_session_id, tvb(8, 16))
    local uuid_str = bytes_to_uuid(tvb, 8)
    subtree:add(f_session_id_str, uuid_str):set_generated(true)

    -- Stream ID (4 bytes)
    local stream_id = tvb(24, 4):uint()
    subtree:add(f_stream_id, tvb(24, 4))

    -- Sequence Number (8 bytes)
    subtree:add(f_sequence, tvb(28, 8))

    -- Nonce (12 bytes)
    subtree:add(f_nonce, tvb(36, 12))

    -- ─── Parse Payload ──────────────────────────────────────────

    local offset = 48
    local is_encrypted = bit.band(flags_val, 0x0002) ~= 0
    local tag_size = 0
    if is_encrypted then
        tag_size = 16
    end

    -- Check we have enough data
    if tvb:len() < offset + payload_length + tag_size then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated KSP packet")
        return offset
    end

    -- Payload
    if payload_length > 0 then
        local payload_tree
        if is_encrypted then
            payload_tree = subtree:add(f_payload, tvb(offset, payload_length))
            payload_tree:append_text(string.format(" (%d bytes, encrypted)", payload_length))
        else
            payload_tree = subtree:add(f_payload, tvb(offset, payload_length))
            payload_tree:append_text(string.format(" (%d bytes, plaintext)", payload_length))

            -- For handshake messages, try to dissect the payload
            if ptype == 0x01 then
                dissect_client_hello(tvb, offset, payload_length, payload_tree)
            end
        end
    end
    offset = offset + payload_length

    -- Authentication Tag
    if is_encrypted and tvb:len() >= offset + 16 then
        subtree:add(f_auth_tag, tvb(offset, 16))
        offset = offset + 16
    end

    -- Add stream info to info column
    if stream_id > 0 then
        pinfo.cols.info:append(string.format(" stream=%d", stream_id))
    end

    -- Add payload size to info column
    if payload_length > 0 then
        pinfo.cols.info:append(string.format(" len=%d", payload_length))
    end

    return offset
end

-- ═══════════════════════════════════════════════════════════════
-- Handshake Sub-Dissectors
-- ═══════════════════════════════════════════════════════════════

function dissect_client_hello(tvb, offset, length, tree)
    if length < 1 then return end

    local pos = offset

    -- Number of versions
    local num_versions = tvb(pos, 1):uint()
    tree:add(f_num_versions, tvb(pos, 1))
    pos = pos + 1

    -- Versions
    for i = 1, num_versions do
        if pos >= offset + length then break end
        local v = tvb(pos, 1):uint()
        local major = bit.rshift(v, 4)
        local minor = bit.band(v, 0x0F)
        tree:add(f_version, tvb(pos, 1)):append_text(
            string.format(" (v%d.%d)", major, minor))
        pos = pos + 1
    end

    -- Capabilities
    if pos + 4 <= offset + length then
        tree:add(f_capabilities, tvb(pos, 4))
        pos = pos + 4
    end

    -- Client Random
    if pos + 32 <= offset + length then
        tree:add(f_client_random, tvb(pos, 32))
        pos = pos + 32
    end

    -- Ephemeral Public Key
    if pos + 32 <= offset + length then
        tree:add(f_ephemeral_key, tvb(pos, 32))
    end
end

-- ═══════════════════════════════════════════════════════════════
-- Register on TCP port 9876
-- ═══════════════════════════════════════════════════════════════

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(9876, ksp_proto)

-- Also register for "Decode As..." support
ksp_proto:register_heuristic("tcp", function(tvb, pinfo, tree)
    if tvb:len() < 48 then return false end

    -- Check version byte looks valid (0x10 = v1.0)
    local version = tvb(0, 1):uint()
    if version ~= 0x10 then return false end

    -- Check packet type is known
    local ptype = tvb(1, 1):uint()
    local known_types = {
        [0x01]=true, [0x02]=true, [0x03]=true, [0x04]=true,
        [0x05]=true, [0x06]=true, [0x07]=true,
        [0x10]=true, [0x11]=true,
        [0x20]=true, [0x21]=true, [0x22]=true, [0x23]=true,
        [0x30]=true, [0x31]=true, [0x32]=true, [0x33]=true,
        [0x40]=true, [0x41]=true,
        [0xFF]=true,
    }
    if not known_types[ptype] then return false end

    ksp_proto.dissector(tvb, pinfo, tree)
    return true
end)
