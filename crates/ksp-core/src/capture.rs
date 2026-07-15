//! PCAP 2.4 application-layer capture hook for KSP traffic.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Standard PCAP 2.4 Global Header (24 bytes, Little-Endian)
/// Magic: 0xa1b2c3d4 | Version: 2.4 | Snaplen: 65535 | Link-type: 147 (USER0 / Custom Protocol)
pub const PCAP_GLOBAL_HEADER: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, // Magic number (0xa1b2c3d4)
    0x02, 0x00, // Major version 2
    0x04, 0x00, // Minor version 4
    0x00, 0x00, 0x00, 0x00, // Thiszone
    0x00, 0x00, 0x00, 0x00, // Sigfigs
    0xff, 0xff, 0x00, 0x00, // Snaplen (65535)
    0x93, 0x00, 0x00, 0x00, // Network / DLT (147 = USER0)
];

pub fn get_capture_file() -> PathBuf {
    std::env::temp_dir().join("ksp_capture.pcap")
}

pub fn get_capture_pid_file() -> PathBuf {
    std::env::temp_dir().join("ksp_capture.pid")
}

pub fn is_capture_active() -> bool {
    get_capture_pid_file().exists()
}

/// Append a KSP packet with a 16-byte PCAP Packet Header to the PCAP file.
pub fn append_packet_to_pcap(packet_bytes: &[u8]) -> std::io::Result<()> {
    let pcap_path = get_capture_file();
    if !pcap_path.exists() {
        fs::write(&pcap_path, PCAP_GLOBAL_HEADER)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(pcap_path)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ts_sec = now.as_secs() as u32;
    let ts_usec = now.subsec_micros();
    let incl_len = packet_bytes.len() as u32;
    let orig_len = incl_len;

    file.write_all(&ts_sec.to_le_bytes())?;
    file.write_all(&ts_usec.to_le_bytes())?;
    file.write_all(&incl_len.to_le_bytes())?;
    file.write_all(&orig_len.to_le_bytes())?;
    file.write_all(packet_bytes)?;
    file.flush()?;
    Ok(())
}

/// Automatically record a KSP packet frame to the global PCAP file if the capture hook is active.
pub fn record_pcap_if_active(packet_bytes: &[u8]) {
    if is_capture_active() {
        let _ = append_packet_to_pcap(packet_bytes);
    }
}
