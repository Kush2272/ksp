//! KSP CLI command modules.

pub mod init;
pub mod version;
pub mod doctor;
pub mod server;
pub mod connect;
pub mod ping;
pub mod packet;
pub mod benchmark;
pub mod chat;
pub mod transfer;
pub mod cert;
pub mod session;
pub mod stream;
pub mod playground;
pub mod docs;
pub mod explain;
pub mod demo;
pub mod new_project;
pub mod config_cmd;
pub mod validate;
pub mod info;
pub mod stats;
pub mod trace;
pub mod easter_eggs;
pub mod generate;
pub mod profile;
pub mod env;
pub mod capture;
pub mod wireshark;
pub mod security;
pub mod learn;
pub mod dashboard;
pub mod shell;
pub mod diag;
pub mod proxy;
pub mod dist;
pub mod telemetry;
pub mod daemon;
pub mod logs;
pub mod metrics;
pub mod completion;
pub mod plugins;

/// Set secure file permissions (0600 on POSIX systems) for private key files.
pub fn set_secure_key_permissions(_path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(_path, perms);
        }
    }
}













