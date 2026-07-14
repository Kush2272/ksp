//! KSP CLI command modules.

pub mod benchmark;
pub mod capture;
pub mod cert;
pub mod chat;
pub mod completion;
pub mod config_cmd;
pub mod connect;
pub mod daemon;
pub mod dashboard;
pub mod demo;
pub mod diag;
pub mod dist;
pub mod docs;
pub mod doctor;
pub mod easter_eggs;
pub mod env;
pub mod explain;
pub mod generate;
pub mod info;
pub mod init;
pub mod learn;
pub mod logs;
pub mod metrics;
pub mod new_project;
pub mod packet;
pub mod ping;
pub mod playground;
pub mod plugins;
pub mod profile;
pub mod proxy;
pub mod security;
pub mod server;
pub mod session;
pub mod shell;
pub mod stats;
pub mod stream;
pub mod telemetry;
pub mod trace;
pub mod transfer;
pub mod validate;
pub mod version;
pub mod wireshark;

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
