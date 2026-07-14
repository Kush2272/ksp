//! CLI Integration & End-to-End Command Parity Tests (`ksp-cli/tests/cli_tests.rs`).
//!
//! Verifies real execution, JSON schema invariants, file generation (`ksp.toml`, certs),
//! diagnostic score calculation, shell completions, and plugin discovery using the compiled `ksp` binary.

use std::process::Command;
use std::path::PathBuf;
use std::fs;

fn ksp_bin() -> PathBuf {
    let p = PathBuf::from(env!("CARGO_BIN_EXE_ksp"));
    if p.exists() {
        return p.canonicalize().unwrap_or(p);
    }
    let p_exe = PathBuf::from(format!("{}.exe", env!("CARGO_BIN_EXE_ksp")));
    if p_exe.exists() {
        return p_exe.canonicalize().unwrap_or(p_exe);
    }
    let mut root = std::env::current_dir().unwrap();
    while !root.join("Cargo.toml").exists() && root.pop() {}
    let candidate = root.join("target").join("debug").join("ksp.exe");
    if candidate.exists() {
        return candidate.canonicalize().unwrap_or(candidate);
    }
    p
}

#[test]
fn test_cli_version_output() {
    let output = Command::new(ksp_bin())
        .arg("version")
        .output()
        .expect("Failed to execute ksp version");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("0.1.0"));
    assert!(stdout.contains("KSP v1.0") || stdout.contains("Protocol"));
}

#[test]
fn test_cli_version_json_schema() {
    let output = Command::new(ksp_bin())
        .args(&["--json", "version"])
        .output()
        .expect("Failed to execute ksp --json version");
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Version output must be valid JSON when --json is requested");
    assert_eq!(json["cli_version"], "0.1.0");
    assert_eq!(json["protocol_version"], "1.0");
    assert_eq!(json["edition"], "2024");
}

#[test]
fn test_cli_doctor_json_schema_and_score() {
    let output = Command::new(ksp_bin())
        .args(&["--json", "doctor"])
        .output()
        .expect("Failed to execute ksp --json doctor");
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Doctor output must be valid JSON");
    assert!(json["health_score"].is_number());
    assert!(json["diagnostics"].is_array());
    assert!(json["runtime_ms"].is_number());
}

#[test]
fn test_cli_completion_bash_and_zsh() {
    let bash_out = Command::new(ksp_bin())
        .args(&["completion", "bash"])
        .output()
        .expect("Failed to generate bash completion");
    assert!(bash_out.status.success());
    let bash_str = String::from_utf8_lossy(&bash_out.stdout);
    assert!(bash_str.contains("complete -F") || bash_str.contains("_ksp"));

    let zsh_out = Command::new(ksp_bin())
        .args(&["completion", "zsh"])
        .output()
        .expect("Failed to generate zsh completion");
    assert!(zsh_out.status.success());
    let zsh_str = String::from_utf8_lossy(&zsh_out.stdout);
    assert!(zsh_str.contains("#compdef ksp"));
}

#[test]
fn test_cli_cert_generate_and_inspect_e2e() {
    let temp_dir = std::env::temp_dir().join("ksp_cli_test_cert_e2e");
    let _ = fs::create_dir_all(&temp_dir);
    let prefix = temp_dir.join("test_identity");

    // 1. Generate cert
    let gen_out = Command::new(ksp_bin())
        .args(&[
            "cert", "generate",
            "--subject", "ksp://e2e.test.node",
            "--days", "90",
            "--output", prefix.to_str().unwrap()
        ])
        .output()
        .expect("Failed to run ksp cert generate");
    assert!(gen_out.status.success());

    let cert_path = temp_dir.join("test_identity.cert");
    let key_path = temp_dir.join("test_identity.key");
    assert!(cert_path.exists(), "Certificate file must be written to disk");
    assert!(key_path.exists(), "Private key file must be written to disk");

    // 2. Inspect cert in JSON mode
    let insp_out = Command::new(ksp_bin())
        .args(&["--json", "cert", "inspect", cert_path.to_str().unwrap()])
        .output()
        .expect("Failed to run ksp cert inspect");
    assert!(insp_out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&insp_out.stdout)
        .expect("Inspect output must be valid JSON");
    assert_eq!(json["subject"], "ksp://e2e.test.node");
    assert_eq!(json["expired"], false);
    assert!(json["not_after"].is_number());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_init_and_config_validate() {
    let temp_dir = std::env::temp_dir().join("ksp_cli_test_config_e2e");
    let _ = fs::create_dir_all(&temp_dir);

    // Run init inside temp_dir
    let init_out = Command::new(ksp_bin())
        .current_dir(&temp_dir)
        .arg("init")
        .output()
        .expect("Failed to run ksp init");
    assert!(init_out.status.success());
    let config_file = temp_dir.join("ksp.toml");
    assert!(config_file.exists());

    // Validate config inside temp_dir
    let val_out = Command::new(ksp_bin())
        .current_dir(&temp_dir)
        .args(&["--json", "config", "validate"])
        .output()
        .expect("Failed to run ksp config validate");
    assert!(val_out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&val_out.stdout)
        .expect("Config validate output must be valid JSON");
    assert_eq!(json["status"], "valid");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_benchmark_json() {
    let output = Command::new(ksp_bin())
        .args(&["--json", "benchmark"])
        .output()
        .expect("Failed to execute ksp benchmark --json");
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Benchmark output must be valid JSON");
    assert!(json["aes_256_gcm_mbps"].is_number());
    assert!(json["chacha20_mbps"].is_number());
    assert!(json["handshake_ns"].is_number());
}

#[test]
fn test_cli_plugins_list_json() {
    let output = Command::new(ksp_bin())
        .args(&["--json", "plugins", "list"])
        .output()
        .expect("Failed to execute ksp plugins list --json");
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Plugins list output must be valid JSON");
    assert_eq!(json["status"], "success");
    assert!(json["plugins"].is_array());
}
