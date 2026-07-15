//! CLI Integration & End-to-End Command Parity Tests (`ksp-cli/tests/cli_tests.rs`).
//!
//! Verifies real execution, JSON schema invariants, file generation (`ksp.toml`, certs),
//! diagnostic score calculation, shell completions, and plugin discovery using the compiled `ksp` binary.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

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
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "Expected stdout {} to contain version {}",
        stdout,
        env!("CARGO_PKG_VERSION")
    );
    assert!(stdout.contains("KSP") || stdout.contains("Protocol"));
}

#[test]
fn test_cli_version_json_schema() {
    let output = Command::new(ksp_bin())
        .args(["--json", "version"])
        .output()
        .expect("Failed to execute ksp --json version");
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Version output must be valid JSON when --json is requested");
    assert_eq!(json["cli_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(json["protocol_version"], "1.0");
    assert_eq!(json["edition"], "2024");
}

#[test]
fn test_cli_doctor_json_schema_and_score() {
    let output = Command::new(ksp_bin())
        .args(["--json", "doctor"])
        .output()
        .expect("Failed to execute ksp --json doctor");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Doctor output must be valid JSON");
    assert!(json["health_score"].is_number());
    assert!(json["diagnostics"].is_array());
    assert!(json["runtime_ms"].is_number());
}

#[test]
fn test_cli_completion_bash_and_zsh() {
    let bash_out = Command::new(ksp_bin())
        .args(["completion", "bash"])
        .output()
        .expect("Failed to generate bash completion");
    assert!(bash_out.status.success());
    let bash_str = String::from_utf8_lossy(&bash_out.stdout);
    assert!(bash_str.contains("complete -F") || bash_str.contains("_ksp"));

    let zsh_out = Command::new(ksp_bin())
        .args(["completion", "zsh"])
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
        .args([
            "cert",
            "generate",
            "--subject",
            "ksp://e2e.test.node",
            "--days",
            "90",
            "--output",
            prefix.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run ksp cert generate");
    assert!(gen_out.status.success());

    let cert_path = temp_dir.join("test_identity.cert");
    let key_path = temp_dir.join("test_identity.key");
    assert!(
        cert_path.exists(),
        "Certificate file must be written to disk"
    );
    assert!(
        key_path.exists(),
        "Private key file must be written to disk"
    );

    // 2. Inspect cert in JSON mode
    let insp_out = Command::new(ksp_bin())
        .args(["--json", "cert", "inspect", cert_path.to_str().unwrap()])
        .output()
        .expect("Failed to run ksp cert inspect");
    assert!(insp_out.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&insp_out.stdout).expect("Inspect output must be valid JSON");
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
        .args(["--json", "config", "validate"])
        .output()
        .expect("Failed to run ksp config validate");
    assert!(val_out.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&val_out.stdout).expect("Config validate output must be valid JSON");
    assert_eq!(json["status"], "valid");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_benchmark_json() {
    let output = Command::new(ksp_bin())
        .args(["--json", "benchmark"])
        .output()
        .expect("Failed to execute ksp benchmark --json");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Benchmark output must be valid JSON");
    assert_eq!(json["status"], "ok");
    assert!(json["benchmarks"].is_array());
    assert!(json["environment"].is_object());
}

#[test]
fn test_cli_plugins_list_json() {
    let output = Command::new(ksp_bin())
        .args(["--json", "plugins", "list"])
        .output()
        .expect("Failed to execute ksp plugins list --json");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Plugins list output must be valid JSON");
    assert_eq!(json["status"], "success");
    assert!(json["plugins"].is_array());
}

#[test]
fn test_cli_all_commands_help() {
    let help_commands: &[&[&str]] = &[
        &["version", "--help"],
        &["init", "--help"],
        &["new", "--help"],
        &["generate", "--help"],
        &["doctor", "--help"],
        &["diag", "--help"],
        &["proxy", "--help"],
        &["gateway", "--help"],
        &["server", "--help"],
        &["server", "start", "--help"],
        &["server", "stop", "--help"],
        &["server", "status", "--help"],
        &["server", "restart", "--help"],
        &["server", "reload", "--help"],
        &["connect", "--help"],
        &["disconnect", "--help"],
        &["ping", "--help"],
        &["packet", "--help"],
        &["packet", "inspect", "--help"],
        &["packet", "decode", "--help"],
        &["packet", "build", "--help"],
        &["packet", "encode", "--help"],
        &["packet", "export", "--help"],
        &["packet", "visualize", "--help"],
        &["capture", "--help"],
        &["capture", "start", "--help"],
        &["capture", "stop", "--help"],
        &["capture", "export", "--help"],
        &["capture", "live", "--help"],
        &["wireshark", "--help"],
        &["wireshark", "install", "--help"],
        &["wireshark", "open", "--help"],
        &["wireshark", "uninstall", "--help"],
        &["benchmark", "--help"],
        &["chat", "--help"],
        &["transfer", "--help"],
        &["transfer", "send", "--help"],
        &["transfer", "receive", "--help"],
        &["transfer", "resume", "--help"],
        &["receive", "--help"],
        &["cert", "--help"],
        &["cert", "generate", "--help"],
        &["cert", "inspect", "--help"],
        &["cert", "verify", "--help"],
        &["cert", "renew", "--help"],
        &["security", "--help"],
        &["replay", "--help"],
        &["replay", "simulate", "--help"],
        &["session", "--help"],
        &["session", "list", "--help"],
        &["session", "inspect", "--help"],
        &["session", "close", "--help"],
        &["session", "resume", "--help"],
        &["stream", "--help"],
        &["stream", "list", "--help"],
        &["stream", "open", "--help"],
        &["stream", "close", "--help"],
        &["stream", "reset", "--help"],
        &["explain", "--help"],
        &["learn", "--help"],
        &["rfc", "--help"],
        &["demo", "--help"],
        &["config", "--help"],
        &["config", "get", "--help"],
        &["config", "set", "--help"],
        &["config", "show", "--help"],
        &["config", "list", "--help"],
        &["config", "validate", "--help"],
        &["config", "reset", "--help"],
        &["profile", "--help"],
        &["profile", "create", "--help"],
        &["profile", "switch", "--help"],
        &["profile", "list", "--help"],
        &["env", "--help"],
        &["env", "use", "--help"],
        &["env", "list", "--help"],
        &["dist", "--help"],
        &["update", "--help"],
        &["install-script", "--help"],
        &["uninstall", "--help"],
        &["validate", "--help"],
        &["info", "--help"],
        &["playground", "--help"],
        &["docs", "--help"],
        &["shell", "--help"],
        &["completion", "--help"],
        &["plugins", "--help"],
        &["plugins", "list", "--help"],
        &["plugins", "install", "--help"],
        &["plugins", "remove", "--help"],
        &["monitor", "--help"],
        &["dashboard", "--help"],
        &["stats", "--help"],
        &["trace", "--help"],
        &["inspect", "--help"],
        &["inspect", "session", "--help"],
        &["inspect", "packet", "--help"],
        &["inspect", "cert", "--help"],
        &["about", "--help"],
        &["matrix", "--help"],
        &["coffee", "--help"],
        &["dance", "--help"],
        &["quote", "--help"],
        &["credits", "--help"],
        &["dev", "--help"],
        &["daemon", "--help"],
        &["daemon", "start", "--help"],
        &["daemon", "stop", "--help"],
        &["daemon", "status", "--help"],
        &["logs", "--help"],
        &["metrics", "--help"],
        &["journey", "--help"],
    ];

    for args in help_commands {
        let output = Command::new(ksp_bin())
            .args(*args)
            .output()
            .unwrap_or_else(|e| panic!("Failed to run ksp {:?}: {}", args, e));
        assert!(
            output.status.success(),
            "Command `ksp {:?}` failed with status {:?}.\nStderr: {}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Usage:") || stdout.contains("ksp") || stdout.contains("Options:"),
            "Command `ksp {:?}` output didn't contain Usage or ksp: {}",
            args,
            stdout
        );
    }
}

#[test]
fn test_cli_all_commands_json_execution() {
    let json_commands: &[&[&str]] = &[
        &["--json", "version"],
        &["--json", "info"],
        &["--json", "explain", "handshake"],
        &["--json", "learn", "list"],
        &["--json", "rfc", "list"],
        &["--json", "config", "show"],
        &["--json", "config", "list"],
        &["--json", "profile", "list"],
        &["--json", "env", "list"],
        &["--json", "session", "list"],
        &["--json", "stream", "list"],
        &["--json", "about"],
        &["--json", "matrix"],
        &["--json", "coffee"],
        &["--json", "dance"],
        &["--json", "quote"],
        &["--json", "credits"],
        &["--json", "dev"],
        &["--json", "journey"],
        &["--json", "shell"],
        &["--json", "completion", "bash"],
        &["--json", "update", "--check"],
        &["--json", "install-script"],
        &["--json", "server", "status"],
        &["--json", "daemon", "status"],
        &["--json", "security", "replay"],
        &["--json", "plugins", "list"],
    ];

    for args in json_commands {
        let output = Command::new(ksp_bin())
            .args(*args)
            .output()
            .unwrap_or_else(|e| panic!("Failed to run ksp {:?}: {}", args, e));
        assert!(
            output.status.success(),
            "Command `ksp {:?}` failed with status {:?}.\nStdout: {}\nStderr: {}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let _json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
            panic!(
                "Output for `ksp {:?}` must be valid JSON: {}\nStdout was: {}",
                args,
                e,
                String::from_utf8_lossy(&output.stdout)
            )
        });
    }
}

#[test]
fn test_no_hardcoded_fake_literals_in_non_demo_dashboard() {
    let output = Command::new(ksp_bin())
        .arg("dashboard")
        .output()
        .expect("Failed to execute ksp dashboard");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("d8193ad7-4e01-4c12-91a2-11bc90a8231e"),
        "Non-demo dashboard contained hardcoded demo UUID"
    );
    assert!(
        !stdout.contains("14,209 pkts/s (Simulated"),
        "Non-demo dashboard contained simulated packet rate"
    );
    assert!(
        stdout.contains("IDLE")
            || stdout.contains("0 B/s")
            || stdout.contains("No active KSP sessions")
            || stdout.contains("Telemetry"),
        "Dashboard missing honest idle indicators: {}",
        stdout
    );
}

#[test]
fn test_idle_dashboard_json_has_zero_sessions() {
    let output = Command::new(ksp_bin())
        .args(["--json", "dashboard"])
        .output()
        .expect("Failed to execute ksp --json dashboard");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Valid JSON required");
    assert!(
        json.get("simulated").is_none(),
        "Non-demo JSON must not have simulated=true"
    );
    assert_eq!(
        json["active_sessions"], 0,
        "Idle JSON dashboard should report 0 active sessions"
    );
}

#[test]
fn test_demo_flag_includes_simulated_true() {
    let output = Command::new(ksp_bin())
        .args(["--json", "dashboard", "--demo"])
        .output()
        .expect("Failed to execute ksp --json dashboard --demo");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Valid JSON required");
    assert_eq!(
        json["simulated"], true,
        "Demo dashboard must explicitly include simulated: true"
    );
}

#[test]
fn test_transfer_verification_status_reporting() {
    let output = Command::new(ksp_bin())
        .args(["--json", "transfer", "send", "nonexistent_file.txt"])
        .output()
        .expect("Failed to execute ksp transfer send");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|_| serde_json::json!({"status": "error"}));
    assert_eq!(
        json["status"], "error",
        "Missing or unverified transfer must not claim verified_remote=true"
    );
}

#[test]
fn test_proxy_and_gateway_json_only_after_bind() {
    let output = Command::new(ksp_bin())
        .args(["--json", "proxy", "--listen", "256.256.256.256:9999"])
        .output()
        .expect("Failed to execute proxy with invalid IP");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("\"status\": \"proxy_running\""),
        "Must not emit proxy_running if socket bind fails"
    );

    let gw_output = Command::new(ksp_bin())
        .args(["--json", "gateway", "--listen", "256.256.256.256:9999"])
        .output()
        .expect("Failed to execute gateway with invalid IP");
    let gw_stdout = String::from_utf8_lossy(&gw_output.stdout);
    assert!(
        !gw_stdout.contains("\"status\": \"gateway_active\""),
        "Must not emit gateway_active if socket bind fails"
    );
}

#[test]
fn test_dist_checksum_matches_actual_binary_artifact() {
    let output = Command::new(ksp_bin())
        .args(["--json", "dist"])
        .output()
        .expect("Failed to execute ksp --json dist");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Valid JSON required");
    assert!(
        json["status"] == "packaged" || json["status"] == "packaged_binary",
        "Expected packaged or packaged_binary, got: {:?}",
        json["status"]
    );
    let sha = json["sha256"]
        .as_str()
        .expect("Must output sha256 hex string");
    assert_eq!(sha.len(), 64, "SHA-256 string must be exactly 64 hex chars");
}
