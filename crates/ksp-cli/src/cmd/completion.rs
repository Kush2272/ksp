//! `ksp completion <shell>` — Generate real shell completion scripts (`bash`, `zsh`, `fish`, `powershell`, `elvish`).

use crate::ui;
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use colored::Colorize;
use std::io;

pub fn run(shell_str: &str, json: bool) {
    let shell = match shell_str.to_lowercase().as_str() {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "powershell" | "ps" | "pwsh" => Shell::PowerShell,
        "elvish" => Shell::Elvish,
        _ => {
            if json {
                ui::json_output(&serde_json::json!({
                    "status": "error",
                    "message": format!("Unsupported shell: '{}'. Supported: bash, zsh, fish, powershell, elvish", shell_str)
                }));
            } else {
                ui::failure(&format!("Unsupported shell: '{}'", shell_str.white().bold()));
                println!("  Supported shells: bash, zsh, fish, powershell, elvish");
                println!("  Example usage: `ksp completion zsh > ~/.zfunc/_ksp`\n");
            }
            return;
        }
    };

    if json {
        let mut buf = Vec::new();
        let mut cmd = crate::Cli::command();
        generate(shell, &mut cmd, "ksp", &mut buf);
        let script = String::from_utf8_lossy(&buf);
        ui::json_output(&serde_json::json!({
            "status": "generated",
            "shell": shell_str.to_lowercase(),
            "script_length_bytes": script.len(),
            "script": script.to_string()
        }));
        return;
    }

    // Generate directly to stdout for shell redirection (`source <(ksp completion zsh)` etc.)
    let mut cmd = crate::Cli::command();
    generate(shell, &mut cmd, "ksp", &mut io::stdout());
}
