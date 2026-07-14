//! # KSP CLI — Unified Command-Line Interface
//!
//! The `ksp` binary provides a cohesive developer experience for the
//! Kush Secure Protocol. Every command supports `--json` for machine-readable
//! output and `-v`/`-vv`/`-vvv` for progressive verbosity.

mod ui;
mod config;
mod cmd;

use clap::{Parser, Subcommand};

/// ═══════════════════════════════════════════════════════════════
/// KSP CLI — Kush Secure Protocol
/// Experimental Secure Application Protocol
/// ═══════════════════════════════════════════════════════════════
#[derive(Parser)]
#[command(
    name = "ksp",
    version,
    about = "KSP CLI — Kush Secure Protocol",
    long_about = "Unified CLI for the Kush Secure Protocol.\n\nKSP is an experimental secure application protocol featuring\nX25519 key exchange, AES-256-GCM/ChaCha20-Poly1305 encryption,\nEd25519 certificates, stream multiplexing, and replay protection.\n\nhttps://www.kspprotocol.dev",
    after_help = "Examples:\n  ksp init                         Initialize a KSP project\n  ksp server start --port 9876     Start the server\n  ksp ping 127.0.0.1:9876          Ping a server\n  ksp connect 127.0.0.1:9876       Interactive session\n  ksp benchmark                    Run crypto benchmarks\n  ksp demo                         Full protocol walkthrough\n  ksp explain handshake            Learn about the handshake\n\nDocs: https://www.kspprotocol.dev/docs"
)]
struct Cli {
    /// Output structured JSON instead of pretty text.
    #[arg(long, global = true)]
    json: bool,

    /// Increase verbosity (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show version information.
    Version,

    /// Initialize a KSP project in the current directory.
    Init,

    /// Create a new KSP project from template.
    New {
        /// Project name.
        name: String,
    },

    /// Generate boilerplate files (config, cert, server, client, packet).
    Generate {
        /// Target resource: config, cert, server, client, packet.
        target: String,
    },

    /// System health check and diagnostics.

    Doctor {
        /// Automatically fix common issues.
        #[arg(long)]
        fix: bool,
    },

    /// Dump deep system diagnostics and troubleshooting reports (`ksp diag`).
    Diag {
        /// Write report to `ksp_diag_report.txt`.
        #[arg(long)]
        dump: bool,
    },

    /// KSP L4/L7 proxy relay (`ksp proxy`).
    Proxy {
        /// Listen address (e.g. `0.0.0.0:9876`).
        #[arg(long, default_value = "0.0.0.0:9876")]
        listen: String,
        /// Upstream target address (e.g. `127.0.0.1:9877`).
        #[arg(long)]
        upstream: String,
    },

    /// KSP-to-HTTP/WebSockets reverse proxy gateway (`ksp gateway`).
    Gateway {
        /// KSP listen address (`0.0.0.0:9876`).
        #[arg(long, default_value = "0.0.0.0:9876")]
        listen: String,
        /// Upstream HTTP backend target (`http://127.0.0.1:3000`).
        #[arg(long)]
        target_http: String,
    },


    /// Manage the KSP server.
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },

    /// Connect to a KSP server interactively.
    Connect {
        /// Server address (e.g., 127.0.0.1:9876).
        address: String,
    },

    /// Disconnect active KSP connection and clear session state.
    Disconnect,


    /// Ping a KSP server (handshake + RTT measurement).
    Ping {
        /// Server address (e.g., 127.0.0.1:9876).
        address: String,
    },

    /// Packet developer tools.
    Packet {
        #[command(subcommand)]
        action: PacketAction,
    },

    /// Live packet capture & PCAP tools (`start`, `stop`, `export`, `live`).
    Capture {
        #[command(subcommand)]
        action: CaptureAction,
    },

    /// Wireshark Lua Dissector plugin management (`install`, `open`, `uninstall`).
    Wireshark {
        #[command(subcommand)]
        action: WiresharkAction,
    },


    /// Run cryptographic benchmarks.
    Benchmark {
        /// Include 100K packet stress test.
        #[arg(long)]
        stress: bool,
        /// Export benchmark results to CSV table format.
        #[arg(long)]
        csv: bool,
        /// Export benchmark results to Markdown table format (`--markdown`).
        #[arg(long)]
        markdown: bool,
    },

    /// Encrypted chat over KSP (`ksp chat`, `ksp chat new`, `ksp chat 127.0.0.1:9876`).
    Chat {
        /// Server address or mode (`default`, `new`/`start` for local server, or `IP:PORT`).
        #[arg(default_value = "default")]
        address: String,
    },

    /// File transfer over KSP (`send`, `receive`, `resume`).
    Transfer {
        #[command(subcommand)]
        action: TransferAction,
    },

    /// Receive incoming file transfer (`ksp receive --port 9888 --output rec.dat`).
    Receive {
        /// Listen port (`9888`).
        #[arg(long, default_value = "9888")]
        port: u16,
        /// Output path for received file (`rec.dat`).
        #[arg(long)]
        output: Option<String>,
    },

    /// Certificate management (`generate`, `inspect`, `verify`, `renew`).
    Cert {
        #[command(subcommand)]
        action: CertAction,
    },

    /// Run educational security attack simulations (`replay`, `mitm`, `nonce`, `downgrade`, `corruption`).
    Security {
        /// Attack type (`replay`, `mitm`, `nonce`, `downgrade`, `corruption`).
        attack: String,
    },

    /// Replay protection tools (`simulate`).
    Replay {
        #[command(subcommand)]
        action: ReplayAction,
    },

    /// Session management.

    Session {
        #[command(subcommand)]
        action: SessionAction,
    },

    /// Stream management.
    Stream {
        #[command(subcommand)]
        action: StreamAction,
    },

    /// Explain a KSP protocol concept.
    Explain {
        /// Topic: handshake, replay, aead, certificate, kdf, nonce, streams, flow-control, packet.
        topic: String,
    },

    /// Interactive educational lessons on KSP concepts (`handshake`, `replay`, `aead`, etc).
    Learn {
        /// Topic or `list`.
        #[arg(default_value = "list")]
        topic: String,
    },

    /// Normative RFC-0001 specification lookup (`list`, `search <query>`, `<section>`).
    Rfc {
        /// Action (`list`, `search`, or section ID like `4.2`).
        #[arg(default_value = "list")]
        action: String,
        /// Search query or section ID.
        #[arg(default_value = "")]
        query: String,
    },


    /// Run an interactive protocol demo.
    Demo,

    /// Configuration management.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Multi-environment profile management (`dev`, `staging`, `production`).
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },

    /// Target KSP connection environment (`local`, `demo`, `staging`, `production`).
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },

    /// Package optimized release binaries and checksums (`ksp dist`).
    Dist {
        /// Target OS architecture (`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`).
        #[arg(long, default_value = "")]
        target: String,
    },

    /// Check for updates and upgrade KSP CLI (`ksp update`).
    Update {
        /// Only check if update is available without installing.
        #[arg(long)]
        check: bool,
    },

    /// Display 1-liner global install scripts for curl / powershell (`ksp install-script`).
    InstallScript,

    /// Uninstall KSP CLI and clean up configuration files (`ksp uninstall` / `remove` / `delete`).
    #[command(alias = "remove", alias = "delete", alias = "rm")]
    Uninstall {
        /// Force uninstallation without asking for interactive confirmation.
        #[arg(short = 'y', long)]
        force: bool,
    },



    /// Validate a KSP packet binary file.
    Validate {
        /// Path to packet binary file.
        file: String,
    },

    /// Show system and protocol information.
    Info,

    /// Launch the KSP interactive playground.
    Playground,

    /// Launch interactive KSP REPL console (`ksp shell` -> `ksp>`).
    Shell,

    /// Generate shell completion scripts (`ksp completion bash | zsh | fish | powershell`).
    Completion {
        /// Target shell (`bash`, `zsh`, `fish`, `powershell`, `elvish`).
        shell: String,
    },

    /// Manage external KSP plugins (`ksp plugins install | list | remove`).
    Plugins {
        #[command(subcommand)]
        action: PluginsAction,
    },

    /// Open KSP documentation.
    Docs {
        /// Specific topic (rfc, api, handshake, replay, packet, benchmarks).
        topic: Option<String>,
    },

    /// Live traffic monitor (`ksp monitor`).
    Monitor {
        /// Watch a live simulated traffic stream with active numbers and sparklines.
        #[arg(long)]
        demo: bool,
    },

    /// Console TUI dashboard (`ksp dashboard`).
    Dashboard {
        /// Watch a live simulated traffic stream with active numbers and sparklines.
        #[arg(long)]
        demo: bool,
    },

    /// System and protocol telemetry statistics (`ksp stats`).
    Stats {
        /// Watch a live simulated traffic stream with active numbers and sparklines.
        #[arg(long)]
        demo: bool,
    },


    /// Trace a single packet across the entire KSP protocol stack.
    Trace {
        /// Optional message payload to trace.
        message: Option<String>,
    },

    /// Inspect protocol resources (session, packet, cert).
    Inspect {
        #[command(subcommand)]
        action: InspectAction,
    },

    /// Display KSP ASCII banner, philosophy, author, and links.
    About,

    /// Matrix mode simulation.
    Matrix,

    /// Brew secure packets (HTTP 418).
    Coffee,

    /// Display a random networking or cryptography quote.
    Quote,

    /// Display underlying dependencies and inspirations.
    Credits,

    /// Secret developer mode with advanced internal dumps.
    Dev,

    /// Local IPC & telemetry control plane daemon (`start`, `stop`, `status`).
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Inspect historical or streaming daemon & session logs over IPC (`ksp logs -f`).
    Logs {
        /// Follow live log output stream.
        #[arg(short, long)]
        follow: bool,

        /// Filter logs by minimum level (`trace`, `debug`, `info`, `warn`, `error`).
        #[arg(short, long)]
        level: Option<String>,

        /// Filter logs by specific session UUID substring.
        #[arg(short, long)]
        session: Option<String>,

        /// Number of recent log lines to display initially.
        #[arg(short = 'n', long, default_value = "50")]
        lines: usize,
    },

    /// Expose Prometheus OpenMetrics and observability export (`ksp metrics`).
    Metrics {
        /// Optional bind address (`--listen 127.0.0.1:9090`) to start a dedicated HTTP scrape endpoint.
        #[arg(long)]
        listen: Option<String>,
    },

    /// Animate a single packet across all 9 layers of KSP.
    Journey,
}


#[derive(Subcommand)]
enum InspectAction {
    /// Inspect a session state.
    Session {
        /// Session ID to inspect.
        id: Option<String>,
    },
    /// Inspect a packet binary file.
    Packet {
        /// Path to packet binary file.
        file: String,
    },
    /// Inspect a certificate file.
    Cert {
        /// Path to certificate file.
        file: String,
    },
}


#[derive(Subcommand)]
enum ServerAction {
    /// Start the KSP server.
    Start {
        /// Port to listen on.
        #[arg(long, default_value = "9876")]
        port: u16,

        /// Host to bind to.
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
    },
    /// Stop the KSP server.
    Stop,
    /// Show server status.
    Status,
    /// Restart the KSP server.
    Restart {
        /// Port to listen on.
        #[arg(long, default_value = "9876")]
        port: u16,

        /// Host to bind to.
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
    },
    /// Hot-reload server configuration (`ksp.toml`).
    Reload,
}


#[derive(Subcommand)]
enum PacketAction {
    /// Inspect a packet file (structured table view).
    Inspect {
        /// Path to packet binary file.
        file: String,
    },
    /// Decode a packet file (hex dump with layer breakdown).
    Decode {
        /// Path to packet binary file.
        file: String,
    },
    /// Build a packet interactively.
    Build {
        /// Output file path.
        #[arg(long, default_value = "packet.bin")]
        output: String,
    },
    /// Encode payload / hex into binary KSP packet.
    Encode {
        /// Output file path.
        #[arg(long, default_value = "encoded.bin")]
        output: String,
    },
    /// Export packet binary to hex or json.
    Export {
        /// Path to packet binary file.
        file: String,
        /// Export format (hex, json).
        #[arg(long, default_value = "hex")]
        format: String,
    },
    /// Visualize 48-byte fixed binary header layout and fields.
    Visualize {
        /// Path to packet binary file.
        file: String,
    },
}

#[derive(Subcommand)]
enum CaptureAction {
    /// Start capturing live KSP traffic.
    Start {
        /// Port to listen on.
        #[arg(long, default_value = "9876")]
        port: u16,
    },
    /// Stop capturing and finalize pcap/buffer.
    Stop,
    /// Export captured packets.
    Export {
        /// Output format (`pcap`, `json`, `bin`).
        #[arg(long, default_value = "pcap")]
        format: String,
        /// Output file name.
        #[arg(long, default_value = "")]
        output: String,
    },
    /// Live packet inspection stream.
    Live,
}

#[derive(Subcommand)]
enum WiresharkAction {
    /// Install KSP Lua Dissector into Wireshark plugins directory.
    Install,
    /// Launch Wireshark with KSP display filter (`-Y ksp`).
    Open,
    /// Remove KSP Lua Dissector plugin.
    Uninstall,
}


#[derive(Subcommand, Debug, Clone)]
enum TransferAction {
    /// Send a file across KSP (`ksp transfer send <file> --to <addr>`).
    Send {
        /// File to send across KSP tunnel.
        file: String,
        /// Target receiver address (`127.0.0.1:9888`).
        #[arg(long, default_value = "127.0.0.1:9888")]
        to: String,
    },
    /// Receive incoming file transfer (`ksp transfer receive --port 9888 --output rec.dat`).
    Receive {
        /// Listen port (`9888`).
        #[arg(long, default_value = "9888")]
        port: u16,
        /// Output path for received file (`rec.dat`).
        #[arg(long)]
        output: Option<String>,
    },
    /// Resume an interrupted file transfer (`ksp transfer resume <file> --to <addr>`).
    Resume {
        /// File to resume sending.
        file: String,
        /// Target receiver address (`127.0.0.1:9888`).
        #[arg(long, default_value = "127.0.0.1:9888")]
        to: String,
    },
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Subcommand)]
enum CertAction {
    /// Generate a self-signed certificate.
    Generate {
        /// Certificate subject (e.g., "ksp://myserver.com").
        #[arg(long, default_value = "ksp://localhost")]
        subject: String,

        /// Validity period in days.
        #[arg(long, default_value = "365")]
        days: u32,

        /// Output file prefix (creates <output>.cert and <output>.key).
        #[arg(long, default_value = "server")]
        output: String,
    },
    /// Inspect a certificate file.
    Inspect {
        /// Path to certificate file.
        file: String,
    },
    /// Verify a certificate's signature and validity.
    Verify {
        /// Path to certificate file.
        file: String,
    },
    /// Renew an expiring certificate by regenerating a new keypair with same subject.
    Renew {
        /// Path to certificate file.
        file: String,
        /// New validity period in days.
        #[arg(long, default_value = "365")]
        days: u32,
    },
}

#[derive(Subcommand)]
enum ReplayAction {
    /// Simulate high-concurrency sliding window replay attacks (1024 packets).
    Simulate,
}


#[derive(Subcommand)]
enum SessionAction {
    /// List active sessions.
    List,
    /// Inspect a session state.
    Inspect {
        /// Session ID to inspect.
        id: Option<String>,
    },
    /// Close a session.
    Close {
        /// Session ID to close.
        id: String,
    },
    /// Resume a disconnected session via PSK resumption token.
    Resume {
        /// Session ID or token.
        id: String,
    },
}


#[derive(Subcommand)]
enum StreamAction {
    /// List active streams.
    List,
    /// Open a new stream.
    Open,
    /// Close a stream.
    Close {
        /// Stream ID to close.
        id: u32,
    },
    /// Reset all stream flow control buffers and error windows.
    Reset,
}


#[derive(Subcommand)]
enum ConfigAction {
    /// Get a config value.
    Get {
        /// Configuration key.
        key: String,
    },
    /// Set a config value.
    Set {
        /// Configuration key.
        key: String,
        /// New value.
        value: String,
    },
    /// Show all configuration.
    Show,
    /// List all configuration.
    List,
    /// Validate configuration syntax and parameters.
    Validate,
    /// Reset configuration to factory default values.
    Reset,
}

#[derive(Subcommand)]
enum ProfileAction {
    /// Create a new profile (`dev`, `staging`, `production`).
    Create {
        /// Profile name.
        name: String,
    },
    /// Switch active profile.
    Switch {
        /// Profile name.
        name: String,
    },
    /// List all profiles.
    List,
}

#[derive(Subcommand)]
enum EnvAction {
    /// Switch target connection environment (`local`, `demo`, `staging`, `production`).
    Use {
        /// Environment name.
        name: String,
    },
    /// List all target environments.
    List,
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the background daemon control plane (`127.0.0.1:9899`).
    Start,
    /// Stop the running background daemon control plane.
    Stop,
    /// Check the status of the running daemon control plane.
    Status,
}

#[derive(Subcommand)]
enum PluginsAction {
    /// List all installed system and user KSP plugins.
    List,
    /// Install a new KSP plugin from path or template.
    Install {
        /// Plugin name or path (e.g. `auth` or `./ksp-custom`).
        target: String,
    },
    /// Remove an installed user KSP plugin.
    Remove {
        /// Plugin name (e.g. `auth`).
        name: String,
    },
}


fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let is_help_or_missing = matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp
                    | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                    | clap::error::ErrorKind::MissingSubcommand
            );
            if is_help_or_missing {
                if let Ok(rt) = tokio::runtime::Runtime::new() {
                    rt.block_on(ui::startup::run());
                } else {
                    ui::print_banner();
                }
            }
            err.exit();
        }
    };

    // Initialize logging based on verbosity
    let log_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    if cli.verbose > 0 {
        tracing_subscriber::fmt()
            .with_env_filter(log_level)
            .init();
    }

    // Print banner on first use (not in JSON mode)
    if !cli.json {
        match &cli.command {
            Commands::Version | Commands::Demo | Commands::About | Commands::Matrix | Commands::Coffee => {} // These print their own banner or output
            _ => {}
        }
    }


    match cli.command {
        Commands::Version => cmd::version::run(cli.verbose, cli.json),
        Commands::Init => cmd::init::run(cli.json),
        Commands::New { name } => cmd::new_project::run(&name, cli.json),
        Commands::Generate { target } => cmd::generate::run(&target, cli.json),
        Commands::Doctor { fix } => cmd::doctor::run(fix, cli.json),
        Commands::Diag { dump } => cmd::diag::run_diag(dump, cli.json),
        Commands::Proxy { listen, upstream } => cmd::proxy::run_proxy(&listen, &upstream, cli.json),
        Commands::Gateway { listen, target_http } => cmd::proxy::run_gateway(&listen, &target_http, cli.json),


        Commands::Server { action } => match action {
            ServerAction::Start { port, host } => {
                cmd::server::run_start(port, &host, cli.verbose > 0, cli.json)
            }
            ServerAction::Stop => cmd::server::run_stop(cli.json),
            ServerAction::Status => cmd::server::run_status(cli.json),
            ServerAction::Restart { port, host } => {
                cmd::server::run_restart(port, &host, cli.verbose > 0, cli.json)
            }
            ServerAction::Reload => cmd::server::run_reload(cli.json),
        },

        Commands::Connect { address } => cmd::connect::run(&address, cli.json),
        Commands::Disconnect => cmd::connect::run_disconnect(cli.json),
        Commands::Ping { address } => cmd::ping::run(&address, cli.json, cli.verbose),

        Commands::Packet { action } => match action {
            PacketAction::Inspect { file } => cmd::packet::run_inspect(&file, cli.json),
            PacketAction::Decode { file } => cmd::packet::run_decode(&file, cli.json),
            PacketAction::Build { output } => cmd::packet::run_build(&output, cli.json),
            PacketAction::Encode { output } => cmd::packet::run_encode(&output, cli.json),
            PacketAction::Export { file, format } => cmd::packet::run_export(&file, &format, cli.json),
            PacketAction::Visualize { file } => cmd::packet::run_visualize(&file, cli.json),
        },
        Commands::Capture { action } => match action {
            CaptureAction::Start { port } => cmd::capture::run_start(port, cli.json),
            CaptureAction::Stop => cmd::capture::run_stop(cli.json),
            CaptureAction::Export { format, output } => cmd::capture::run_export(&format, &output, cli.json),
            CaptureAction::Live => cmd::capture::run_live(cli.json),
        },
        Commands::Wireshark { action } => match action {
            WiresharkAction::Install => cmd::wireshark::run_install(cli.json),
            WiresharkAction::Open => cmd::wireshark::run_open(cli.json),
            WiresharkAction::Uninstall => cmd::wireshark::run_uninstall(cli.json),
        },
        Commands::Benchmark { stress, csv, markdown } => cmd::benchmark::run(stress, csv, markdown, cli.json),

        Commands::Chat { address } => cmd::chat::run(&address, cli.json),
        Commands::Transfer { action } => match action {
            TransferAction::Send { file, to } => cmd::transfer::run_send(&file, &to, cli.json),
            TransferAction::Receive { port, output } => {
                cmd::transfer::run_receive(port, output.as_deref(), cli.json)
            }
            TransferAction::Resume { file, to } => cmd::transfer::run_resume(&file, &to, cli.json),
            TransferAction::External(args) => {
                if let Some(file) = args.first() {
                    let mut to = "127.0.0.1:9888".to_string();
                    let mut resume = false;
                    let mut idx = 1;
                    while idx < args.len() {
                        if args[idx] == "--to" && idx + 1 < args.len() {
                            to = args[idx + 1].clone();
                            idx += 2;
                        } else if args[idx] == "--resume" {
                            resume = true;
                            idx += 1;
                        } else {
                            idx += 1;
                        }
                    }
                    if resume {
                        cmd::transfer::run_resume(file, &to, cli.json);
                    } else {
                        cmd::transfer::run_send(file, &to, cli.json);
                    }
                } else {
                    println!("Usage: ksp transfer <send|receive|resume> [OPTIONS]");
                }
            }
        },
        Commands::Receive { port, output } => {
            cmd::transfer::run_receive(port, output.as_deref(), cli.json)
        }
        Commands::Cert { action } => match action {
            CertAction::Generate { subject, days, output } => {
                cmd::cert::run_generate(&subject, days, &output, cli.json)
            }
            CertAction::Inspect { file } => cmd::cert::run_inspect(&file, cli.json),
            CertAction::Verify { file } => cmd::cert::run_verify(&file, cli.json),
            CertAction::Renew { file, days } => cmd::cert::run_renew(&file, days, cli.json),
        },
        Commands::Security { attack } => cmd::security::run_security(&attack, cli.json),
        Commands::Replay { action } => match action {
            ReplayAction::Simulate => cmd::security::run_replay_simulate(cli.json),
        },

        Commands::Session { action } => match action {
            SessionAction::List => cmd::session::run_list(cli.json),
            SessionAction::Inspect { id } => cmd::session::run_inspect(id.as_deref(), cli.json),
            SessionAction::Close { id } => cmd::session::run_close(&id, cli.json),
            SessionAction::Resume { id } => cmd::session::run_resume(&id, cli.json),
        },
        Commands::Stream { action } => match action {
            StreamAction::List => cmd::stream::run_list(cli.json),
            StreamAction::Open => cmd::stream::run_open(cli.json),
            StreamAction::Close { id } => cmd::stream::run_close(id, cli.json),
            StreamAction::Reset => cmd::stream::run_reset(cli.json),
        },

        Commands::Explain { topic } => cmd::explain::run(&topic, cli.json),
        Commands::Learn { topic } => cmd::learn::run_learn(&topic, cli.json),
        Commands::Rfc { action, query } => cmd::learn::run_rfc(&action, &query, cli.json),
        Commands::Demo => cmd::demo::run(cli.json),

        Commands::Config { action } => match action {
            ConfigAction::Get { key } => cmd::config_cmd::run_get(&key, cli.json),
            ConfigAction::Set { key, value } => cmd::config_cmd::run_set(&key, &value, cli.json),
            ConfigAction::Show => cmd::config_cmd::run_show(cli.json),
            ConfigAction::List => cmd::config_cmd::run_list(cli.json),
            ConfigAction::Validate => cmd::config_cmd::run_validate(cli.json),
            ConfigAction::Reset => cmd::config_cmd::run_reset(cli.json),
        },
        Commands::Profile { action } => match action {
            ProfileAction::Create { name } => cmd::profile::run_create(&name, cli.json),
            ProfileAction::Switch { name } => cmd::profile::run_switch(&name, cli.json),
            ProfileAction::List => cmd::profile::run_list(cli.json),
        },
        Commands::Env { action } => match action {
            EnvAction::Use { name } => cmd::env::run_use(&name, cli.json),
            EnvAction::List => cmd::env::run_list(cli.json),
        },
        Commands::Dist { target } => cmd::dist::run_dist(&target, cli.json),
        Commands::Update { check } => cmd::dist::run_update(check, cli.json),
        Commands::InstallScript => cmd::dist::run_install_script(cli.json),
        Commands::Uninstall { force } => cmd::dist::run_uninstall(force, cli.json),
        Commands::Validate { file } => cmd::validate::run(&file, cli.json),


        Commands::Info => cmd::info::run(cli.json),
        Commands::Playground => cmd::playground::run(cli.json),
        Commands::Docs { topic } => cmd::docs::run(topic.as_deref(), cli.json),
        Commands::Shell => cmd::shell::run_shell(cli.json),
        Commands::Completion { shell } => cmd::completion::run(&shell, cli.json),
        Commands::Plugins { action } => match action {
            PluginsAction::List => cmd::plugins::run_list(cli.json),
            PluginsAction::Install { target } => cmd::plugins::run_install(&target, cli.json),
            PluginsAction::Remove { name } => cmd::plugins::run_remove(&name, cli.json),
        },

        Commands::Monitor { demo } => cmd::dashboard::run_monitor(demo, cli.json),

        Commands::Dashboard { demo } => cmd::dashboard::run_dashboard(demo, cli.json),
        Commands::Stats { demo } => cmd::stats::run(demo, cli.json),


        Commands::Trace { message } => cmd::trace::run(message.as_deref(), cli.json),
        Commands::Inspect { action } => match action {
            InspectAction::Session { id } => cmd::session::run_inspect(id.as_deref(), cli.json),
            InspectAction::Packet { file } => cmd::packet::run_inspect(&file, cli.json),
            InspectAction::Cert { file } => cmd::cert::run_inspect(&file, cli.json),
        },
        Commands::About => cmd::easter_eggs::run_about(cli.json),
        Commands::Matrix => cmd::easter_eggs::run_matrix(cli.json),
        Commands::Coffee => cmd::easter_eggs::run_coffee(cli.json),
        Commands::Quote => cmd::easter_eggs::run_quote(cli.json),
        Commands::Credits => cmd::easter_eggs::run_credits(cli.json),
        Commands::Dev => cmd::easter_eggs::run_dev(cli.json),
        Commands::Daemon { action } => match action {
            DaemonAction::Start => cmd::daemon::run_start(cli.verbose > 0, cli.json),
            DaemonAction::Stop => cmd::daemon::run_stop(cli.json),
            DaemonAction::Status => cmd::daemon::run_status(cli.json),
        },
        Commands::Logs { follow, level, session, lines } => {
            cmd::logs::run(follow, cli.json, level.as_deref(), session.as_deref(), lines)
        }
        Commands::Metrics { listen } => cmd::metrics::run(listen.as_deref(), cli.json),
        Commands::Journey => cmd::easter_eggs::run_journey(cli.json),
    }

}

