//! KSP Server SDK API (`ksp-server`).
//!
//! Provides `ServerConfig` and `run_server` / `handle_connection` for asynchronous TCP server handling.

pub mod server;
pub use server::*;
