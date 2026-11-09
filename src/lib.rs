//! Core application entry point and module boundaries for proxyctl.

pub mod benchmark;
pub mod cli;
pub mod cores;
pub mod database;
pub mod domain;
pub mod parser;
pub mod services;
pub mod tun;
pub mod updates;

/// Parse command-line arguments and run the application.
pub fn run() -> anyhow::Result<()> {
    use clap::Parser as _;

    cli::dispatch(cli::Cli::parse())
}
