//! Core application entry point and module boundaries for proxyctl.

pub mod cli;
pub mod cores;
pub mod database;
pub mod domain;
pub mod parser;
pub mod services;
pub mod tun;

/// Parse command-line arguments and run the application.
pub fn run() -> anyhow::Result<()> {
    use clap::Parser as _;

    let _cli = cli::Cli::parse();

    println!("proxyctl is under development; see --help for available options.");
    Ok(())
}
