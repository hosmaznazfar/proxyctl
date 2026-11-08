//! Command-line interface definitions.
//!
//! Keep argument parsing and presentation here. Application behavior belongs in services.
use clap::Parser;

/// Top-level proxyctl command line.
#[derive(Debug, Parser)]
#[command(
    name = "proxyctl",
    version,
    about = "A lightweight CLI for managing and benchmarking proxy nodes",
    long_about = None
)]
pub struct Cli {}
