//! Time the steps of a PostgreSQL connection separately: DNS resolution, TCP connect, TLS (when
//! `--sslmode require`) and authentication. Failed runs are recorded with the phase that failed.

mod counters;
mod handshake;
mod phases;
mod report;
mod socket_info;
mod stats;
mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use chrono::Utc;
use clap::{Parser, ValueEnum};

use phases::Target;
use report::RunRecord;
use socket_info::route_interface;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SslMode {
    /// Plain TCP.
    Disable,
    /// TLS, server certificate is not verified (same as libpq `sslmode=require`).
    Require,
}

/// Benchmark PostgreSQL connection setup: DNS, TCP, TLS (optional) and authentication.
///
/// Every run is attempted, even when some fail. The password is read from the PGPASSWORD
/// environment variable and never printed. The exit code is 1 if any run failed.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Server host name or IP address.
    #[arg(long, default_value = "localhost", env = "PGHOST")]
    host: String,

    /// Server port.
    #[arg(long, default_value_t = 5432, env = "PGPORT")]
    port: u16,

    /// User to authenticate as.
    #[arg(long, default_value = "postgres", env = "PGUSER")]
    user: String,

    /// Database to open after authentication.
    #[arg(long, env = "PGDATABASE")]
    dbname: Option<String>,

    /// Number of connections to time.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..))]
    runs: u32,

    /// Transport encryption.
    #[arg(long, value_enum, default_value_t = SslMode::Disable, env = "PGSSLMODE")]
    sslmode: SslMode,

    /// Print one line per run as it finishes: status, timings, TCP retransmit counters, error.
    #[arg(long)]
    details: bool,

    /// Also write one CSV row per run to this file.
    #[arg(long, value_name = "PATH")]
    csv: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    let cli = Cli::parse();

    let tls = match cli.sslmode {
        SslMode::Disable => None,
        SslMode::Require => Some(std::sync::Arc::new(tls::no_verify_config()?)),
    };

    let target = Target {
        host: cli.host.clone(),
        port: cli.port,
        user: cli.user.clone(),
        dbname: cli.dbname.clone(),
        password: std::env::var("PGPASSWORD").ok(),
        tls,
    };

    if cli.details {
        println!("{}", report::details_header());
    }
    // The interface that carries traffic to the server, found without sending any packet.
    let iface = match phases::resolve(&target).await {
        Ok(addrs) => route_interface(addrs[0]),
        Err(_) => None,
    };

    let mut records = Vec::with_capacity(cli.runs as usize);
    for index in 1..=cli.runs {
        let started = Utc::now();
        let before = counters::read();
        let nic_before = iface.as_deref().and_then(counters::read_nic);
        let outcome = phases::run_once(&target).await;
        let after = counters::read();
        let nic_after = iface.as_deref().and_then(counters::read_nic);
        let tcp = match (before, after) {
            (Some(b), Some(a)) => Some(a.since(b)),
            _ => None,
        };
        let nic = match (nic_before, nic_after) {
            (Some(b), Some(a)) => Some(a.since(b)),
            _ => None,
        };

        let record = RunRecord {
            index,
            started,
            outcome,
            tcp,
            nic,
        };
        if cli.details {
            println!("{}", report::run_line(&record));
        }
        records.push(record);
    }

    print_report(&cli, &records, iface.as_deref());

    if let Some(path) = &cli.csv {
        report::write_csv(path, &records)?;
        println!("csv: {}", path.display());
    }

    let any_failed = records.iter().any(|r| r.outcome.is_err());
    Ok(if any_failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn print_report(cli: &Cli, records: &[RunRecord], iface: Option<&str>) {
    let has_tls = matches!(cli.sslmode, SslMode::Require);
    let dbname = cli.dbname.as_deref().unwrap_or("(default)");

    println!(
        "target: {}:{}  user={}  db={}  sslmode={:?}  runs={}",
        cli.host,
        cli.port,
        cli.user,
        dbname,
        cli.sslmode,
        records.len()
    );

    let mut addresses: Vec<SocketAddr> = Vec::new();
    for (_, addr) in records.iter().filter_map(|r| r.outcome.as_ref().ok()) {
        if !addresses.contains(addr) {
            addresses.push(*addr);
        }
    }
    let ips: Vec<String> = addresses.iter().map(ToString::to_string).collect();
    println!("resolved: {}", ips.join(", "));
    match iface {
        Some(name) => println!("route interface: {name}"),
        None => println!("route interface: not found (NIC counters skipped)"),
    }
    println!();

    print!("{}", report::verdict(records, iface));
    println!();
    print!("{}", report::failure_summary(records));
    println!();

    if records.iter().any(|r| r.outcome.is_ok()) {
        report::print_stats(records, has_tls);
    }
}
