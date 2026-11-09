//! Per-run records, flags, the verdict, the summary with failure statistics, and CSV output.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use crate::counters::{NicCounters, TcpCounters};
use crate::phases::{Phase, RunFailure, Timings};
use crate::stats::{Summary, summarize};

/// One connection attempt, successful or not.
pub struct RunRecord {
    pub index: u32,
    pub started: DateTime<Utc>,
    pub outcome: Result<(Timings, SocketAddr), RunFailure>,
    /// System-wide TCP counter change during the run, when they could be read.
    pub tcp: Option<TcpCounters>,
    /// Counter change on the route's interface during the run, when it could be read.
    pub nic: Option<NicCounters>,
}

/// A connect slower than this was almost certainly a SYN retransmit: the first SYN retransmit on
/// Linux comes after one second.
const SLOW_CONNECT: Duration = Duration::from_millis(900);

/// Authentication slower than this is outside the normal range (typically 15 to 40 ms on a nearby server). Such a
/// stall can come from the server or from a direction the client cannot see, so it gets its own flag.
const SLOW_AUTH: Duration = Duration::from_millis(100);

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn timestamp(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// The first line of an error, shortened, so a table row stays on one line.
fn short_error(error: &anyhow::Error) -> String {
    let text = format!("{error:#}");
    let first = text.lines().next().unwrap_or_default();
    if first.chars().count() > 100 {
        let cut: String = first.chars().take(97).collect();
        format!("{cut}...")
    } else {
        first.to_string()
    }
}

fn cell(value: Option<Duration>) -> String {
    value.map_or_else(|| "-".to_string(), |d| format!("{:.3}", ms(d)))
}

fn number(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_string(), |v| v.to_string())
}

/// Retransmitted segments on this connection while connecting (SYNs included).
fn connect_retrans(t: &Timings) -> Option<u32> {
    t.socket_after_tcp.map(|s| s.total_retrans)
}

/// Retransmitted segments on this connection during authentication.
fn auth_retrans(t: &Timings) -> Option<u32> {
    match (t.socket_after_tcp, t.socket_after_auth) {
        (Some(before), Some(after)) => {
            Some(after.total_retrans.saturating_sub(before.total_retrans))
        }
        _ => None,
    }
}

/// Network signs of one run.
///
/// - `slow-connect`: the connect took at least 900 ms.
/// - `conn-retransmit`: this connection retransmitted while connecting (a SYN, most likely).
/// - `auth-retransmit`: this connection retransmitted during authentication.
/// - `syn-retransmit`, `segment-retransmit`, `timeout`: system-wide counters, so they can include
///   traffic from other processes.
/// - `slow-auth`: authentication took at least 100 ms.
/// - `nic-error`: error or drop counters on the route's interface changed during the run.
pub fn flags(r: &RunRecord) -> Vec<&'static str> {
    let mut out = Vec::new();
    if let Ok((t, _)) = &r.outcome {
        if t.tcp >= SLOW_CONNECT {
            out.push("slow-connect");
        }
        if t.auth.total >= SLOW_AUTH {
            out.push("slow-auth");
        }
        if connect_retrans(t).is_some_and(|n| n > 0) {
            out.push("conn-retransmit");
        }
        if auth_retrans(t).is_some_and(|n| n > 0) {
            out.push("auth-retransmit");
        }
    }
    if let Some(c) = r.tcp {
        if c.syn_retrans > 0 {
            out.push("syn-retransmit");
        }
        if c.retrans_segs > 0 {
            out.push("segment-retransmit");
        }
        if c.timeouts > 0 {
            out.push("timeout");
        }
    }
    if r.nic.is_some_and(NicCounters::any) {
        out.push("nic-error");
    }
    out
}

fn has(flags: &[&str], names: &[&str]) -> bool {
    flags.iter().any(|f| names.contains(f))
}

/// The overall result, first: OK, or what went wrong, with the runs involved.
pub fn verdict(records: &[RunRecord], iface: Option<&str>) -> String {
    let total = records.len();
    let failed = records.iter().filter(|r| r.outcome.is_err()).count();
    let flagged: Vec<(&RunRecord, Vec<&'static str>)> = records
        .iter()
        .map(|r| (r, flags(r)))
        .filter(|(_, f)| !f.is_empty())
        .collect();

    let count = |names: &[&str]| flagged.iter().filter(|(_, f)| has(f, names)).count();
    let syn = count(&["slow-connect", "syn-retransmit", "conn-retransmit"]);
    let auth = count(&["auth-retransmit"]);
    let system = count(&["segment-retransmit", "timeout"]);
    let slow_auth = count(&["slow-auth"]);
    let nic = count(&["nic-error"]);
    let counters_known = records.iter().any(|r| r.tcp.is_some());

    let mut out = String::new();
    if failed == 0 && flagged.is_empty() {
        let _ = writeln!(
            out,
            "RESULT: OK  all {total} runs succeeded; no slow connects, SYN retransmits, retransmits or NIC errors"
        );
    } else {
        let _ = writeln!(out, "RESULT: ISSUES");
    }
    if failed > 0 {
        let _ = writeln!(out, "  failed runs: {failed} of {total} (see below)");
    }
    if syn > 0 {
        let _ = writeln!(
            out,
            "  SYN issues: {syn} runs (connect >= 900 ms, or this connection retransmitted while connecting)"
        );
    }
    if auth > 0 {
        let _ = writeln!(
            out,
            "  retransmits during authentication (this connection): {auth} runs"
        );
    }
    if slow_auth > 0 {
        let _ = writeln!(
            out,
            "  slow authentication (>= 100 ms): {slow_auth} runs (no retransmit on this connection; cause not visible from the client)"
        );
    }
    if system > 0 {
        let _ = writeln!(
            out,
            "  other TCP retransmits (system-wide counters, may include other traffic): {system} runs"
        );
    }
    if nic > 0 {
        let name = iface.unwrap_or("route interface");
        let _ = writeln!(
            out,
            "  NIC errors or drops on {name} (interface-wide): {nic} runs"
        );
    }
    if !counters_known {
        let _ = writeln!(
            out,
            "  system TCP counters unavailable here: SYN and system-wide checks were skipped"
        );
    }
    if !flagged.is_empty() {
        let _ = writeln!(out, "  flagged runs:");
        for (r, f) in &flagged {
            let _ = writeln!(
                out,
                "    run {:>5}  {}  {}",
                r.index,
                timestamp(&r.started),
                f.join(", ")
            );
        }
    }
    out
}

/// One line per run: status, timings, per-connection and system-wide TCP, NIC, flags, error.
pub fn run_line(r: &RunRecord) -> String {
    let (status, dns, tcp, tls, auth, c_rtx, a_rtx, rtt, error) = match &r.outcome {
        Ok((t, _)) => (
            "ok".to_string(),
            cell(Some(t.dns)),
            cell(Some(t.tcp)),
            cell(t.tls),
            cell(Some(t.auth.total)),
            number(connect_retrans(t).map(u64::from)),
            number(auth_retrans(t).map(u64::from)),
            number(t.socket_after_auth.map(|s| u64::from(s.rtt_us))),
            String::new(),
        ),
        Err(f) => {
            let (dns, tcp, tls, auth) = match f.phase {
                Phase::Dns => (Some(f.elapsed), None, None, None),
                Phase::Tcp => (None, Some(f.elapsed), None, None),
                Phase::Tls => (None, None, Some(f.elapsed), None),
                Phase::Auth => (None, None, None, Some(f.elapsed)),
            };
            (
                format!("FAIL {}", f.phase),
                cell(dns),
                cell(tcp),
                cell(tls),
                cell(auth),
                "-".into(),
                "-".into(),
                "-".into(),
                short_error(&f.error),
            )
        }
    };
    let (retr, syn, timeouts) = match r.tcp {
        Some(c) => (
            number(Some(c.retrans_segs)),
            number(Some(c.syn_retrans)),
            number(Some(c.timeouts)),
        ),
        None => ("-".into(), "-".into(), "-".into()),
    };
    let nic_err = r.nic.map_or_else(
        || "-".to_string(),
        |n| {
            number(Some(
                n.rx_errors + n.rx_dropped + n.rx_missed + n.tx_errors + n.tx_dropped,
            ))
        },
    );

    format!(
        "{:>5}  {}  {:<9} {:>10} {:>10} {:>10} {:>10} {:>6} {:>6} {:>7} {:>8} {:>6} {:>8} {:>8}  {:<36} {}",
        r.index,
        timestamp(&r.started),
        status,
        dns,
        tcp,
        tls,
        auth,
        c_rtx,
        a_rtx,
        rtt,
        retr,
        syn,
        timeouts,
        nic_err,
        flags(r).join(","),
        error
    )
}

/// Column header for the per-run lines.
pub fn details_header() -> String {
    format!(
        "{:>5}  {:<24}  {:<9} {:>10} {:>10} {:>10} {:>10} {:>6} {:>6} {:>7} {:>8} {:>6} {:>8} {:>8}  {:<36} {}",
        "run",
        "started (UTC)",
        "status",
        "dns ms",
        "tcp ms",
        "tls ms",
        "auth ms",
        "c-rtx",
        "a-rtx",
        "rtt us",
        "retr",
        "synretr",
        "timeouts",
        "nic-err",
        "flags",
        "error"
    )
}

/// The per-phase table for the successful runs.
pub fn print_stats(records: &[RunRecord], has_tls: bool) {
    let ok: Vec<&(Timings, SocketAddr)> = records
        .iter()
        .filter_map(|r| r.outcome.as_ref().ok())
        .collect();

    println!(
        "{:<12} {:>12} {:>12} {:>12} {:>12}",
        "phase", "min", "median", "p95", "max"
    );

    let row = |name: &str, f: fn(&Timings) -> Option<Duration>| {
        let samples: Vec<f64> = ok.iter().filter_map(|(t, _)| f(t)).map(ms).collect();
        if let Some(s) = summarize(&samples) {
            print_row(name, s);
        }
    };

    row("dns", |t| Some(t.dns));
    row("tcp", |t| Some(t.tcp));
    if has_tls {
        row("tls", |t| t.tls);
    }
    row("auth", |t| Some(t.auth.total));
    row("  startup", |t| Some(t.auth.startup));
    row("  reply", |t| t.auth.reply);
    row("  scram-1", |t| t.auth.scram.map(|s| s.first));
    row("  derive", |t| t.auth.scram.map(|s| s.derive));
    row("  scram-2", |t| t.auth.scram.map(|s| s.last));
    row("  ready", |t| Some(t.auth.ready));
}

fn print_row(name: &str, s: Summary) {
    println!(
        "{:<12} {:>12} {:>12} {:>12} {:>12}",
        name,
        format!("{:.3} ms", s.min),
        format!("{:.3} ms", s.median),
        format!("{:.3} ms", s.p95),
        format!("{:.3} ms", s.max)
    );
}

/// Counts of successful and failed runs, failures per phase, and each failed run.
pub fn failure_summary(records: &[RunRecord]) -> String {
    let mut out = String::new();
    let failed: Vec<(&RunRecord, &RunFailure)> = records
        .iter()
        .filter_map(|r| r.outcome.as_ref().err().map(|f| (r, f)))
        .collect();

    let _ = writeln!(
        out,
        "runs: {}  ok: {}  failed: {}",
        records.len(),
        records.len() - failed.len(),
        failed.len()
    );
    if failed.is_empty() {
        return out;
    }

    let count = |phase: Phase| failed.iter().filter(|(_, f)| f.phase == phase).count();
    let _ = writeln!(
        out,
        "failures by phase: dns={} tcp={} tls={} auth={}",
        count(Phase::Dns),
        count(Phase::Tcp),
        count(Phase::Tls),
        count(Phase::Auth)
    );
    for (r, f) in &failed {
        let _ = writeln!(
            out,
            "  run {:>5}  {}  phase={}  after {:.3} ms  {}",
            r.index,
            timestamp(&r.started),
            f.phase,
            ms(f.elapsed),
            short_error(&f.error)
        );
    }
    out
}

/// Write one CSV row per run. Durations are milliseconds with three decimals.
pub fn write_csv(path: &Path, records: &[RunRecord]) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("creating {} failed", path.display()))?;

    writer.write_record([
        "run",
        "started_utc",
        "status",
        "addr",
        "failed_phase",
        "failed_after_ms",
        "error",
        "dns_ms",
        "tcp_ms",
        "tls_ms",
        "auth_total_ms",
        "auth_startup_ms",
        "auth_reply_ms",
        "scram_first_ms",
        "scram_derive_ms",
        "scram_last_ms",
        "auth_ready_ms",
        "sys_retrans_segs",
        "sys_syn_retrans",
        "sys_timeouts",
        "conn_retrans",
        "auth_retrans",
        "conn_rtt_us",
        "conn_rttvar_us",
        "conn_cwnd",
        "nic_rx_errors",
        "nic_rx_dropped",
        "nic_rx_missed",
        "nic_tx_errors",
        "nic_tx_dropped",
        "flags",
    ])?;

    for r in records {
        let sys = |f: fn(&TcpCounters) -> u64| {
            r.tcp.as_ref().map(|c| f(c).to_string()).unwrap_or_default()
        };
        let nic = |f: fn(&NicCounters) -> u64| {
            r.nic.as_ref().map(|n| f(n).to_string()).unwrap_or_default()
        };
        let flag_text = flags(r).join(";");
        let fields: Vec<String> = match &r.outcome {
            Ok((t, addr)) => {
                let scram = t.auth.scram;
                let sock = t.socket_after_auth;
                vec![
                    r.index.to_string(),
                    timestamp(&r.started),
                    "ok".into(),
                    addr.to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                    format!("{:.3}", ms(t.dns)),
                    format!("{:.3}", ms(t.tcp)),
                    t.tls.map(|d| format!("{:.3}", ms(d))).unwrap_or_default(),
                    format!("{:.3}", ms(t.auth.total)),
                    format!("{:.3}", ms(t.auth.startup)),
                    t.auth
                        .reply
                        .map(|d| format!("{:.3}", ms(d)))
                        .unwrap_or_default(),
                    scram
                        .map(|s| format!("{:.3}", ms(s.first)))
                        .unwrap_or_default(),
                    scram
                        .map(|s| format!("{:.3}", ms(s.derive)))
                        .unwrap_or_default(),
                    scram
                        .map(|s| format!("{:.3}", ms(s.last)))
                        .unwrap_or_default(),
                    format!("{:.3}", ms(t.auth.ready)),
                    sys(|c| c.retrans_segs),
                    sys(|c| c.syn_retrans),
                    sys(|c| c.timeouts),
                    connect_retrans(t)
                        .map(|n| n.to_string())
                        .unwrap_or_default(),
                    auth_retrans(t).map(|n| n.to_string()).unwrap_or_default(),
                    sock.map(|s| s.rtt_us.to_string()).unwrap_or_default(),
                    sock.map(|s| s.rttvar_us.to_string()).unwrap_or_default(),
                    sock.map(|s| s.cwnd.to_string()).unwrap_or_default(),
                    nic(|n| n.rx_errors),
                    nic(|n| n.rx_dropped),
                    nic(|n| n.rx_missed),
                    nic(|n| n.tx_errors),
                    nic(|n| n.tx_dropped),
                    flag_text,
                ]
            }
            Err(f) => vec![
                r.index.to_string(),
                timestamp(&r.started),
                "failed".into(),
                String::new(),
                f.phase.to_string(),
                format!("{:.3}", ms(f.elapsed)),
                format!("{:#}", f.error),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                sys(|c| c.retrans_segs),
                sys(|c| c.syn_retrans),
                sys(|c| c.timeouts),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                nic(|n| n.rx_errors),
                nic(|n| n.rx_dropped),
                nic(|n| n.rx_missed),
                nic(|n| n.tx_errors),
                nic(|n| n.tx_dropped),
                flag_text,
            ],
        };
        writer.write_record(&fields)?;
    }

    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::AuthTimings;
    use crate::socket_info::SocketSnapshot;

    fn failure(phase: Phase, elapsed_ms: u64, msg: &str) -> RunFailure {
        RunFailure {
            phase,
            elapsed: Duration::from_millis(elapsed_ms),
            error: anyhow::anyhow!(msg.to_string()),
        }
    }

    fn snap(total_retrans: u32) -> SocketSnapshot {
        SocketSnapshot {
            rtt_us: 5000,
            rttvar_us: 100,
            total_retrans,
            cwnd: 10,
        }
    }

    /// A successful timing; `tcp_ms` sets the connect time, the snapshots set the retransmits.
    fn ok_with(tcp_ms: u64, conn_retrans: u32, auth_retrans_total: u32) -> (Timings, SocketAddr) {
        let t = Timings {
            dns: Duration::from_micros(200),
            tcp: Duration::from_millis(tcp_ms),
            tls: None,
            auth: AuthTimings {
                total: Duration::from_millis(20),
                startup: Duration::from_millis(8),
                reply: None,
                scram: None,
                ready: Duration::from_micros(10),
            },
            socket_after_tcp: Some(snap(conn_retrans)),
            socket_after_auth: Some(snap(auth_retrans_total)),
        };
        (t, "10.0.0.1:31432".parse().unwrap())
    }

    fn record(index: u32, outcome: Result<(Timings, SocketAddr), RunFailure>) -> RunRecord {
        RunRecord {
            index,
            started: DateTime::parse_from_rfc3339("2026-11-09T10:51:43.187Z")
                .unwrap()
                .with_timezone(&Utc),
            outcome,
            tcp: Some(TcpCounters {
                retrans_segs: 0,
                syn_retrans: 0,
                timeouts: 0,
            }),
            nic: Some(NicCounters::default()),
        }
    }

    fn clean() -> RunRecord {
        record(1, Ok(ok_with(5, 0, 0)))
    }

    #[test]
    fn clean_run_has_no_flags_and_verdict_is_ok() {
        let records = vec![clean()];
        assert!(flags(&records[0]).is_empty());
        let v = verdict(&records, Some("eth0"));
        assert!(v.starts_with("RESULT: OK"), "{v}");
    }

    #[test]
    fn slow_connect_without_retransmit_is_a_syn_issue() {
        let r = record(1, Ok(ok_with(1019, 0, 0)));
        assert_eq!(flags(&r), vec!["slow-connect"]);
        let v = verdict(std::slice::from_ref(&r), None);
        assert!(v.contains("SYN issues: 1 runs"), "{v}");
    }

    #[test]
    fn connection_retransmit_while_connecting_is_a_syn_issue() {
        let r = record(1, Ok(ok_with(1019, 1, 1)));
        assert!(flags(&r).contains(&"conn-retransmit"));
        let v = verdict(std::slice::from_ref(&r), None);
        assert!(v.contains("SYN issues: 1 runs"), "{v}");
    }

    #[test]
    fn retransmit_during_auth_is_reported_for_this_connection() {
        let r = record(1, Ok(ok_with(5, 0, 2)));
        assert_eq!(auth_retrans(&r.outcome.as_ref().unwrap().0), Some(2));
        assert!(flags(&r).contains(&"auth-retransmit"));
        let v = verdict(std::slice::from_ref(&r), None);
        assert!(
            v.contains("during authentication (this connection): 1 runs"),
            "{v}"
        );
    }

    #[test]
    fn system_wide_retransmit_is_reported_separately() {
        let mut r = clean();
        r.tcp = Some(TcpCounters {
            retrans_segs: 2,
            syn_retrans: 0,
            timeouts: 0,
        });
        assert!(flags(&r).contains(&"segment-retransmit"));
        let v = verdict(std::slice::from_ref(&r), None);
        assert!(v.contains("other TCP retransmits"), "{v}");
        assert!(!v.contains("SYN issues"), "{v}");
    }

    #[test]
    fn slow_auth_is_flagged_even_without_retransmits() {
        let mut t = ok_with(5, 0, 0).0;
        t.auth.total = Duration::from_millis(247);
        let r = record(1, Ok((t, "10.0.0.1:31432".parse().unwrap())));
        assert_eq!(flags(&r), vec!["slow-auth"]);
        let v = verdict(std::slice::from_ref(&r), None);
        assert!(v.starts_with("RESULT: ISSUES"), "{v}");
        assert!(v.contains("slow authentication (>= 100 ms): 1 runs"), "{v}");
    }

    #[test]
    fn nic_error_is_flagged_with_interface_name() {
        let mut r = clean();
        r.nic = Some(NicCounters {
            rx_errors: 0,
            rx_dropped: 3,
            rx_missed: 0,
            tx_errors: 0,
            tx_dropped: 0,
        });
        assert!(flags(&r).contains(&"nic-error"));
        let v = verdict(std::slice::from_ref(&r), Some("enp1s0"));
        assert!(v.contains("NIC errors or drops on enp1s0"), "{v}");
    }

    #[test]
    fn failures_are_counted_in_the_verdict() {
        let records = vec![record(1, Err(failure(Phase::Auth, 30, "bad password")))];
        let v = verdict(&records, None);
        assert!(v.starts_with("RESULT: ISSUES"), "{v}");
        assert!(v.contains("failed runs: 1 of 1"), "{v}");
    }

    #[test]
    fn missing_system_counters_are_stated() {
        let mut r = clean();
        r.tcp = None;
        assert!(
            verdict(std::slice::from_ref(&r), None).contains("system TCP counters unavailable")
        );
    }

    #[test]
    fn ok_run_line_has_status_and_socket_columns() {
        let line = run_line(&record(1, Ok(ok_with(5, 0, 2))));
        assert!(line.contains(" ok "), "{line}");
        assert!(line.contains("5000"), "rtt missing: {line}");
        assert!(line.contains("2026-11-09T10:51:43.187Z"), "{line}");
    }

    #[test]
    fn failed_run_line_names_phase_and_error() {
        let line = run_line(&record(
            2,
            Err(failure(Phase::Tcp, 1019, "TCP connect to x failed")),
        ));
        assert!(line.contains("FAIL tcp"), "{line}");
        assert!(line.contains("1019.000"), "{line}");
        assert!(line.contains("TCP connect to x failed"), "{line}");
    }

    #[test]
    fn long_error_is_shortened() {
        let long = "x".repeat(300);
        let line = run_line(&record(3, Err(failure(Phase::Auth, 1, &long))));
        assert!(line.contains("..."), "{line}");
        assert!(!line.contains(&long));
    }

    #[test]
    fn failure_summary_counts_by_phase() {
        let records = vec![
            clean(),
            record(2, Err(failure(Phase::Tcp, 1019, "a"))),
            record(3, Err(failure(Phase::Tcp, 1, "b"))),
            record(4, Err(failure(Phase::Auth, 30, "c"))),
        ];
        let s = failure_summary(&records);
        assert!(s.contains("runs: 4  ok: 1  failed: 3"), "{s}");
        assert!(s.contains("dns=0 tcp=2 tls=0 auth=1"), "{s}");
    }

    #[test]
    fn csv_has_one_row_per_run_and_quotes_errors() {
        let dir = std::env::temp_dir().join(format!("pg-conn-bench-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("runs.csv");
        let records = vec![
            record(1, Ok(ok_with(5, 0, 1))),
            record(
                2,
                Err(failure(Phase::Tcp, 1019, "connect, \"quoted\" failed")),
            ),
        ];

        write_csv(&path, &records).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let mut lines = text.lines();
        assert!(lines.next().unwrap().starts_with("run,started_utc,status"));
        assert!(lines.next().unwrap().contains(",ok,10.0.0.1:31432,"));
        let failed = lines.next().unwrap();
        assert!(failed.contains(",failed,,tcp,1019.000,"), "{failed}");
        assert!(
            failed.contains("\"connect, \"\"quoted\"\" failed\""),
            "{failed}"
        );
        assert_eq!(lines.next(), None);
    }
}
