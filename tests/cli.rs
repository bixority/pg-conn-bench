//! End-to-end tests against a live PostgreSQL server. They are ignored by default.
//!
//! Run with a server reachable through the usual libpq variables, for example:
//!   PGHOST=localhost PGPORT=55432 PGUSER=bench PGPASSWORD=... PGDATABASE=benchdb \
//!     cargo test --test cli -- --ignored

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pg-conn-bench"))
        .args(args)
        .output()
        .expect("pg-conn-bench binary runs")
}

#[test]
#[ignore = "needs a live PostgreSQL server (see module docs)"]
fn reports_all_phases_for_plain_connection() {
    let out = run(&["--runs", "3", "--sslmode", "disable"]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for phase in ["dns", "tcp", "auth"] {
        assert!(
            stdout.lines().any(|l| l.starts_with(phase)),
            "missing {phase} row:\n{stdout}"
        );
    }
    assert!(
        !stdout.lines().any(|l| l.starts_with("tls")),
        "tls row must not appear:\n{stdout}"
    );
}

#[test]
#[ignore = "needs a live PostgreSQL server with TLS (see module docs)"]
fn reports_tls_phase_for_require() {
    let out = run(&["--runs", "3", "--sslmode", "require"]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.lines().any(|l| l.starts_with("tls")),
        "missing tls row:\n{stdout}"
    );
}

#[test]
fn unknown_host_is_reported_as_dns_failure() {
    let out = run(&["--host", "no-such-host.invalid", "--runs", "2"]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(!out.status.success(), "a failed run must give exit code 1");
    assert!(stdout.contains("failed: 2"), "{stdout}");
    assert!(stdout.contains("phase=dns"), "{stdout}");
}

#[test]
fn zero_runs_is_rejected() {
    let out = run(&["--runs", "0"]);

    assert!(!out.status.success());
}

#[test]
fn csv_file_gets_one_row_per_run_even_when_runs_fail() {
    let path = std::env::temp_dir().join(format!("pg-conn-bench-cli-{}.csv", std::process::id()));
    let out = run(&[
        "--host",
        "no-such-host.invalid",
        "--runs",
        "3",
        "--csv",
        path.to_str().unwrap(),
    ]);
    let text = std::fs::read_to_string(&path).expect("csv written");
    std::fs::remove_file(&path).ok();

    assert!(!out.status.success());
    assert_eq!(text.lines().count(), 4, "header plus 3 runs:\n{text}");
    assert!(
        text.lines().skip(1).all(|l| l.contains(",failed,")),
        "{text}"
    );
}
