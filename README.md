# pg-conn-bench

Times each step of a PostgreSQL connection separately, over many sequential runs, and points out
network stalls such as retransmitted SYNs.

- **dns**: resolving the host name (`tokio::net::lookup_host`)
- **tcp**: TCP connect to the first resolved address, with `TCP_NODELAY` set as libpq does
- **tls**: SSL request and TLS handshake (only with `--sslmode require`)
- **auth**: from the StartupMessage until the server reports ReadyForQuery, split into the startup
  reply, the SCRAM-SHA-256 round trips, the client-side key derivation and the wait for ReadyForQuery.
  Cleartext and MD5 passwords are supported too.

Each run resolves and connects again, so nothing is cached between runs. Runs are strictly
sequential, and the connection is closed (with a Terminate message) outside the timed steps.

## Install

```
cargo install --git https://github.com/bixority/pg-conn-bench
```

Or build from a checkout with `cargo build --release`. `.cargo/config.toml` builds for the CPU of the
build machine (`target-cpu=native`); remove it to build a portable binary.

Linux is required: the network diagnostics read `/proc/net` and `TCP_INFO`.

## Usage

```
PGPASSWORD=... pg-conn-bench --host db.example --port 5432 --user app --dbname app --runs 100
pg-conn-bench --sslmode require --runs 1000 --details --csv runs.csv
```

Connection settings also come from `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE` and `PGSSLMODE`.
The password is read only from `PGPASSWORD` and is never printed.

| Option | Meaning |
|---|---|
| `--runs N` | number of connections to time (default 10) |
| `--sslmode disable\|require` | plain TCP, or TLS without certificate verification (libpq `require`) |
| `--details` | one line per run as it finishes: timestamp, status, timings, counters, error |
| `--csv PATH` | also write one CSV row per run |

## Output

The summary gives min, median, p95 and max per step and sub-step (in milliseconds), the failures
per phase (`dns`, `tcp`, `tls`, `auth`) with each failed run's time and error, and a verdict that
explains the outliers. Timing statistics cover the successful runs only. The exit code is 1 if any
run failed.

Each run can carry these flags:

| Flag | Meaning |
|---|---|
| `slow-connect` | the TCP connect took at least 900 ms (the first SYN retransmit on Linux comes after 1 s) |
| `conn-retransmit` | this connection retransmitted while connecting, most likely a SYN |
| `auth-retransmit` | this connection retransmitted during authentication |
| `slow-auth` | authentication took at least 100 ms |
| `syn-retransmit`, `segment-retransmit`, `timeout` | system-wide TCP counters changed during the run |
| `nic-error` | error or drop counters of the outgoing interface changed during the run |

Where the numbers come from:

- Per connection: `TCP_INFO` (RTT, RTT variance, retransmits, congestion window), read right after
  the connect and again after authentication.
- System-wide: `TcpRetransSegs` from `/proc/net/snmp`, `TCPSynRetrans` and `TCPTimeouts` from
  `/proc/net/netstat`. These include other traffic on the machine.
- Interface: `/sys/class/net/<iface>/statistics` for the interface that routes to the server.

A stall with no retransmit on the client side points to loss in the server-to-client direction or
to a delay on the server, which the client cannot see.

## TLS

`--sslmode require` encrypts the connection but does not verify the server certificate, the same as
libpq's `require`. `disable` is plain TCP. Other libpq modes are not supported.

Limitation: TLS is negotiated by this tool, and authentication runs without channel binding. A server
that requires `scram-sha-256-plus` (channel binding) rejects the connection.

## Tests

```
cargo test                                   # unit and CLI tests that need no server
PGHOST=... PGPORT=... PGUSER=... PGPASSWORD=... PGDATABASE=... cargo test --test cli -- --ignored
```

For a local test server with TLS (mount a directory with `server.crt` and `server.key` at `/in`):

```
podman run -d -p 55432:5432 -v ./certs:/in:Z -e POSTGRES_PASSWORD=benchpass -e POSTGRES_USER=bench \
  -e POSTGRES_DB=benchdb docker.io/library/postgres:18 sh -c 'cp /in/server.crt /in/server.key /tmp/ \
  && chown postgres:postgres /tmp/server.* && chmod 600 /tmp/server.key \
  && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key'
```

## License

GPL-3.0-only. See [LICENSE](LICENSE).
