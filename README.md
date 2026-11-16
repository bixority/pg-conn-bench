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

Releases are also published to the Bixority cargo registry on Codeberg:

```
cargo install pg-conn-bench --index sparse+https://codeberg.org/api/packages/bixority/cargo/
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

## Container

Build the image with any OCI-compatible tool:

```
podman build -t pg-conn-bench .
```

The image supports `amd64` and `arm64` platforms and uses a minimal distroless runtime.

### Running locally with podman

Pull the image from GitHub Container Registry and pass connection settings as environment variables:

```
podman run --rm -it \
  -e PGHOST=postgres.example.com \
  -e PGPORT=5432 \
  -e PGUSER=postgres \
  -e PGPASSWORD=changeme \
  -e PGDATABASE=postgres \
  ghcr.io/bixority/pg-conn-bench:main --runs 10 --details
```

### Local testing with Compose

Run against a local PostgreSQL 18.7 instance:

```
compose up --build
```

Re-run the benchmark without rebuilding:

```
compose run --rm pg-conn-bench
```

### Running on Kubernetes

First, create a secret for the database password:

```
kubectl create secret generic pg-conn-bench-secret \
  --from-literal=PGPASSWORD='changeme'
```

Then run the benchmark as a one-shot pod:

```
kubectl run pg-conn-bench --restart=Never --image=ghcr.io/bixority/pg-conn-bench:main \
  --env=PGHOST=postgres.example.com \
  --env=PGPORT=5432 \
  --env=PGUSER=postgres \
  --env=PGDATABASE=postgres \
  --env=PGSSLMODE=disable \
  --env-from=secret/pg-conn-bench-secret \
  --limits='cpu=500m,memory=128Mi' \
  -- /pg-conn-bench --runs 10 --details
```

Follow the output with `kubectl logs -f pg-conn-bench`. The pod exits after the benchmark
completes. For recurring benchmarks, wrap the same command in a `CronJob` manifest.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
