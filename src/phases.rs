//! The timed connection phases: DNS resolution, TCP connect, optional TLS handshake, and
//! authentication (see `handshake`). A failed run says which phase failed and how long it ran.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::handshake::{self, AuthTimings, Credentials};
use crate::socket_info::{self, SocketSnapshot};

/// Postgres SSLRequest: length 8, request code 80877103 (0x04D2162F).
const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F];

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub dbname: Option<String>,
    pub password: Option<String>,
    pub tls: Option<Arc<ClientConfig>>,
}

#[derive(Debug, Clone, Copy)]
pub struct Timings {
    pub dns: Duration,
    pub tcp: Duration,
    pub tls: Option<Duration>,
    pub auth: AuthTimings,
    /// TCP state right after the connect, which includes any SYN retransmissions.
    pub socket_after_tcp: Option<SocketSnapshot>,
    /// TCP state after authentication, before the connection is closed.
    pub socket_after_auth: Option<SocketSnapshot>,
}

/// The step of a connection that a failed run stopped in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Dns,
    Tcp,
    Tls,
    Auth,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Phase::Dns => "dns",
            Phase::Tcp => "tcp",
            Phase::Tls => "tls",
            Phase::Auth => "auth",
        })
    }
}

/// A run that failed: the phase, how long that phase ran before failing, and the error.
#[derive(Debug)]
pub struct RunFailure {
    pub phase: Phase,
    pub elapsed: Duration,
    pub error: anyhow::Error,
}

/// Run one step and time it, whether it succeeds or fails.
async fn step<T>(
    phase: Phase,
    fut: impl Future<Output = Result<T>>,
) -> Result<(T, Duration), RunFailure> {
    let start = Instant::now();
    match fut.await {
        Ok(value) => Ok((value, start.elapsed())),
        Err(error) => Err(RunFailure {
            phase,
            elapsed: start.elapsed(),
            error,
        }),
    }
}

/// Resolve the target host to every address found.
pub async fn resolve(target: &Target) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = lookup_host((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("DNS resolution failed for {}", target.host))?
        .collect();

    if addrs.is_empty() {
        bail!("DNS resolution returned no addresses for {}", target.host);
    }

    Ok(addrs)
}

async fn connect(addr: SocketAddr) -> Result<TcpStream> {
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("TCP connect to {addr} failed"))?;
    // Like libpq: without TCP_NODELAY, Nagle's algorithm and delayed ACKs stall small TLS records.
    stream
        .set_nodelay(true)
        .context("setting TCP_NODELAY failed")?;
    Ok(stream)
}

/// Ask for TLS and run the handshake over the same socket.
async fn upgrade(
    mut stream: TcpStream,
    tls_config: &ClientConfig,
    host: &str,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + use<>> {
    stream
        .write_all(&SSL_REQUEST)
        .await
        .context("sending SSLRequest failed")?;
    let mut answer = [0u8; 1];
    stream
        .read_exact(&mut answer)
        .await
        .context("reading SSLRequest answer failed")?;
    if answer[0] != b'S' {
        bail!("server refused TLS (answered {:?})", char::from(answer[0]));
    }

    let mut maker = MakeRustlsConnect::new(tls_config.clone());
    let connector = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut maker, host)
        .context("invalid TLS server name")?;
    connector
        .connect(stream)
        .await
        .context("TLS handshake failed")
}

/// Run one full connection: DNS, TCP, optional TLS, authentication. The connection is closed
/// afterwards, outside every timed step.
pub async fn run_once(target: &Target) -> Result<(Timings, SocketAddr), RunFailure> {
    let (addrs, dns) = step(Phase::Dns, resolve(target)).await?;
    let addr = addrs[0];

    let (mut stream, tcp) = step(Phase::Tcp, connect(addr)).await?;
    let fd = stream.as_raw_fd();
    let socket_after_tcp = socket_info::snapshot(fd);

    let creds = Credentials {
        user: &target.user,
        dbname: target.dbname.as_deref(),
        password: target.password.as_deref().map(str::as_bytes),
    };

    let (tls, (auth, socket_after_auth)) = if let Some(tls_config) = &target.tls {
        let (mut tls_stream, tls) =
            step(Phase::Tls, upgrade(stream, tls_config, &target.host)).await?;
        let (outcome, _) = step(
            Phase::Auth,
            authenticate_and_close(&mut tls_stream, &creds, fd),
        )
        .await?;
        (Some(tls), outcome)
    } else {
        let (outcome, _) =
            step(Phase::Auth, authenticate_and_close(&mut stream, &creds, fd)).await?;
        (None, outcome)
    };

    Ok((
        Timings {
            dns,
            tcp,
            tls,
            auth,
            socket_after_tcp,
            socket_after_auth,
        },
        addr,
    ))
}

/// Authenticate, read the socket state, then close. The socket state is read before the close, so
/// the Terminate message is not counted.
async fn authenticate_and_close<S>(
    stream: &mut S,
    creds: &Credentials<'_>,
    fd: std::os::fd::RawFd,
) -> Result<(AuthTimings, Option<SocketSnapshot>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let auth = handshake::authenticate(stream, creds).await?;
    let socket = socket_info::snapshot(fd);
    handshake::close(stream).await?;
    Ok((auth, socket))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn target(port: u16, tls: Option<Arc<ClientConfig>>) -> Target {
        Target {
            host: "127.0.0.1".to_string(),
            port,
            user: "u".to_string(),
            dbname: None,
            password: None,
            tls,
        }
    }

    #[test]
    fn ssl_request_has_length_8_and_postgres_code() {
        assert_eq!(u32::from_be_bytes(SSL_REQUEST[0..4].try_into().unwrap()), 8);
        assert_eq!(
            u32::from_be_bytes(SSL_REQUEST[4..8].try_into().unwrap()),
            80_877_103
        );
    }

    #[tokio::test]
    async fn resolve_ip_literal_returns_that_address_without_dns() {
        let addrs = resolve(&target(5432, None)).await.unwrap();
        assert_eq!(addrs, vec!["127.0.0.1:5432".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn tcp_refused_port_fails_at_tcp_step() {
        // Bind and drop to get a port nothing listens on.
        let port = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let failure = run_once(&target(port, None)).await.unwrap_err();

        assert_eq!(failure.phase, Phase::Tcp);
        assert!(
            format!("{:#}", failure.error).contains("TCP connect"),
            "{:#}",
            failure.error
        );
    }

    #[tokio::test]
    async fn server_refusing_tls_fails_at_tls_step() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 8];
            sock.read_exact(&mut req).await.unwrap();
            sock.write_all(b"N").await.unwrap();
        });
        let tls = Arc::new(crate::tls::no_verify_config().unwrap());

        let failure = run_once(&target(port, Some(tls))).await.unwrap_err();

        assert_eq!(failure.phase, Phase::Tls);
        assert!(
            format!("{:#}", failure.error).contains("refused TLS"),
            "{:#}",
            failure.error
        );
    }

    /// A fake server: accepts the startup, reports AuthenticationOk and ReadyForQuery, then records
    /// the client's next message and whether the socket is closed after it.
    async fn fake_server_once(listener: TcpListener) -> (u8, bool) {
        let (mut sock, _) = listener.accept().await.unwrap();

        let len = sock.read_u32().await.unwrap() as usize;
        let mut startup = vec![0u8; len - 4];
        sock.read_exact(&mut startup).await.unwrap();

        // AuthenticationOk ('R', length 8, code 0), then ReadyForQuery ('Z', length 5, idle 'I').
        sock.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0])
            .await
            .unwrap();
        sock.write_all(&[b'Z', 0, 0, 0, 5, b'I']).await.unwrap();

        let kind = sock.read_u8().await.unwrap();
        let body_len = sock.read_u32().await.unwrap() as usize;
        let mut body = vec![0u8; body_len - 4];
        sock.read_exact(&mut body).await.unwrap();

        // After Terminate the client must close the socket: the next read sees end of file.
        let mut rest = [0u8; 1];
        let closed = sock.read(&mut rest).await.unwrap() == 0;

        (kind, closed)
    }

    #[tokio::test]
    async fn run_once_sends_terminate_and_closes_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(fake_server_once(listener));

        run_once(&target(port, None)).await.unwrap();

        let (kind, closed) = server.await.unwrap();
        assert_eq!(kind, b'X', "client must send Terminate");
        assert!(closed, "socket must close after Terminate");
    }

    #[test]
    fn phase_names_are_short_lowercase() {
        assert_eq!(
            [Phase::Dns, Phase::Tcp, Phase::Tls, Phase::Auth].map(|p| p.to_string()),
            ["dns", "tcp", "tls", "auth"]
        );
    }
}
