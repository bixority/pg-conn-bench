//! Startup and authentication, one protocol message at a time, so each step can be timed.
//!
//! This replaces tokio-postgres' `connect_raw`, which runs the whole exchange in one call. The
//! framing and the SCRAM client come from `postgres-protocol`, the crate tokio-postgres itself uses,
//! so the same messages go over the wire.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::BytesMut;
use fallible_iterator::FallibleIterator;
use postgres_protocol::authentication::md5_hash;
use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256};
use postgres_protocol::message::backend::Message;
use postgres_protocol::message::frontend;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const SCRAM_MECHANISM: &str = "SCRAM-SHA-256";

/// Durations of the three SCRAM exchanges, when the server asked for SCRAM.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScramTimings {
    /// Client-first sent until server-first received.
    pub first: Duration,
    /// Client-side SCRAM computation (PBKDF2 and proof) between server-first and client-final.
    pub derive: Duration,
    /// Client-final sent until server-final received.
    pub last: Duration,
}

/// Where the time of one authentication went.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AuthTimings {
    /// StartupMessage sent until ReadyForQuery received.
    pub total: Duration,
    /// StartupMessage sent until the server's first reply (an authentication request or an error).
    pub startup: Duration,
    /// Password or MD5 reply sent until AuthenticationOk, if the server asked for one.
    pub reply: Option<Duration>,
    /// SCRAM exchange, if the server asked for SCRAM.
    pub scram: Option<ScramTimings>,
    /// AuthenticationOk received until ReadyForQuery received.
    pub ready: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct Credentials<'a> {
    pub user: &'a str,
    pub dbname: Option<&'a str>,
    pub password: Option<&'a [u8]>,
}

/// Reads backend messages and remembers when the bytes of the latest socket read arrived.
struct Reader<'a, S> {
    stream: &'a mut S,
    buf: BytesMut,
    arrived: Instant,
}

impl<S: AsyncRead + Unpin> Reader<'_, S> {
    /// The next message, with the time its bytes arrived.
    async fn next(&mut self) -> Result<(Message, Instant)> {
        loop {
            if let Some(msg) = Message::parse(&mut self.buf).context("malformed server message")? {
                return Ok((msg, self.arrived));
            }
            let read = self
                .stream
                .read_buf(&mut self.buf)
                .await
                .context("reading from the server failed")?;
            self.arrived = Instant::now();
            if read == 0 {
                bail!("server closed the connection during authentication");
            }
        }
    }
}

/// Write the buffered bytes and return the time just before the write started.
async fn send<S: AsyncWrite + Unpin>(stream: &mut S, out: &mut BytesMut) -> Result<Instant> {
    let sent = Instant::now();
    stream
        .write_all(out)
        .await
        .context("writing to the server failed")?;
    out.clear();
    Ok(sent)
}

fn password<'a>(creds: &Credentials<'a>) -> Result<&'a [u8]> {
    creds
        .password
        .context("server asked for a password, but PGPASSWORD is not set")
}

/// Send the StartupMessage and run authentication until ReadyForQuery, timing each step.
pub async fn authenticate<S>(stream: &mut S, creds: &Credentials<'_>) -> Result<AuthTimings>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut params = vec![("user", creds.user)];
    if let Some(dbname) = creds.dbname {
        params.push(("database", dbname));
    }
    let mut out = BytesMut::new();
    frontend::startup_message(params, &mut out).context("building the startup message failed")?;

    let start = Instant::now();
    let sent_startup = send(stream, &mut out).await?;
    let mut rd = Reader {
        stream,
        buf: BytesMut::new(),
        arrived: sent_startup,
    };

    let mut startup = None;
    let mut reply_sent = None;
    let mut reply = None;
    let mut scram = None;
    let mut scram_first_sent = None;
    let mut scram_final_sent = None;
    let mut ok_at = None;

    loop {
        let (msg, at) = rd.next().await?;
        startup.get_or_insert(at - start);

        match msg {
            Message::AuthenticationOk => {
                if let Some(sent) = reply_sent.take() {
                    reply = Some(at - sent);
                }
                ok_at = Some(at);
            }
            Message::AuthenticationCleartextPassword => {
                frontend::password_message(password(creds)?, &mut out)
                    .context("building the password message failed")?;
                reply_sent = Some(send(rd.stream, &mut out).await?);
            }
            Message::AuthenticationMd5Password(body) => {
                let hashed = md5_hash(creds.user.as_bytes(), password(creds)?, body.salt());
                frontend::password_message(hashed.as_bytes(), &mut out)
                    .context("building the password message failed")?;
                reply_sent = Some(send(rd.stream, &mut out).await?);
            }
            Message::AuthenticationSasl(body) => {
                let mut mechanisms = body.mechanisms();
                let mut offered = false;
                while let Some(mechanism) = mechanisms
                    .next()
                    .context("reading SASL mechanisms failed")?
                {
                    offered |= mechanism == SCRAM_MECHANISM;
                }
                if !offered {
                    bail!(
                        "server offers no SASL mechanism this tool supports (needs {SCRAM_MECHANISM})"
                    );
                }
                let client = ScramSha256::new(password(creds)?, ChannelBinding::unsupported());
                frontend::sasl_initial_response(SCRAM_MECHANISM, client.message(), &mut out)
                    .context("building the SASL response failed")?;
                scram_first_sent = Some(send(rd.stream, &mut out).await?);
                scram = Some((
                    client,
                    ScramTimings {
                        first: Duration::ZERO,
                        derive: Duration::ZERO,
                        last: Duration::ZERO,
                    },
                ));
            }
            Message::AuthenticationSaslContinue(body) => {
                let (client, timings) =
                    scram.as_mut().context("SASL continue without SASL start")?;
                let sent = scram_first_sent.context("SASL continue without SASL start")?;
                timings.first = at - sent;

                let derive_start = Instant::now();
                client
                    .update(body.data())
                    .context("SCRAM server-first message is invalid")?;
                timings.derive = derive_start.elapsed();

                frontend::sasl_response(client.message(), &mut out)
                    .context("building the SASL response failed")?;
                scram_final_sent = Some(send(rd.stream, &mut out).await?);
            }
            Message::AuthenticationSaslFinal(body) => {
                let (client, timings) = scram.as_mut().context("SASL final without SASL start")?;
                let sent = scram_final_sent.context("SASL final without client-final")?;
                timings.last = at - sent;
                client
                    .finish(body.data())
                    .context("SCRAM server signature does not match")?;
            }
            Message::ReadyForQuery(_) => {
                let ok = ok_at.context("ReadyForQuery before AuthenticationOk")?;
                return Ok(AuthTimings {
                    total: at - start,
                    startup: startup.unwrap_or_default(),
                    reply,
                    scram: scram.map(|(_, timings)| timings),
                    ready: at - ok,
                });
            }
            Message::ErrorResponse(body) => {
                bail!("server rejected the connection: {}", error_message(&body)?);
            }
            Message::ParameterStatus(_)
            | Message::BackendKeyData(_)
            | Message::NoticeResponse(_) => {}
            _ => bail!("unexpected message during authentication"),
        }
    }
}

/// Send Terminate and shut the write side down, so the server sees a clean disconnect.
pub async fn close<S: AsyncWrite + Unpin>(stream: &mut S) -> Result<()> {
    let mut out = BytesMut::new();
    frontend::terminate(&mut out);
    stream
        .write_all(&out)
        .await
        .context("sending Terminate failed")?;
    stream
        .shutdown()
        .await
        .context("closing the connection failed")
}

fn error_message(body: &postgres_protocol::message::backend::ErrorResponseBody) -> Result<String> {
    let mut fields = body.fields();
    while let Some(field) = fields.next().context("malformed error response")? {
        if field.type_() == b'M' {
            return Ok(String::from_utf8_lossy(field.value_bytes()).into_owned());
        }
    }
    Ok("no message".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{DuplexStream, duplex};

    fn backend(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut msg = vec![tag];
        msg.extend(((body.len() + 4) as u32).to_be_bytes());
        msg.extend(body);
        msg
    }

    fn auth_ok() -> Vec<u8> {
        backend(b'R', &0u32.to_be_bytes())
    }

    fn ready() -> Vec<u8> {
        backend(b'Z', b"I")
    }

    fn creds(password: Option<&'static [u8]>) -> Credentials<'static> {
        Credentials {
            user: "app",
            dbname: Some("db"),
            password,
        }
    }

    /// Read one frontend message: its tag and body (the length prefix is stripped).
    async fn read_frontend(server: &mut DuplexStream) -> (u8, Vec<u8>) {
        let tag = server.read_u8().await.unwrap();
        let len = server.read_u32().await.unwrap() as usize;
        let mut body = vec![0u8; len - 4];
        server.read_exact(&mut body).await.unwrap();
        (tag, body)
    }

    /// Read the StartupMessage (no tag, length-prefixed) and return the bytes it carried.
    async fn read_startup(server: &mut DuplexStream) -> Vec<u8> {
        let len = server.read_u32().await.unwrap() as usize;
        let mut body = vec![0u8; len - 4];
        server.read_exact(&mut body).await.unwrap();
        body
    }

    #[tokio::test]
    async fn trust_auth_skips_reply_and_scram() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            read_startup(&mut server).await;
            server
                .write_all(&[auth_ok(), ready()].concat())
                .await
                .unwrap();
        });

        let t = authenticate(&mut client, &creds(None)).await.unwrap();

        assert!(t.reply.is_none());
        assert!(t.scram.is_none());
        assert!(t.total >= t.startup);
    }

    #[tokio::test]
    async fn startup_message_carries_user_and_database() {
        let (mut client, mut server) = duplex(4096);
        let seen = tokio::spawn(async move {
            let body = read_startup(&mut server).await;
            server
                .write_all(&[auth_ok(), ready()].concat())
                .await
                .unwrap();
            body
        });

        authenticate(&mut client, &creds(None)).await.unwrap();

        let body = seen.await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("user\0app\0"), "{text:?}");
        assert!(text.contains("database\0db\0"), "{text:?}");
    }

    #[tokio::test]
    async fn cleartext_password_is_sent_and_timed() {
        let (mut client, mut server) = duplex(4096);
        let sent = tokio::spawn(async move {
            read_startup(&mut server).await;
            server
                .write_all(&backend(b'R', &3u32.to_be_bytes()))
                .await
                .unwrap();
            let reply = read_frontend(&mut server).await;
            server
                .write_all(&[auth_ok(), ready()].concat())
                .await
                .unwrap();
            reply
        });

        let t = authenticate(&mut client, &creds(Some(b"secret")))
            .await
            .unwrap();

        let (tag, body) = sent.await.unwrap();
        assert_eq!(tag, b'p');
        assert_eq!(body, b"secret\0");
        assert!(t.reply.is_some());
    }

    #[tokio::test]
    async fn password_request_without_password_fails() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            read_startup(&mut server).await;
            server
                .write_all(&backend(b'R', &3u32.to_be_bytes()))
                .await
                .unwrap();
        });

        let err = authenticate(&mut client, &creds(None)).await.unwrap_err();

        assert!(format!("{err:#}").contains("PGPASSWORD"), "{err:#}");
    }

    #[tokio::test]
    async fn server_error_message_is_reported() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            read_startup(&mut server).await;
            // ErrorResponse fields: 'S' severity, 'M' message, each NUL-terminated, then a final NUL.
            server
                .write_all(&backend(
                    b'E',
                    b"SFATAL\0Mpassword authentication failed\0\0",
                ))
                .await
                .unwrap();
        });

        let err = authenticate(&mut client, &creds(None)).await.unwrap_err();

        assert!(
            format!("{err:#}").contains("password authentication failed"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn server_without_scram_is_rejected() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            read_startup(&mut server).await;
            server
                .write_all(&backend(
                    b'R',
                    &[10u32.to_be_bytes().as_slice(), b"SCRAM-SHA-256-PLUS\0\0"].concat(),
                ))
                .await
                .unwrap();
        });

        let err = authenticate(&mut client, &creds(Some(b"pw")))
            .await
            .unwrap_err();

        assert!(format!("{err:#}").contains("no SASL mechanism"), "{err:#}");
    }

    #[tokio::test]
    async fn server_closing_early_fails() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            read_startup(&mut server).await;
            drop(server);
        });

        let err = authenticate(&mut client, &creds(None)).await.unwrap_err();

        assert!(
            format!("{err:#}").contains("closed the connection"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn close_sends_terminate_then_shuts_down() {
        let (mut client, mut server) = duplex(4096);

        close(&mut client).await.unwrap();

        let (tag, body) = read_frontend(&mut server).await;
        assert_eq!(tag, b'X');
        assert!(body.is_empty());
        assert_eq!(server.read_u8().await.ok(), None, "stream must be at EOF");
    }
}
