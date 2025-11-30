use std::net::SocketAddr;

use http_body_util::Empty;
use hyper::body::{Body, Incoming};
use hyper::http::uri::{Authority, Scheme};
use hyper::server::conn::http1;
use hyper::service::{HttpService, service_fn};
use hyper::{Request, Response, StatusCode, Uri, header};
use hyper_util::rt::TokioIo;
use std::io;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Accept either an HTTP or HTTPS connection using Hyper
pub struct HttpOrHttpsAcceptor {
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    upgrade: bool,
}

impl HttpOrHttpsAcceptor {
    /// Creates a new [`HttpOrHttpsAcceptor`] configured to only serve HTTP
    pub const fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            tls: None,
            upgrade: false,
        }
    }

    /// Configures this [`HttpOrHttpsAcceptor`] to serve HTTPS using the provided [`TlsAcceptor`].
    /// `upgrade` determines whether HTTP connections are automatically upgraded to HTTPS.
    ///
    /// If you need to create a [`TlsAcceptor`], see the helper functions in [`rustls_helpers`](crate::rustls_helpers)
    #[must_use]
    pub fn with_tls(mut self, tls: TlsAcceptor, upgrade: bool) -> Self {
        self.tls = Some(tls);
        self.upgrade = upgrade;
        self
    }

    /// Accepts a singular connection.
    /// Returns a the peer address of the connected client and a future that MUST be spawned to serve the connection.
    ///
    /// # Errors
    /// The function will return an error if the TCP connection fails, the returned future will return an error if the TLS handshake or Hyper service fails.
    pub async fn accept<S>(
        &self,
        service: S,
    ) -> Result<
        (
            SocketAddr,
            impl Future<Output = Result<(), AcceptorError>> + use<S>,
        ),
        AcceptorError,
    >
    where
        S: HttpService<Incoming> + 'static,
        <S::ResBody as Body>::Error: std::error::Error + Send + Sync,
    {
        let (stream, peer_addr) = self.listener.accept().await?;
        // The TlsAcceptor is a wrapper around an Arc, so this is relatively cheap
        let cloned_tls = self.tls.clone();

        let conn_fut = handle_conn(stream, cloned_tls, self.upgrade, service);
        Ok((peer_addr, conn_fut))
    }
}

async fn handle_conn<S>(
    mut stream: TcpStream,
    tls: Option<TlsAcceptor>,
    upgrade: bool,
    handler: S,
) -> Result<(), AcceptorError>
where
    S: HttpService<Incoming>,
    S::ResBody: 'static,
    <S::ResBody as Body>::Error: std::error::Error + Send + Sync,
{
    let mut typ = [0];
    let n = stream.peek(&mut typ).await?;
    if n == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
    }

    let is_https_conn = typ == [0x16];

    match tls {
        None => {
            if is_https_conn {
                // A "no shared protocols" TLS error alert
                // It seems to be the best message to use in this case
                // Encoded into a raw array here because it would be overkill to use the rustls
                // state machine to get these bytes
                let tls_error_msg = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
                stream.write_all(&tls_error_msg).await?;
                stream.shutdown().await?;
                return Err(io::Error::new(io::ErrorKind::InvalidData, "tls not enabled").into());
            }

            serve_connection(stream, handler).await
        }
        Some(tls) => {
            if !is_https_conn && upgrade {
                return serve_connection(stream, service_fn(upgrade_handler)).await;
            }
            let tls_stream = tls.accept(stream).await?;
            serve_connection(tls_stream, handler).await
        }
    }
}

async fn upgrade_handler(
    req: Request<Incoming>,
) -> Result<Response<Empty<&'static [u8]>>, std::convert::Infallible> {
    let authority = req
        .headers()
        .get(header::HOST)
        .and_then(|header| header.to_str().ok())
        .and_then(|host| Authority::try_from(host).ok());

    let scheme = match req.uri().scheme_str() {
        // Panics if ASCII is invalid, this is always valid
        Some("ws") => Some(Scheme::try_from("wss").unwrap()),
        Some("http") | None => Some(Scheme::HTTPS),
        _ => None,
    };

    if let (Some(authority), Some(scheme)) = (authority, scheme) {
        let mut uri = Uri::builder().scheme(scheme).authority(authority);

        if let Some(p_and_q) = req.uri().path_and_query() {
            uri = uri.path_and_query(p_and_q.clone());
        }

        // If the path and query was valid before, it must be valid now
        let uri = uri.build().unwrap();

        Ok(Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(header::LOCATION, uri.to_string())
            .body(Empty::new())
            .unwrap())
    } else {
        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Empty::new())
            .unwrap())
    }
}

async fn serve_connection<IO, S>(io: IO, handler: S) -> Result<(), AcceptorError>
where
    S: HttpService<Incoming>,
    S::ResBody: 'static,
    <S::ResBody as Body>::Error: std::error::Error + Send + Sync,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Ok(http1::Builder::new()
        .serve_connection(TokioIo::new(io), handler)
        .with_upgrades()
        .await?)
}

/// Error when accepting connections
#[derive(Error, Debug)]
pub enum AcceptorError {
    /// IO Error, either in TCP or TLS
    #[error("I/O errror (TLS or TCP)")]
    IO(#[from] std::io::Error),
    /// Hyper failed to serve connection
    #[error("hyper error")]
    Hyper(#[from] hyper::Error),
}

impl AcceptorError {
    #[must_use]
    pub fn ignorable(&self) -> bool {
        match self {
            Self::IO(err) => matches!(
                err.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::InvalidData
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::InvalidInput
            ),
            Self::Hyper(_) => true,
        }
    }
}
