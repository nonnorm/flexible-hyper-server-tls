use flexible_hyper_server_tls::*;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use std::convert::Infallible;
use tokio::net::TcpListener;

const CERT_DATA: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/certs/cert.pem"
));
const KEY_DATA: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/certs/key.pem"
));

async fn hello_world(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::<Bytes>::from("Hello, World!")))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let use_tls = true;

    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();

    let mut acceptor = HttpOrHttpsAcceptor::new(listener);

    if use_tls {
        let tls = rustls_helpers::get_tlsacceptor_from_pem_data(CERT_DATA, KEY_DATA).unwrap();
        acceptor = acceptor.with_tls(tls, false);
    }

    loop {
        if let Ok((peer_addr, conn_fut)) = acceptor.accept(service_fn(hello_world)).await {
            println!("New connection from {peer_addr}");

            tokio::spawn(async move {
                if let Err(err) = conn_fut.await {
                    eprintln!("Error serving connection: {err:?}")
                }
            });
        }
    }
}
