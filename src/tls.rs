//! HTTPS for the daemon: a listener that finishes the TLS handshake before
//! handing a connection to the web server.
//!
//! Handshakes run in their own tasks with a time limit, so a client that
//! connects and then says nothing cannot hold up anyone else. The
//! certificate files are read again when they change, so a renewed
//! certificate is picked up without a restart.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// A handshake must finish within this.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// At most this many handshakes are in progress at once; further
/// connections wait their turn.
const MAX_HANDSHAKES: usize = 256;

/// Read a certificate chain and its key, and build the TLS settings.
pub fn load(cert: &Path, key: &Path) -> Result<rustls::ServerConfig, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("cannot read {}: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("{} holds no certificate", cert.display()));
    }
    // The error names the file, never its contents.
    let key_der = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| format!("cannot read a private key from {}: {e}", key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key_der)
        .map_err(|e| format!("the certificate and key cannot be used together: {e}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// A TCP listener whose connections arrive with TLS already set up.
pub struct TlsListener {
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl TlsListener {
    /// Wrap a bound listener. `config` is what [`load`] gave for the two
    /// files; they are read again whenever either changes on disk.
    pub fn new(
        tcp: TcpListener,
        config: rustls::ServerConfig,
        cert: PathBuf,
        key: PathBuf,
        log: impl Fn(&str) + Send + Sync + 'static,
    ) -> std::io::Result<Self> {
        let local = tcp.local_addr()?;
        let (send, ready) = mpsc::channel(64);
        let task = tokio::spawn(async move {
            let mut acceptor = TlsAcceptor::from(Arc::new(config));
            let mut stamp = (modified(&cert), modified(&key));
            let slots = Arc::new(Semaphore::new(MAX_HANDSHAKES));
            loop {
                let (stream, peer) = match tcp.accept().await {
                    Ok(pair) => pair,
                    Err(_) => {
                        // Out of file descriptors, most likely; give the
                        // system a moment rather than spin.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let now = (modified(&cert), modified(&key));
                if now != stamp {
                    stamp = now;
                    match load(&cert, &key) {
                        Ok(config) => {
                            acceptor = TlsAcceptor::from(Arc::new(config));
                            log("the TLS certificate changed on disk and was loaded again");
                        }
                        // Keep serving with the one that works.
                        Err(e) => log(&format!("the changed TLS certificate was not loaded: {e}")),
                    }
                }
                let Ok(slot) = slots.clone().acquire_owned().await else {
                    return;
                };
                let (acceptor, send) = (acceptor.clone(), send.clone());
                tokio::spawn(async move {
                    let handshake =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream));
                    if let Ok(Ok(tls)) = handshake.await {
                        drop(slot);
                        let _ = send.send((tls, peer)).await;
                    }
                });
            }
        });
        Ok(Self { ready, local, task })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(pair) => pair,
            // The accepting task is gone; nothing more will arrive.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}
