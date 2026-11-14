//! Limits on the connections the daemon accepts.
//!
//! The web server itself puts no limit on how many connections one client
//! opens, nor on how long a client may sit on one without sending
//! anything. Either lets a single machine hold the daemon's sockets until
//! it has none left. Here every accepted connection takes a slot (so many
//! in all, so many per address), and one that sends nothing for a while
//! is closed.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// At most this many connections are open at once.
pub const MAX_CONNECTIONS: usize = 1024;
/// At most this many of them may come from one address. A browser opens
/// about six.
pub const MAX_CONNECTIONS_PER_ADDRESS: usize = 64;
/// A connection on which nothing arrives for this long is closed.
pub const IDLE: Duration = Duration::from_secs(60);

#[derive(Default)]
struct Counts {
    total: usize,
    by_address: HashMap<IpAddr, usize>,
}

/// One connection's place in the counts; given back when it closes.
struct Slot {
    counts: Arc<Mutex<Counts>>,
    address: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().expect("lock");
        counts.total = counts.total.saturating_sub(1);
        if let Some(n) = counts.by_address.get_mut(&self.address) {
            *n -= 1;
            if *n == 0 {
                counts.by_address.remove(&self.address);
            }
        }
    }
}

/// The limits, shared by every connection of one listener.
#[derive(Clone)]
pub struct Limits {
    counts: Arc<Mutex<Counts>>,
    max_total: usize,
    max_per_address: usize,
    idle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self::new(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_ADDRESS, IDLE)
    }
}

impl Limits {
    pub fn new(max_total: usize, max_per_address: usize, idle: Duration) -> Self {
        Self {
            counts: Arc::default(),
            max_total,
            max_per_address,
            idle,
        }
    }

    /// Take a slot for a connection from `address`, or `None` when there
    /// is none left: the connection is then to be closed at once, since
    /// making it wait would let silent clients hold up everyone else.
    fn admit(&self, address: IpAddr) -> Option<Slot> {
        let mut counts = self.counts.lock().expect("lock");
        let mine = counts.by_address.get(&address).copied().unwrap_or(0);
        if counts.total >= self.max_total || mine >= self.max_per_address {
            return None;
        }
        counts.total += 1;
        counts.by_address.insert(address, mine + 1);
        Some(Slot {
            counts: self.counts.clone(),
            address,
        })
    }

    /// Wrap an accepted connection, or `None` when it must be dropped.
    pub fn guard<S>(&self, stream: S, address: IpAddr) -> Option<Guarded<S>> {
        let slot = self.admit(address)?;
        Some(Guarded {
            inner: stream,
            idle: Box::pin(tokio::time::sleep(self.idle)),
            limit: self.idle,
            _slot: slot,
        })
    }
}

/// A connection that holds a slot and is closed when nothing arrives on
/// it for too long.
pub struct Guarded<S> {
    inner: S,
    idle: Pin<Box<tokio::time::Sleep>>,
    limit: Duration,
    _slot: Slot,
}

impl<S: AsyncRead + Unpin> AsyncRead for Guarded<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                // Something arrived (or the other side closed): the
                // clock starts again.
                if buf.filled().len() > before {
                    let limit = self.limit;
                    self.idle
                        .as_mut()
                        .reset(tokio::time::Instant::now() + limit);
                }
                Poll::Ready(result)
            }
            Poll::Pending => match self.idle.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "nothing arrived on the connection for too long",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Guarded<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A listener whose connections are all guarded.
pub struct GuardedListener<L> {
    inner: L,
    limits: Limits,
}

impl<L> GuardedListener<L> {
    pub fn new(inner: L, limits: Limits) -> Self {
        Self { inner, limits }
    }
}

impl<L> axum::serve::Listener for GuardedListener<L>
where
    L: axum::serve::Listener<Addr = SocketAddr>,
    L::Io: Unpin,
{
    type Io = Guarded<L::Io>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = self.inner.accept().await;
            // No slot: the connection is dropped here, which closes it.
            if let Some(guarded) = self.limits.guard(stream, address.ip()) {
                return (guarded, address);
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn one_address_cannot_take_every_slot() {
        let limits = Limits::new(5, 2, IDLE);
        let (a, b): (IpAddr, IpAddr) = ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        let first = limits.admit(a).unwrap();
        let _second = limits.admit(a).unwrap();
        assert!(limits.admit(a).is_none(), "a third from one address");
        let _other = limits.admit(b).unwrap();
        // A slot comes back when its connection closes.
        drop(first);
        let _again = limits.admit(a).unwrap();
        let _fifth = limits.admit(b).unwrap();
        let _sixth = limits.admit("192.0.2.3".parse().unwrap()).unwrap();
        // The total is reached, whoever asks.
        assert!(limits.admit("192.0.2.4".parse().unwrap()).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_connection_is_closed() {
        let limits = Limits::new(5, 5, Duration::from_secs(60));
        let (client, server) = tokio::io::duplex(64);
        let mut guarded = limits.guard(server, "192.0.2.1".parse().unwrap()).unwrap();
        // The client holds its end open and sends nothing.
        let mut buf = [0u8; 8];
        let read = guarded.read(&mut buf).await;
        assert_eq!(read.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        drop(client);
        // Its slot is free again once it is dropped.
        drop(guarded);
        assert_eq!(limits.counts.lock().unwrap().total, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_keeps_sending_stays_open() {
        use tokio::io::AsyncWriteExt;
        let limits = Limits::new(5, 5, Duration::from_secs(60));
        let (mut client, server) = tokio::io::duplex(64);
        let mut guarded = limits.guard(server, "192.0.2.1".parse().unwrap()).unwrap();
        let mut buf = [0u8; 1];
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_secs(40)).await;
            client.write_all(b"x").await.unwrap();
            guarded.read_exact(&mut buf).await.unwrap();
        }
    }
}
