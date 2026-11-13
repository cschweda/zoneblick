//! Politeness: bounded global concurrency and a per-server query rate cap.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::{Semaphore, SemaphorePermit};
use tokio::time::Instant;

pub struct Limiter {
    global: Semaphore,
    min_interval: Duration,
    next_slot: Mutex<HashMap<IpAddr, Instant>>,
}

impl Limiter {
    /// `concurrency` queries may be in flight at once; each server address
    /// is sent at most `qps_per_server` queries per second.
    pub fn new(concurrency: usize, qps_per_server: u32) -> Self {
        Self {
            global: Semaphore::new(concurrency.max(1)),
            min_interval: Duration::from_secs(1) / qps_per_server.max(1),
            next_slot: Mutex::new(HashMap::new()),
        }
    }

    /// Wait for this server's next send slot, then for a concurrency permit.
    /// Hold the permit for as long as the query is in flight.
    pub async fn acquire(&self, server: IpAddr) -> SemaphorePermit<'_> {
        let slot = {
            let mut next = self.next_slot.lock().expect("limiter lock");
            let now = Instant::now();
            let slot = next.get(&server).copied().unwrap_or(now).max(now);
            next.insert(server, slot + self.min_interval);
            slot
        };
        tokio::time::sleep_until(slot).await;
        self.global
            .acquire()
            .await
            .expect("semaphore is never closed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn spaces_queries_to_one_server() {
        let limiter = Limiter::new(16, 5);
        let server: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        let start = Instant::now();
        for _ in 0..3 {
            drop(limiter.acquire(server).await);
        }
        assert_eq!(start.elapsed(), Duration::from_millis(400));
        // A different server is not held back.
        drop(limiter.acquire(other).await);
        assert_eq!(start.elapsed(), Duration::from_millis(400));
    }

    #[tokio::test(start_paused = true)]
    async fn bounds_concurrency() {
        let limiter = Limiter::new(1, 1000);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let held = limiter.acquire(a).await;
        let waiting = tokio::time::timeout(Duration::from_secs(1), limiter.acquire(b)).await;
        assert!(waiting.is_err(), "second query must wait for the permit");
        drop(held);
        drop(limiter.acquire(b).await);
    }
}
