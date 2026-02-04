use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    claims: Mutex<HashMap<String, Instant>>,
    interval: Duration,
}

impl RateLimiter {
    pub fn new(interval: Duration) -> Self {
        Self {
            claims: Mutex::new(HashMap::new()),
            interval,
        }
    }

    pub fn try_claim(&self, ip: &str) -> bool {
        let mut claims = self.claims.lock().unwrap();
        if let Some(last) = claims.get(ip) {
            if last.elapsed() < self.interval {
                return false;
            }
        }
        claims.insert(ip.to_string(), Instant::now());
        true
    }
}
