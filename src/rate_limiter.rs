use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    // Track claims by IP address
    ip_claims: Mutex<HashMap<String, Instant>>,
    // Track claims by destination address to prevent same address abuse
    address_claims: Mutex<HashMap<String, Instant>>,
    // Track lifetime claims per address (never expires, prevents address reuse)
    address_lifetime_claims: Mutex<HashMap<String, u32>>,
    // Track IP subnet (/24 for IPv4, /64 for IPv6) to detect VPN patterns
    subnet_claims: Mutex<HashMap<String, (Instant, u32)>>,
    // Track rapid requests from different IPs to same address (VPN detection)
    address_ip_rotations: Mutex<HashMap<String, (Vec<String>, Instant)>>,
    interval: Duration,
    // Cleanup threshold: remove entries older than 2x interval
    cleanup_threshold: Duration,
    // Maximum lifetime claims per address
    max_lifetime_claims_per_address: u32,
    // Maximum claims per subnet within interval
    max_subnet_claims: u32,
    // Maximum IP rotations per address within window
    max_ip_rotations: u32,
}

impl RateLimiter {
    pub fn new(interval: Duration) -> Self {
        Self {
            ip_claims: Mutex::new(HashMap::new()),
            address_claims: Mutex::new(HashMap::new()),
            address_lifetime_claims: Mutex::new(HashMap::new()),
            subnet_claims: Mutex::new(HashMap::new()),
            address_ip_rotations: Mutex::new(HashMap::new()),
            interval,
            cleanup_threshold: interval * 2,
            max_lifetime_claims_per_address: 3, // Allow max 3 claims per address ever
            max_subnet_claims: 5,               // Max 5 claims from same subnet per interval
            max_ip_rotations: 3,                // Max 3 different IPs per address in short window
        }
    }

    /// Extract subnet from IP address (/24 for IPv4, /64 for IPv6)
    fn extract_subnet(ip: &str) -> String {
        if ip.contains(':') {
            // IPv6 - use first 64 bits (first 4 groups)
            ip.split(':').take(4).collect::<Vec<_>>().join(":")
        } else {
            // IPv4 - use /24 (first 3 octets)
            ip.rsplitn(2, '.').nth(1).unwrap_or(ip).to_string() + ".0"
        }
    }

    /// Check if a claim is allowed for the given IP and address
    /// Returns (allowed, reason) where reason is None if allowed
    pub fn try_claim(&self, ip: &str, address: &str) -> (bool, Option<&'static str>) {
        let mut ip_claims = self.ip_claims.lock().unwrap();
        let mut address_claims = self.address_claims.lock().unwrap();
        let mut lifetime_claims = self.address_lifetime_claims.lock().unwrap();
        let mut subnet_claims = self.subnet_claims.lock().unwrap();
        let mut ip_rotations = self.address_ip_rotations.lock().unwrap();

        // Cleanup old entries periodically
        if ip_claims.len() > 1000 {
            Self::cleanup_map(&mut ip_claims, self.cleanup_threshold);
        }
        if address_claims.len() > 1000 {
            Self::cleanup_map(&mut address_claims, self.cleanup_threshold);
        }
        if subnet_claims.len() > 1000 {
            let now = Instant::now();
            subnet_claims
                .retain(|_, (instant, _)| now.duration_since(*instant) < self.cleanup_threshold);
        }
        if ip_rotations.len() > 1000 {
            let now = Instant::now();
            ip_rotations.retain(|_, (_, instant)| now.duration_since(*instant) < self.interval * 2);
        }

        let normalized_address = address.to_lowercase().trim().to_string();
        let subnet = Self::extract_subnet(ip);
        let now = Instant::now();

        // 1. Check IP-based rate limiting
        if let Some(last) = ip_claims.get(ip) {
            if last.elapsed() < self.interval {
                return (false, Some("IP rate limit"));
            }
        }

        // 2. Check address-based rate limiting (time window)
        if let Some(last) = address_claims.get(&normalized_address) {
            if last.elapsed() < self.interval {
                return (false, Some("Address rate limit"));
            }
        }

        // 3. Check lifetime address claims (hard limit)
        let lifetime_count = lifetime_claims
            .get(&normalized_address)
            .copied()
            .unwrap_or(0);
        if lifetime_count >= self.max_lifetime_claims_per_address {
            return (false, Some("Address lifetime limit exceeded"));
        }

        // 4. Check subnet-based rate limiting (detect VPN ranges)
        let subnet_entry = subnet_claims.entry(subnet.clone()).or_insert((now, 0));
        if subnet_entry.0.elapsed() < self.interval {
            if subnet_entry.1 >= self.max_subnet_claims {
                return (false, Some("Subnet rate limit (possible VPN abuse)"));
            }
            subnet_entry.1 += 1;
        } else {
            // Reset counter for new window
            subnet_entry.0 = now;
            subnet_entry.1 = 1;
        }

        // 5. Check IP rotation pattern (detect VPN switching)
        let rotation_entry = ip_rotations
            .entry(normalized_address.clone())
            .or_insert_with(|| (Vec::new(), now));
        if rotation_entry.1.elapsed() < self.interval {
            // Check if this IP is new for this address
            if !rotation_entry.0.contains(&ip.to_string()) {
                rotation_entry.0.push(ip.to_string());
                if rotation_entry.0.len() > self.max_ip_rotations as usize {
                    return (false, Some("Too many IP rotations (possible VPN abuse)"));
                }
            }
        } else {
            // Reset for new window
            rotation_entry.0.clear();
            rotation_entry.0.push(ip.to_string());
            rotation_entry.1 = now;
        }

        // All checks passed, record the claim
        ip_claims.insert(ip.to_string(), now);
        address_claims.insert(normalized_address.clone(), now);
        *lifetime_claims.entry(normalized_address).or_insert(0) += 1;

        (true, None)
    }

    /// Clean up old entries from a HashMap
    fn cleanup_map(map: &mut HashMap<String, Instant>, threshold: Duration) {
        let now = Instant::now();
        map.retain(|_, instant| now.duration_since(*instant) < threshold);
    }
}
