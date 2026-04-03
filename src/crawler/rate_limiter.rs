use std::collections::HashMap;
use tokio::time::{Duration, Instant};

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate: f64) -> Self {
        Self {
            tokens: rate,
            max_tokens: rate,
            refill_rate: rate,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }
}

/// Per-domain rate limiter using the token bucket algorithm.
///
/// Each domain gets its own bucket that refills at `requests_per_second`.
/// Callers acquire a permit (which may require waiting) before making a request.
pub struct DomainRateLimiter {
    limiters: HashMap<String, TokenBucket>,
    default_rate: f64,
}

impl DomainRateLimiter {
    pub fn new(requests_per_second: f64) -> Self {
        Self {
            limiters: HashMap::new(),
            default_rate: requests_per_second,
        }
    }

    /// Returns the duration the caller must wait before sending a request.
    /// Internally consumes one token from the domain's bucket.
    pub fn acquire(&mut self, domain: &str) -> Duration {
        let rate = self.default_rate;
        let limiter = self
            .limiters
            .entry(domain.to_string())
            .or_insert_with(|| TokenBucket::new(rate));

        limiter.refill();

        let wait = if limiter.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let deficit = 1.0 - limiter.tokens;
            Duration::from_secs_f64(deficit / limiter.refill_rate)
        };

        limiter.tokens -= 1.0;
        wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_first_request_is_immediate() {
        let mut rl = DomainRateLimiter::new(10.0);
        let wait = rl.acquire("example.com");
        assert_eq!(wait, Duration::ZERO);
    }

    #[tokio::test]
    async fn test_burst_then_wait() {
        let mut rl = DomainRateLimiter::new(2.0);
        // First two requests should be immediate (burst = rate)
        assert_eq!(rl.acquire("example.com"), Duration::ZERO);
        assert_eq!(rl.acquire("example.com"), Duration::ZERO);
        // Third request should require waiting
        let wait = rl.acquire("example.com");
        assert!(wait > Duration::ZERO);
    }

    #[tokio::test]
    async fn test_different_domains_independent() {
        let mut rl = DomainRateLimiter::new(1.0);
        assert_eq!(rl.acquire("a.com"), Duration::ZERO);
        assert_eq!(rl.acquire("b.com"), Duration::ZERO);
    }

    #[tokio::test]
    async fn test_refill_after_wait() {
        let mut rl = DomainRateLimiter::new(10.0);
        // Exhaust the bucket
        for _ in 0..10 {
            rl.acquire("example.com");
        }
        // Wait for a refill
        tokio::time::sleep(Duration::from_millis(200)).await;
        let wait = rl.acquire("example.com");
        assert_eq!(wait, Duration::ZERO);
    }
}
