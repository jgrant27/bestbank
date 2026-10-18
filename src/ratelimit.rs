//! Per-client-IP rate limiting for login and registration.
//!
//! A small fixed-window limiter: at most `login_rate_limit` attempts per
//! `rate_limit_window_secs` per client IP and action. Exceeding it returns
//! `429 Too Many Requests` with a `Retry-After` header.
//!
//! The client IP is the TCP peer address. Rocket's `ip_header` (e.g.
//! `X-Real-IP`) is disabled in `Rocket.toml` so clients can't dodge the limit
//! by spoofing it; enable it only behind a trusted reverse proxy.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rocket::http::{Header, Status};
use rocket::request::{self, FromRequest, Request};
use rocket_dyn_templates::Template;

/// Entries are pruned once the table grows past this many keys.
const PRUNE_THRESHOLD: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    Login,
    Register,
}

/// `(client IP, action)` -> `(window start, attempts in window)`.
type Buckets = HashMap<(Option<IpAddr>, Action), (Instant, u32)>;

pub struct RateLimiter {
    limit: u32,
    window: Duration,
    buckets: Mutex<Buckets>,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Record an attempt. `Err(retry_after)` if the client is over the limit.
    /// A limit of 0 disables rate limiting.
    pub fn check(&self, ip: Option<IpAddr>, action: Action) -> Result<(), Duration> {
        if self.limit == 0 {
            return Ok(());
        }
        let now = Instant::now();
        // Never panics while holding the lock, so poisoning can't happen;
        // recover anyway rather than unwrap.
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if buckets.len() > PRUNE_THRESHOLD {
            let window = self.window;
            buckets.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let (start, count) = buckets.entry((ip, action)).or_insert((now, 0));
        if now.duration_since(*start) >= self.window {
            *start = now;
            *count = 0;
        }
        if *count >= self.limit {
            return Err(self.window.saturating_sub(now.duration_since(*start)));
        }
        *count += 1;
        Ok(())
    }
}

/// Seconds to wait, stashed for the 429 catcher.
#[derive(Clone, Copy)]
struct RetryAfter(u64);

fn throttle(request: &Request<'_>, action: Action) -> request::Outcome<(), ()> {
    let Some(limiter) = request.rocket().state::<RateLimiter>() else {
        return request::Outcome::Success(());
    };
    match limiter.check(request.client_ip(), action) {
        Ok(()) => request::Outcome::Success(()),
        Err(retry) => {
            let secs = retry.as_secs() + u64::from(retry.subsec_nanos() > 0);
            request.local_cache(|| RetryAfter(secs.max(1)));
            tracing::warn!(
                client_ip = ?request.client_ip(),
                action = ?action,
                retry_after_secs = secs,
                "rate limit exceeded"
            );
            request::Outcome::Error((Status::TooManyRequests, ()))
        }
    }
}

/// Request guard: counts a login attempt against the client's limit.
pub struct LoginAttempt;

/// Request guard: counts a registration attempt against the client's limit.
pub struct RegisterAttempt;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for LoginAttempt {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, ()> {
        throttle(request, Action::Login).map(|()| LoginAttempt)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RegisterAttempt {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, ()> {
        throttle(request, Action::Register).map(|()| RegisterAttempt)
    }
}

#[derive(Responder)]
#[response(status = 429, content_type = "html")]
pub struct TooManyRequests {
    page: Template,
    retry_after: Header<'static>,
}

#[catch(429)]
pub fn too_many_requests(request: &Request<'_>) -> TooManyRequests {
    let secs = request.local_cache(|| RetryAfter(60)).0;
    let message = format!("Too many attempts. Please wait {secs} seconds and try again.");
    let mut context = HashMap::new();
    context.insert("flash", message);
    context.insert("flash_kind", "error".to_owned());
    TooManyRequests {
        page: Template::render("login", &context),
        retry_after: Header::new("Retry-After", secs.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
    const B: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)));

    #[test]
    fn limits_per_ip_and_action() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check(A, Action::Login).is_ok());
        assert!(limiter.check(A, Action::Login).is_ok());
        let retry = limiter.check(A, Action::Login).unwrap_err();
        assert!(retry <= Duration::from_secs(60) && retry > Duration::from_secs(55));
        assert!(
            limiter.check(B, Action::Login).is_ok(),
            "other IPs unaffected"
        );
        assert!(
            limiter.check(A, Action::Register).is_ok(),
            "separate per action"
        );
    }

    #[test]
    fn window_resets() {
        let limiter = RateLimiter::new(1, Duration::from_millis(50));
        assert!(limiter.check(A, Action::Login).is_ok());
        assert!(limiter.check(A, Action::Login).is_err());
        std::thread::sleep(Duration::from_millis(60));
        assert!(limiter.check(A, Action::Login).is_ok());
    }

    #[test]
    fn zero_disables() {
        let limiter = RateLimiter::new(0, Duration::from_secs(60));
        for _ in 0..100 {
            assert!(limiter.check(A, Action::Login).is_ok());
        }
    }
}
