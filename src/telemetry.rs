//! Structured logging with `tracing`, plus per-request IDs.
//!
//! * `RUST_LOG` controls filtering (default: `info`, with Rocket's own
//!   per-request chatter turned down since we log requests ourselves).
//!   For example `RUST_LOG=debug` or `RUST_LOG=info,bestbank=debug`.
//! * `BESTBANK_LOG_FORMAT=json` switches to one JSON object per line.
//! * Every response carries an `X-Request-Id` header. A well-formed incoming
//!   `X-Request-Id` (e.g. from a proxy) is reused, otherwise one is generated.

use std::time::Instant;

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::request::{self, FromRequest, Request};
use rocket::{Data, Response};
use tracing_subscriber::EnvFilter;

pub const REQUEST_ID_HEADER: &str = "X-Request-Id";

/// Default filter: our own events at `info`, Rocket's launch banner, and
/// warnings/errors from Rocket. Rocket's routine per-request notes (guard
/// forwarding, default catchers) are hidden because `bestbank::http` already
/// logs one structured line per request.
const DEFAULT_FILTER: &str = "info,rocket=warn,rocket::launch=info,rocket::launch::_=warn,\
     rocket::server::_=error,rocket_dyn_templates=warn,bestbank::login::_=error,\
     bestbank::banking::_=error,bestbank::events::_=error,bestbank::_=error";

/// Install the global `tracing` subscriber (which also captures Rocket's
/// `log` records). Safe to call more than once.
pub fn init() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));
    let json = std::env::var("BESTBANK_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true);
    let result = if json {
        builder.json().flatten_event(true).try_init()
    } else {
        builder.compact().try_init()
    };
    if result.is_err() {
        tracing::debug!("tracing subscriber already installed");
    }
}

/// Generate `bytes` random bytes as lowercase hex.
///
/// # Panics
/// Only if the OS random number generator is unavailable.
pub fn random_hex(bytes: usize) -> String {
    use std::fmt::Write;
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("OS RNG unavailable");
    buf.iter()
        .fold(String::with_capacity(bytes * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The ID assigned to the current request. Usable as a request guard so
/// handlers can include it in their own log events.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

struct RequestStart(Instant);

fn is_valid_incoming(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn request_id<'r>(request: &'r Request<'_>) -> &'r RequestId {
    request.local_cache(|| {
        let incoming = request
            .headers()
            .get_one(REQUEST_ID_HEADER)
            .filter(|id| is_valid_incoming(id));
        RequestId(incoming.map_or_else(|| random_hex(8), str::to_owned))
    })
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequestId {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        request::Outcome::Success(request_id(request).clone())
    }
}

/// Fairing that assigns request IDs and logs one structured line per request.
pub struct RequestLogger;

#[rocket::async_trait]
impl Fairing for RequestLogger {
    fn info(&self) -> Info {
        Info {
            name: "Request ID + structured request logging",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        request.local_cache(|| RequestStart(Instant::now()));
        request_id(request);
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        let id = &request_id(request).0;
        let elapsed = request
            .local_cache(|| RequestStart(Instant::now()))
            .0
            .elapsed();
        response.set_header(Header::new(REQUEST_ID_HEADER, id.clone()));
        let status = response.status().code;
        let latency_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let method = request.method().as_str();
        let path = request.uri().path().as_str();
        let client_ip = request.client_ip().map(|ip| ip.to_string());
        if status >= 500 {
            tracing::error!(target: "bestbank::http", request_id = %id, method, path, status, latency_us, client_ip, "request failed");
        } else {
            tracing::info!(target: "bestbank::http", request_id = %id, method, path, status, latency_us, client_ip, "request");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_hex_is_hex_and_unique() {
        let a = random_hex(8);
        assert_eq!(a.len(), 16);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, random_hex(8));
    }

    #[test]
    fn incoming_ids_are_validated() {
        assert!(is_valid_incoming("abcdef12-3456"));
        assert!(!is_valid_incoming("short"));
        assert!(!is_valid_incoming("has spaces in it"));
        assert!(!is_valid_incoming(&"x".repeat(65)));
        assert!(!is_valid_incoming("inject\r\nheader"));
    }
}
