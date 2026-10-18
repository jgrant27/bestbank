//! CSRF protection: per-browser tokens plus an Origin/Referer check.
//!
//! * A random token lives in an encrypted, `HttpOnly`, `SameSite=Strict`
//!   private cookie (`csrf`). Pages embed it: forms as a hidden
//!   `csrf_token` field, and the banking page as a `<meta name="csrf-token">`
//!   that the JS sends back in an `X-CSRF-Token` header. Every state-changing
//!   request must present the same token. An attacker's page can neither read
//!   the cookie nor the page, so it can't forge requests (including login
//!   CSRF, since the login form needs the token too).
//! * POSTs and the websocket upgrade are rejected if `Origin` (or, failing
//!   that, `Referer`) names a different origin than this app. Requests with
//!   neither header (non-browser clients) still need a valid token.
//! * The token is rotated on login and logout.

use rocket::http::{Cookie, CookieJar, SameSite, Status};
use rocket::request::{self, FromRequest, Request};

use crate::db::AppConfig;

pub const CSRF_COOKIE: &str = "csrf";
pub const CSRF_HEADER: &str = "X-CSRF-Token";

fn new_cookie(token: String) -> Cookie<'static> {
    Cookie::build((CSRF_COOKIE, token))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .build()
}

fn current(jar: &CookieJar<'_>) -> Option<String> {
    jar.get_private(CSRF_COOKIE)
        .map(|c| c.value().to_owned())
        .filter(|v| !v.is_empty())
}

/// Issue a fresh token (on login/logout), returning it.
pub fn rotate(jar: &CookieJar<'_>) -> String {
    let token = crate::telemetry::random_hex(32);
    jar.add_private(new_cookie(token.clone()));
    token
}

/// Constant-time string comparison.
fn tokens_match(expected: &str, submitted: &str) -> bool {
    expected.len() == submitted.len()
        && expected
            .bytes()
            .zip(submitted.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// The authority (`host[:port]`) of an `Origin`/`Referer` URL.
fn authority(url: &str) -> Option<&str> {
    let has_prefix = |p: &str| {
        url.get(..p.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(p))
    };
    let rest = if has_prefix("https://") {
        &url[8..]
    } else if has_prefix("http://") {
        &url[7..]
    } else {
        return None;
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&rest[..end]).filter(|a| !a.is_empty())
}

/// `scheme://authority`, lowercased, of an `Origin`/`Referer` URL.
fn origin_of(url: &str) -> Option<String> {
    let https = url
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"));
    let scheme = if https { "https" } else { "http" };
    authority(url).map(|a| format!("{scheme}://{a}").to_ascii_lowercase())
}

/// Is this request from our own origin (as far as the browser tells us)?
///
/// If `allowed_origins` is configured (e.g. behind a proxy that rewrites
/// `Host`), the origin must be one of them; otherwise its host must match
/// the request's `Host` header.
fn same_origin(request: &Request<'_>) -> bool {
    let headers = request.headers();
    let Some(claimed) = headers
        .get_one("Origin")
        .or_else(|| headers.get_one("Referer"))
    else {
        // No browser origin information: allow (tokens still apply).
        return true;
    };
    let allowed = request
        .rocket()
        .state::<AppConfig>()
        .map(|c| c.allowed_origins.as_slice())
        .unwrap_or_default();
    if !allowed.is_empty() {
        return origin_of(claimed).is_some_and(|origin| {
            allowed
                .iter()
                .any(|a| origin == a.trim_end_matches('/').to_ascii_lowercase())
        });
    }
    let host = request
        .host()
        .map(ToString::to_string)
        .or_else(|| headers.get_one("Host").map(str::to_owned));
    match (authority(claimed), host) {
        (Some(authority), Some(host)) => authority.eq_ignore_ascii_case(&host),
        _ => false,
    }
}

fn reject_cross_origin(request: &Request<'_>) -> bool {
    if same_origin(request) {
        return false;
    }
    tracing::warn!(
        method = %request.method(),
        path = %request.uri().path(),
        origin = ?request.headers().get_one("Origin"),
        referer = ?request.headers().get_one("Referer"),
        "cross-origin request rejected"
    );
    true
}

/// Request guard for pages that render forms: the current token, creating
/// one (and its cookie) if needed.
pub struct CsrfToken(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CsrfToken {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let jar = request.cookies();
        let token = current(jar).unwrap_or_else(|| rotate(jar));
        request::Outcome::Success(CsrfToken(token))
    }
}

/// Request guard for form POSTs. Rejects cross-origin requests with 403;
/// the handler then checks the submitted `csrf_token` field with
/// [`CsrfForm::verify`].
pub struct CsrfForm {
    expected: Option<String>,
}

impl CsrfForm {
    pub fn verify(&self, submitted: &str) -> bool {
        self.expected
            .as_deref()
            .is_some_and(|expected| tokens_match(expected, submitted))
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CsrfForm {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, ()> {
        if reject_cross_origin(request) {
            return request::Outcome::Error((Status::Forbidden, ()));
        }
        request::Outcome::Success(CsrfForm {
            expected: current(request.cookies()),
        })
    }
}

/// Why an API request failed the CSRF check.
#[derive(Debug)]
pub enum CsrfError {
    CrossOrigin,
    BadToken,
}

/// Request guard for JSON API POSTs: same origin and a matching
/// `X-CSRF-Token` header. Take it as `Result<CsrfHeader, CsrfError>` to
/// return a JSON error.
pub struct CsrfHeader;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CsrfHeader {
    type Error = CsrfError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, CsrfError> {
        if reject_cross_origin(request) {
            return request::Outcome::Error((Status::Forbidden, CsrfError::CrossOrigin));
        }
        let ok = match (
            current(request.cookies()),
            request.headers().get_one(CSRF_HEADER),
        ) {
            (Some(expected), Some(submitted)) => tokens_match(&expected, submitted),
            _ => false,
        };
        if ok {
            request::Outcome::Success(CsrfHeader)
        } else {
            tracing::warn!(path = %request.uri().path(), "missing or invalid CSRF token");
            request::Outcome::Error((Status::Forbidden, CsrfError::BadToken))
        }
    }
}

/// Request guard: rejects cross-origin requests (used for the websocket
/// upgrade, which browsers don't restrict by origin).
pub struct SameOrigin;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SameOrigin {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, ()> {
        if reject_cross_origin(request) {
            request::Outcome::Error((Status::Forbidden, ()))
        } else {
            request::Outcome::Success(SameOrigin)
        }
    }
}

/// `GET /json/csrf`: the current token, for API clients. Same-origin policy
/// stops other sites reading it.
#[get("/json/csrf")]
pub fn token(token: CsrfToken) -> rocket::serde::json::Value {
    rocket::serde::json::json!({ "csrf_token": token.0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_tokens() {
        assert!(tokens_match("abc", "abc"));
        assert!(!tokens_match("abc", "abd"));
        assert!(!tokens_match("abc", "ab"));
        assert!(!tokens_match("abc", ""));
    }

    #[test]
    fn parses_authority() {
        assert_eq!(
            authority("https://bank.example:8443"),
            Some("bank.example:8443")
        );
        assert_eq!(
            authority("http://localhost:8080/login?x=1"),
            Some("localhost:8080")
        );
        assert_eq!(authority("null"), None);
        assert_eq!(authority("ftp://x"), None);
        assert_eq!(authority("http://"), None);
        assert_eq!(
            origin_of("HTTPS://Bank.Example/x").as_deref(),
            Some("https://bank.example")
        );
    }
}
