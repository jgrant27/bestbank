//! Security response headers.
//!
//! * A strict `Content-Security-Policy` on every response: only same-origin
//!   scripts, styles, images and connections (including the `/ws`
//!   WebSocket), no inline scripts or styles, no plugins, no framing, and
//!   forms may only post back to us. The templates keep all JS and CSS in
//!   `static/` so this works.
//! * Rocket's [`Shield`] for the rest: `X-Content-Type-Options: nosniff`,
//!   `X-Frame-Options: DENY`, `Referrer-Policy: same-origin` (Referer is still
//!   sent to ourselves, which the CSRF origin check can fall back on), a
//!   restrictive `Permissions-Policy`, and HSTS automatically when TLS is on.
//! * `Cache-Control: no-store` on everything except static assets, so account
//!   pages and JSON aren't kept in shared or browser caches.

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::shield::{Feature, Frame, NoSniff, Permission, Referrer, Shield};
use rocket::{Request, Response};

pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; \
     style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; \
     frame-ancestors 'none'; base-uri 'none'";

/// Rocket's built-in security headers, tightened from the defaults.
pub fn shield() -> Shield {
    let permissions = [
        Feature::Camera,
        Feature::Microphone,
        Feature::Geolocation,
        Feature::Payment,
        Feature::Usb,
        Feature::InterestCohort,
    ]
    .into_iter()
    .fold(Permission::default(), Permission::block);
    Shield::new()
        .enable(NoSniff::Enable)
        .enable(Frame::Deny)
        .enable(Referrer::SameOrigin)
        .enable(permissions)
}

/// Adds the CSP and cache headers described in the module docs.
pub struct SecurityHeaders;

#[rocket::async_trait]
impl Fairing for SecurityHeaders {
    fn info(&self) -> Info {
        Info {
            name: "Security headers",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new(
            "Content-Security-Policy",
            CONTENT_SECURITY_POLICY,
        ));
        if !request.uri().path().starts_with("/static/") {
            response.set_header(Header::new("Cache-Control", "no-store"));
        }
    }
}
