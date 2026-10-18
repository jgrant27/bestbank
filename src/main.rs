#![warn(clippy::all, clippy::pedantic)]
// Rocket request guards (e.g. `User`, `Form<T>`) are taken by value by design.
#![allow(clippy::needless_pass_by_value)]

#[macro_use]
extern crate rocket;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_faults;
#[cfg(test)]
mod tests_ws;

mod app;
mod banking;
mod csrf;
mod db;
mod events;
mod hashing;
mod headers;
mod health;
mod login;
mod money;
mod ratelimit;
mod register;
mod sessions;
mod telemetry;

use std::process::ExitCode;

use app::build;

// Process entry point: argument handling, environment-driven logging setup
// and launching. Everything here is thin glue around tested functions and is
// excluded from coverage (see README "Coverage").
#[rocket::main]
async fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        None => {}
        // `bestbank healthcheck`: probe a running server (used by the
        // container HEALTHCHECK; the runtime image has no curl or shell).
        Some("healthcheck") => {
            return match rocket::Config::try_from(rocket::Config::figment()) {
                Ok(config) => health::probe(&config),
                Err(e) => {
                    eprintln!("unhealthy: invalid configuration: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        Some(other) => {
            eprintln!("unknown argument {other:?}\nusage: bestbank [healthcheck]");
            return ExitCode::from(2);
        }
    }
    let rust_log = std::env::var("RUST_LOG").ok();
    let json = std::env::var("BESTBANK_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"));
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let subscriber = telemetry::subscriber(rust_log.as_deref(), json, ansi);
    // Also captures Rocket's `log` records (Rocket only installs its own
    // logger when none is set).
    if tracing_subscriber::util::SubscriberInitExt::try_init(subscriber).is_err() {
        eprintln!("a global logger was already installed");
    }
    match build(rocket::Config::figment()).launch().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{}", e.pretty_print());
            ExitCode::FAILURE
        }
    }
}
