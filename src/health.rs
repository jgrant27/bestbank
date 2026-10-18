//! Liveness/readiness: `GET /healthz`, and a `bestbank healthcheck`
//! subcommand that probes it (for container health checks in images that
//! have no curl or shell).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

use rocket::State;
use rocket::http::Status;

use crate::db::Db;

/// `200 ok` when the app is up and the database answers, `503` otherwise.
#[get("/healthz")]
pub async fn healthz(db: &State<Db>) -> (Status, &'static str) {
    match sqlx::query("SELECT 1").execute(db.inner()).await {
        Ok(_) => (Status::Ok, "ok"),
        Err(e) => {
            tracing::error!(error = %e, "health check: database unavailable");
            (Status::ServiceUnavailable, "database unavailable")
        }
    }
}

const TIMEOUT: Duration = Duration::from_secs(3);

/// Probe the local server using the same configuration (`Rocket.toml` plus
/// `ROCKET_*` variables) the server reads. Over plain HTTP it requires
/// `GET /healthz` to return 200; with TLS enabled it only checks that the
/// port accepts connections (the probe has no TLS client).
pub fn probe() -> ExitCode {
    let config = match rocket::Config::try_from(rocket::Config::figment()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("unhealthy: invalid configuration: {e}");
            return ExitCode::FAILURE;
        }
    };
    match probe_port(config.port, config.tls_enabled()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("unhealthy: {message}");
            ExitCode::FAILURE
        }
    }
}

fn probe_port(port: u16, tls: bool) -> Result<(), String> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream =
        TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| format!("{addr}: {e}"))?;
    if tls {
        return Ok(());
    }
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).map_err(|e| e.to_string())?;
    if head.starts_with(b"HTTP/1.1 200") || head.starts_with(b"HTTP/1.0 200") {
        Ok(())
    } else {
        Err(format!(
            "unexpected response {:?}",
            String::from_utf8_lossy(&head)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rocket::async_test]
    async fn probe_succeeds_against_a_running_server_and_fails_without_one() {
        let (port, shutdown) = crate::tests_ws::launch().await;
        let result = rocket::tokio::task::spawn_blocking(move || probe_port(port, false))
            .await
            .unwrap();
        assert_eq!(result, Ok(()));
        let tcp_only = rocket::tokio::task::spawn_blocking(move || probe_port(port, true))
            .await
            .unwrap();
        assert_eq!(tcp_only, Ok(()));
        shutdown.notify();

        // Nothing listening on a fresh ephemeral port.
        let free = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let result = rocket::tokio::task::spawn_blocking(move || probe_port(free, false))
            .await
            .unwrap();
        assert!(result.is_err());
    }

    #[rocket::async_test]
    async fn probe_rejects_non_200_responses() {
        use rocket::tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = rocket::tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = rocket::tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let _ = socket.read(&mut buf).await;
            socket
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let result = rocket::tokio::task::spawn_blocking(move || probe_port(port, false))
            .await
            .unwrap();
        assert!(result.unwrap_err().contains("503"));
        server.await.unwrap();
    }
}
