//! End-to-end tests against a real server on a local port: WebSocket
//! upgrades can't go through Rocket's in-process `local` client.

use std::collections::HashMap;
use std::time::Duration;

use rocket::futures::StreamExt;
use rocket::tokio::io::{AsyncReadExt, AsyncWriteExt};
use rocket::tokio::net::TcpStream;
use rocket::tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

/// Minimal HTTP/1.1 client with a cookie jar, just enough for these tests.
struct Browser {
    port: u16,
    cookies: HashMap<String, String>,
}

struct HttpResponse {
    status: u16,
    body: String,
}

impl Browser {
    fn new(port: u16) -> Self {
        Self {
            port,
            cookies: HashMap::new(),
        }
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    async fn request(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &str,
    ) -> HttpResponse {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\
             Cookie: {cookies}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\n\r\n{body}",
            port = self.port,
            cookies = self.cookie_header(),
            len = body.len(),
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
        let mut lines = head.lines();
        let status = lines
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if !name.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            let pair = value.trim().split(';').next().unwrap_or_default();
            if let Some((k, v)) = pair.split_once('=') {
                if v.is_empty() {
                    self.cookies.remove(k);
                } else {
                    self.cookies.insert(k.to_owned(), v.to_owned());
                }
            }
        }
        HttpResponse {
            status,
            body: body.to_owned(),
        }
    }

    async fn form(&mut self, path: &str, body: &str) -> HttpResponse {
        self.request("POST", path, "application/x-www-form-urlencoded", body)
            .await
    }

    async fn json(&mut self, path: &str, body: &str) -> HttpResponse {
        self.request("POST", path, "application/json", body).await
    }

    /// Open `/ws` with this browser's cookies; `None` if the upgrade fails.
    async fn websocket(&self) -> Option<Ws> {
        let mut request = format!("ws://127.0.0.1:{}/ws", self.port)
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "Cookie",
            HeaderValue::from_str(&self.cookie_header()).unwrap(),
        );
        let stream = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
        tokio_tungstenite::client_async(request, stream)
            .await
            .ok()
            .map(|(ws, _)| ws)
    }
}

/// Launch the app on a free local port with an in-memory database.
async fn launch() -> (u16, rocket::Shutdown) {
    launch_with(&[]).await
}

/// Like [`launch`], with extra config overrides.
async fn launch_with(overrides: &[(&str, i64)]) -> (u16, rocket::Shutdown) {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let figment = rocket::Config::figment()
        .merge(("database_url", "sqlite::memory:"))
        .merge(("address", "127.0.0.1"))
        .merge(("port", port))
        .merge(("log_level", "off"));
    let figment = overrides
        .iter()
        .fold(figment, |f, (key, value)| f.merge((*key, *value)));
    let rocket = super::build(figment).ignite().await.expect("ignite");
    let shutdown = rocket.shutdown();
    rocket::tokio::spawn(rocket.launch());
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return (port, shutdown);
        }
        rocket::tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not start");
}

async fn register_and_login(port: u16, user: &str, password: &str) -> Browser {
    let mut browser = Browser::new(port);
    let body = format!("username={user}&password={password}&confirm={password}");
    assert_eq!(browser.form("/register", &body).await.status, 303);
    let response = browser
        .form("/login", &format!("username={user}&password={password}"))
        .await;
    assert_eq!(response.status, 303);
    let info = browser.request("GET", "/json/account_info", "", "").await;
    assert_eq!(info.status, 200, "{user} logged in");
    browser
}

type Ws = tokio_tungstenite::WebSocketStream<TcpStream>;

async fn next_text(ws: &mut Ws, wait: Duration) -> Option<String> {
    match timeout(wait, ws.next()).await {
        Ok(Some(Ok(message))) if message.is_text() => Some(message.into_text().unwrap()),
        _ => None,
    }
}

#[rocket::async_test]
async fn websocket_events_are_isolated_per_user() {
    let (port, shutdown) = launch().await;
    let mut alice = register_and_login(port, "alice", "sunny-river-42").await;
    let mut bob = register_and_login(port, "bob", "quiet-forest-17").await;

    // No session: the upgrade is refused.
    assert!(Browser::new(port).websocket().await.is_none());

    let mut alice_ws = alice.websocket().await.expect("alice ws");
    let mut bob_ws = bob.websocket().await.expect("bob ws");

    let response = alice.json("/json/deposit", r#"{"amount": 5}"#).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        next_text(&mut alice_ws, Duration::from_secs(3))
            .await
            .as_deref(),
        Some("Successful deposit for 💵5.00")
    );
    assert_eq!(
        next_text(&mut bob_ws, Duration::from_millis(300)).await,
        None,
        "bob must not see alice's deposit"
    );

    let response = bob.json("/json/deposit", r#"{"amount": 7.5}"#).await;
    assert_eq!(response.status, 200, "{}", response.body);
    let response = bob.json("/json/withdraw", r#"{"amount": 2.5}"#).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        next_text(&mut bob_ws, Duration::from_secs(3))
            .await
            .as_deref(),
        Some("Successful deposit for 💵7.50")
    );
    assert_eq!(
        next_text(&mut bob_ws, Duration::from_secs(3))
            .await
            .as_deref(),
        Some("Successful withdrawal for 💵2.50")
    );
    assert_eq!(
        next_text(&mut alice_ws, Duration::from_millis(300)).await,
        None,
        "alice must not see bob's transactions"
    );

    shutdown.notify();
}

#[rocket::async_test]
async fn open_websocket_is_closed_when_sessions_are_revoked() {
    let (port, shutdown) = launch_with(&[("session_check_secs", 1)]).await;
    let mut laptop = register_and_login(port, "carol", "sunny-river-42").await;
    let mut phone = Browser::new(port);
    let response = phone
        .form("/login", "username=carol&password=sunny-river-42")
        .await;
    assert_eq!(response.status, 303);
    let mut phone_ws = phone.websocket().await.expect("phone ws");

    // Revoke everything from the laptop; the phone's open socket closes.
    assert_eq!(laptop.form("/logout_all", "").await.status, 303);
    let closed = timeout(Duration::from_secs(5), async {
        loop {
            match phone_ws.next().await {
                None | Some(Err(_)) => return true,
                Some(Ok(message)) if message.is_close() => return true,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(closed, "websocket should close after revocation");
    assert!(phone.websocket().await.is_none(), "and can't reconnect");

    shutdown.notify();
}
