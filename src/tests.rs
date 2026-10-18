use rocket::figment::Figment;
use rocket::http::{ContentType, Cookie, SameSite, Status};
use rocket::local::blocking::{Client, LocalResponse};
use rocket::serde::json::Value;
use tempfile::TempDir;

use crate::csrf::{CSRF_COOKIE, CSRF_HEADER};
use crate::db;
use crate::hashing::hash_password;
use crate::login::SESSION_COOKIE;

/// App config pointing at `database_url`.
fn figment(database_url: &str) -> Figment {
    rocket::Config::figment().merge(("database_url", database_url))
}

/// App with a fresh in-memory database (demo admin seeded).
fn client() -> Client {
    Client::tracked(super::build(figment("sqlite::memory:"))).expect("valid rocket instance")
}

/// A file-backed database in a temp dir, pre-populated with `users`.
/// Keep the `TempDir` alive for as long as the database is used.
fn file_db(users: &[(&str, &str)]) -> (String, TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let url = format!("sqlite://{}", dir.path().join("test.db").display());
    let runtime = rocket::tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let pool = db::connect(&url).await.expect("connect");
        for (user, password) in users {
            db::create_user(&pool, user, &hash_password(password))
                .await
                .expect("create user");
        }
        pool.close().await;
    });
    (url, dir)
}

/// App backed by a file database containing `users` (plus the demo admin).
fn client_with_users(users: &[(&str, &str)]) -> (Client, TempDir) {
    let (url, dir) = file_db(users);
    let client = Client::tracked(super::build(figment(&url))).expect("valid rocket instance");
    (client, dir)
}

/// The client's current CSRF token (fetching one if it has none yet).
fn csrf(client: &Client) -> String {
    if let Some(cookie) = client.cookies().get_private(CSRF_COOKIE) {
        return cookie.value().to_owned();
    }
    let json: Value = client.get("/json/csrf").dispatch().into_json().unwrap();
    json["csrf_token"].as_str().unwrap().to_owned()
}

/// POST a form, adding the client's CSRF token.
fn post_form<'c>(client: &'c Client, path: &str, body: &str) -> LocalResponse<'c> {
    let token = csrf(client);
    let sep = if body.is_empty() { "" } else { "&" };
    client
        .post(path.to_owned())
        .header(ContentType::Form)
        .body(format!("{body}{sep}csrf_token={token}"))
        .dispatch()
}

fn login<'c>(client: &'c Client, user: &str, password: &str) -> LocalResponse<'c> {
    post_form(
        client,
        "/login",
        &format!("username={user}&password={password}"),
    )
}

fn location(response: &LocalResponse<'_>) -> Option<String> {
    response.headers().get_one("Location").map(str::to_owned)
}

fn post_json(client: &Client, path: &str, body: &str) -> (Status, Value) {
    let token = csrf(client);
    let response = client
        .post(path.to_owned())
        .header(ContentType::JSON)
        .header(rocket::http::Header::new(CSRF_HEADER, token))
        .body(body)
        .dispatch();
    let status = response.status();
    (status, response.into_json().expect("JSON response"))
}

fn balance(client: &Client) -> String {
    let info: Value = client
        .get("/json/account_info")
        .dispatch()
        .into_json()
        .expect("JSON account info");
    info["balance"].as_str().expect("balance string").to_owned()
}

#[test]
fn login_page_renders() {
    let client = client();
    let response = client.get("/login").dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::HTML));
    let body = response.into_string().unwrap();
    assert!(body.contains("Please Login"));
    assert!(body.contains(r#"name="username""#));
    assert!(body.contains(r#"name="password""#));
    assert!(
        !body.contains("class=\"flash"),
        "no flash without a message"
    );
}

#[test]
fn root_and_banking_redirect_to_login_when_logged_out() {
    let client = client();
    for path in ["/", "/user_banking"] {
        let response = client.get(path).dispatch();
        assert_eq!(response.status(), Status::SeeOther, "{path}");
        assert_eq!(location(&response).as_deref(), Some("/login"), "{path}");
    }
}

#[test]
fn bad_login_is_rejected_with_flash() {
    let client = client();
    for (user, pass) in [("admin", "wrong"), ("nobody", "admin"), ("", "")] {
        let response = login(&client, user, pass);
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(location(&response).as_deref(), Some("/login"));
        assert!(response.cookies().get_private(SESSION_COOKIE).is_none());
        let page = client.get("/login").dispatch().into_string().unwrap();
        assert!(page.contains("Invalid username/password."), "{user}/{pass}");
    }
    assert_eq!(
        client.get("/json/account_info").dispatch().status(),
        Status::Unauthorized
    );
}

#[test]
fn good_login_works_and_logout_ends_session() {
    let client = client();
    let response = login(&client, "admin", "admin");
    assert_eq!(response.status(), Status::SeeOther);
    assert_eq!(location(&response).as_deref(), Some("/user_banking"));

    let cookie = response
        .cookies()
        .get(SESSION_COOKIE)
        .expect("session cookie");
    assert_ne!(cookie.value(), "admin", "session cookie must be encrypted");
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Strict));

    let page = client.get("/user_banking").dispatch();
    assert_eq!(page.status(), Status::Ok);
    assert!(page.into_string().unwrap().contains("Best Bank"));

    let info: Value = client
        .get("/json/account_info")
        .dispatch()
        .into_json()
        .unwrap();
    assert_eq!(info["user_name"], "admin");
    assert_eq!(info["balance"], "0.00");

    // /dump works for admin.
    assert_eq!(client.get("/dump").dispatch().status(), Status::Ok);

    let response = post_form(&client, "/logout", "");
    assert_eq!(response.status(), Status::SeeOther);
    let page = client.get("/login").dispatch().into_string().unwrap();
    assert!(page.contains("Successfully logged out."));
    assert_eq!(
        client.get("/json/account_info").dispatch().status(),
        Status::Unauthorized
    );
    assert_eq!(
        client.get("/dump").dispatch().status(),
        Status::Unauthorized
    );
}

#[test]
fn forged_plain_cookie_is_rejected() {
    let client = Client::untracked(super::build(figment("sqlite::memory:"))).unwrap();
    let forged = || Cookie::new(SESSION_COOKIE, "admin");

    let response = client.get("/dump").cookie(forged()).dispatch();
    assert_eq!(response.status(), Status::Unauthorized);

    let response = client.get("/user_banking").cookie(forged()).dispatch();
    assert_eq!(response.status(), Status::SeeOther);
    assert_eq!(location(&response).as_deref(), Some("/login"));

    let response = client.get("/json/account_info").cookie(forged()).dispatch();
    assert_eq!(response.status(), Status::Unauthorized);

    let response = client
        .post("/json/deposit")
        .cookie(forged())
        .header(ContentType::JSON)
        .body(r#"{"amount": 100}"#)
        .dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
}

#[test]
fn dump_is_admin_only() {
    let (client, _dir) = client_with_users(&[("alice", "pw")]);
    login(&client, "alice", "pw");
    assert_eq!(client.get("/dump").dispatch().status(), Status::Forbidden);
}

#[test]
fn deposit_validation() {
    let client = client();
    login(&client, "admin", "admin");
    for body in [
        r#"{"amount": 0}"#,
        r#"{"amount": -5}"#,
        r#"{"amount": -0.01}"#,
        r#"{"amount": 1.234}"#,
        r#"{"amount": 0.001}"#,
        r#"{"amount": 1000000.01}"#,
    ] {
        let (status, json) = post_json(&client, "/json/deposit", body);
        assert_eq!(status, Status::UnprocessableEntity, "{body}");
        assert_eq!(json["success"], false, "{body}");
        assert!(json["message"].is_string(), "{body}");
    }
    for body in [
        r#"{"amount": "abc"}"#,
        r#"{"amount": null}"#,
        "{}",
        "not json",
        "",
    ] {
        let (status, json) = post_json(&client, "/json/deposit", body);
        assert_eq!(status, Status::BadRequest, "{body:?}");
        assert_eq!(json["success"], false, "{body:?}");
    }
    assert_eq!(balance(&client), "0.00");

    // Integer cents: 0.1 + 0.2 is exactly 0.30, not 0.30000000000000004.
    assert_eq!(
        post_json(&client, "/json/deposit", r#"{"amount": 0.1}"#).0,
        Status::Ok
    );
    assert_eq!(
        post_json(&client, "/json/deposit", r#"{"amount": 0.2}"#).0,
        Status::Ok
    );
    assert_eq!(balance(&client), "0.30");
}

#[test]
fn withdraw_validation_and_overdraft() {
    let client = client();
    login(&client, "admin", "admin");

    let (status, json) = post_json(&client, "/json/withdraw", r#"{"amount": 1}"#);
    assert_eq!(status, Status::UnprocessableEntity);
    assert_eq!(json["message"], "Insufficient funds available.");

    for body in [r#"{"amount": 0}"#, r#"{"amount": -5}"#] {
        let (status, json) = post_json(&client, "/json/withdraw", body);
        assert_eq!(status, Status::UnprocessableEntity, "{body}");
        assert_eq!(json["success"], false);
    }

    let (status, json) = post_json(&client, "/json/deposit", r#"{"amount": 10.10}"#);
    assert_eq!(
        (status, json["success"].as_bool()),
        (Status::Ok, Some(true))
    );
    let (status, _) = post_json(&client, "/json/withdraw", r#"{"amount": 10.11}"#);
    assert_eq!(status, Status::UnprocessableEntity, "overdraft by one cent");
    let (status, json) = post_json(&client, "/json/withdraw", r#"{"amount": 10.10}"#);
    assert_eq!(
        (status, json["success"].as_bool()),
        (Status::Ok, Some(true))
    );
    assert_eq!(balance(&client), "0.00");

    let info: Value = client
        .get("/json/account_info")
        .dispatch()
        .into_json()
        .unwrap();
    let txs = info["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 2);
    assert_eq!(txs[0][1], "-10.10", "newest first");
    assert_eq!(txs[1][1], "10.10");
}

#[test]
fn user_without_history_does_not_panic() {
    // "bob" has no transactions yet; this used to panic on `.unwrap()` and
    // poison the in-memory storage mutex.
    let (client, _dir) = client_with_users(&[("bob", "pw")]);
    login(&client, "bob", "pw");
    assert_eq!(client.get("/user_banking").dispatch().status(), Status::Ok);
    assert_eq!(balance(&client), "0.00");
    let (status, _) = post_json(&client, "/json/withdraw", r#"{"amount": 1}"#);
    assert_eq!(status, Status::UnprocessableEntity);
    assert_eq!(
        post_json(&client, "/json/deposit", r#"{"amount": 5}"#).0,
        Status::Ok
    );
    assert_eq!(balance(&client), "5.00");
}

#[test]
fn valid_session_for_unknown_user_is_rejected_and_app_keeps_working() {
    let client = client();
    // A correctly encrypted cookie for a user that isn't in storage.
    let response = client
        .get("/json/account_info")
        .private_cookie(Cookie::new(SESSION_COOKIE, "ghost"))
        .dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    let response = client
        .get("/user_banking")
        .private_cookie(Cookie::new(SESSION_COOKIE, "ghost"))
        .dispatch();
    assert_eq!(response.status(), Status::SeeOther);

    // The app (and its storage mutex) is still healthy afterwards.
    login(&client, "admin", "admin");
    assert_eq!(balance(&client), "0.00");
}

#[test]
fn websocket_requires_login() {
    let client = Client::untracked(super::build(figment("sqlite::memory:"))).unwrap();
    let response = client
        .get("/ws")
        .header(rocket::http::Header::new("Connection", "Upgrade"))
        .header(rocket::http::Header::new("Upgrade", "websocket"))
        .header(rocket::http::Header::new("Sec-WebSocket-Version", "13"))
        .header(rocket::http::Header::new(
            "Sec-WebSocket-Key",
            "dGhlIHNhbXBsZSBub25jZQ==",
        ))
        .dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
}

#[test]
fn favicon_is_served() {
    let client = client();
    let response = client.get("/static/favicon.ico").dispatch();
    assert_eq!(response.status(), Status::Ok);
}

#[test]
fn responses_carry_unique_request_ids() {
    let client = client();
    let id = |path: &str| {
        client
            .get(path.to_owned())
            .dispatch()
            .headers()
            .get_one(crate::telemetry::REQUEST_ID_HEADER)
            .map(str::to_owned)
            .expect("X-Request-Id header")
    };
    let a = id("/login");
    let b = id("/login");
    assert_eq!(a.len(), 16);
    assert_ne!(a, b);
    // Also set on error and redirect responses.
    id("/json/account_info");
    id("/");
}

#[test]
fn valid_incoming_request_id_is_reused_and_bogus_one_replaced() {
    let client = client();
    let send = |value: &str| {
        client
            .get("/login")
            .header(rocket::http::Header::new(
                crate::telemetry::REQUEST_ID_HEADER,
                value.to_owned(),
            ))
            .dispatch()
            .headers()
            .get_one(crate::telemetry::REQUEST_ID_HEADER)
            .map(str::to_owned)
            .unwrap()
    };
    assert_eq!(send("proxy-req-12345678"), "proxy-req-12345678");
    let replaced = send("bad id!");
    assert_ne!(replaced, "bad id!");
    assert_eq!(replaced.len(), 16);
}

#[test]
fn dump_lists_users_without_password_hashes() {
    let (client, _dir) = client_with_users(&[("alice", "pw")]);
    login(&client, "admin", "admin");
    let response = client.get("/dump").dispatch();
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().unwrap();
    assert!(body.contains("\"admin\"") && body.contains("\"alice\""));
    assert!(!body.contains("argon2"), "hashes must not be dumped");
}

#[test]
fn data_persists_across_restarts() {
    let (url, _dir) = file_db(&[]);
    {
        let client = Client::tracked(super::build(figment(&url))).unwrap();
        login(&client, "admin", "admin");
        assert_eq!(
            post_json(&client, "/json/deposit", r#"{"amount": 42.42}"#).0,
            Status::Ok
        );
    }
    // A brand new app instance (new secret key, so log in again).
    let client = Client::tracked(super::build(figment(&url))).unwrap();
    login(&client, "admin", "admin");
    assert_eq!(balance(&client), "42.42");
    let info: Value = client
        .get("/json/account_info")
        .dispatch()
        .into_json()
        .unwrap();
    assert_eq!(info["transactions"].as_array().unwrap().len(), 1);
}

#[test]
fn migrations_are_applied_once() {
    let (url, _dir) = file_db(&[]);
    // Opening the database again must not re-run or fail on migrations.
    let runtime = rocket::tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let pool = db::connect(&url).await.expect("reconnect");
        let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        let embedded = sqlx::migrate!("./migrations").iter().count();
        assert_eq!(usize::try_from(applied).unwrap(), embedded);
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('users', 'transactions') ORDER BY name",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(tables, ["transactions", "users"]);
    });
}

#[test]
fn usernames_are_case_insensitive_unique() {
    let (url, _dir) = file_db(&[("Carol", "pw")]);
    let runtime = rocket::tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let pool = db::connect(&url).await.unwrap();
        assert!(db::create_user(&pool, "carol", "x").await.is_err());
        assert!(db::find_user(&pool, "CAROL").await.unwrap().is_some());
    });
}

#[rocket::async_test]
async fn concurrent_withdrawals_cannot_overdraw() {
    use rocket::local::asynchronous::Client as AsyncClient;

    let (url, _dir) = rocket::tokio::task::spawn_blocking(|| file_db(&[]))
        .await
        .unwrap();
    let client = AsyncClient::tracked(super::build(figment(&url)))
        .await
        .unwrap();
    let token = |client: &AsyncClient| {
        client
            .cookies()
            .get_private(CSRF_COOKIE)
            .map(|c| c.value().to_owned())
            .unwrap_or_default()
    };
    client.get("/json/csrf").dispatch().await;
    client
        .post("/login")
        .header(ContentType::Form)
        .body(format!(
            "username=admin&password=admin&csrf_token={}",
            token(&client)
        ))
        .dispatch()
        .await;
    let csrf_header = || rocket::http::Header::new(CSRF_HEADER, token(&client));
    let response = client
        .post("/json/deposit")
        .header(ContentType::JSON)
        .header(csrf_header())
        .body(r#"{"amount": 10}"#)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // 25 concurrent $1 withdrawals against a $10 balance.
    let attempts = (0..25).map(|_| async {
        client
            .post("/json/withdraw")
            .header(ContentType::JSON)
            .header(csrf_header())
            .body(r#"{"amount": 1}"#)
            .dispatch()
            .await
            .status()
    });
    let statuses = rocket::futures::future::join_all(attempts).await;
    let ok = statuses.iter().filter(|s| **s == Status::Ok).count();
    assert_eq!(
        ok, 10,
        "exactly the funded withdrawals succeed: {statuses:?}"
    );
    assert!(
        statuses
            .iter()
            .all(|s| *s == Status::Ok || *s == Status::UnprocessableEntity)
    );

    let info: Value = client
        .get("/json/account_info")
        .dispatch()
        .await
        .into_json()
        .await
        .unwrap();
    assert_eq!(info["balance"], "0.00");
}

fn register<'c>(
    client: &'c Client,
    user: &str,
    password: &str,
    confirm: &str,
) -> LocalResponse<'c> {
    post_form(
        client,
        "/register",
        &format!("username={user}&password={password}&confirm={confirm}"),
    )
}

#[test]
fn register_page_renders_and_is_linked_from_login() {
    let client = client();
    let response = client.get("/register").dispatch();
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().unwrap();
    assert!(body.contains("Create an account"));
    assert!(body.contains(r#"name="confirm""#));
    let login_page = client.get("/login").dispatch().into_string().unwrap();
    assert!(login_page.contains(r#"href="/register""#));
}

#[test]
fn registration_creates_a_user_who_can_log_in() {
    let client = client();
    let response = register(&client, "dana", "sunny-river-42", "sunny-river-42");
    assert_eq!(response.status(), Status::SeeOther);
    assert_eq!(location(&response).as_deref(), Some("/login"));
    let page = client.get("/login").dispatch().into_string().unwrap();
    assert!(page.contains("Account created. Please log in."));

    assert_eq!(
        location(&login(&client, "dana", "sunny-river-42")).as_deref(),
        Some("/user_banking")
    );
    let info: Value = client
        .get("/json/account_info")
        .dispatch()
        .into_json()
        .unwrap();
    assert_eq!(info["user_name"], "dana");
    assert_eq!(info["balance"], "0.00");
    // Logged-in users are sent to their account instead of the form.
    assert_eq!(
        location(&client.get("/register").dispatch()).as_deref(),
        Some("/user_banking")
    );
    // New users aren't admins.
    assert_eq!(client.get("/dump").dispatch().status(), Status::Forbidden);
}

#[test]
fn registration_validation_errors() {
    let client = client();
    for (user, password, confirm, message) in [
        (
            "ab",
            "long-enough-pw",
            "long-enough-pw",
            "Username must be 3-32 characters long.",
        ),
        (
            "bad%20name",
            "long-enough-pw",
            "long-enough-pw",
            "Username may only contain",
        ),
        ("erin", "short", "short", "at least 8 characters"),
        ("erin", "password1", "password1", "too common"),
        (
            "erin",
            "erin-is-great",
            "erin-is-great",
            "must not contain your username",
        ),
        (
            "erin",
            "long-enough-pw",
            "different-pw",
            "Passwords do not match.",
        ),
    ] {
        let response = register(&client, user, password, confirm);
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(location(&response).as_deref(), Some("/register"));
        let page = client.get("/register").dispatch().into_string().unwrap();
        assert!(
            page.contains(message),
            "{user}/{password}: expected {message:?}"
        );
    }
    // None of those created an account.
    login(&client, "erin", "long-enough-pw");
    assert_eq!(
        client.get("/json/account_info").dispatch().status(),
        Status::Unauthorized
    );
}

#[test]
fn duplicate_usernames_are_rejected_case_insensitively() {
    let client = client();
    for name in ["admin", "ADMIN", "Admin"] {
        let response = register(&client, name, "another-long-pw", "another-long-pw");
        assert_eq!(location(&response).as_deref(), Some("/register"), "{name}");
        let page = client.get("/register").dispatch().into_string().unwrap();
        assert!(page.contains("already taken"), "{name}");
    }
    // The original admin password still works.
    assert_eq!(
        location(&login(&client, "admin", "admin")).as_deref(),
        Some("/user_banking")
    );
}

#[test]
fn registration_can_be_disabled() {
    let figment = figment("sqlite::memory:").merge(("allow_registration", false));
    let client = Client::tracked(super::build(figment)).unwrap();
    assert_eq!(
        client.get("/register").dispatch().status(),
        Status::NotFound
    );
    let response = register(&client, "frank", "frank-long-pw1", "frank-long-pw1");
    assert_eq!(response.status(), Status::NotFound);
    let page = client.get("/login").dispatch().into_string().unwrap();
    assert!(!page.contains(r#"href="/register""#));
}

/// Log in and return the raw (decrypted) session token.
fn login_token(client: &Client, user: &str, password: &str) -> String {
    let response = login(client, user, password);
    assert_eq!(location(&response).as_deref(), Some("/user_banking"));
    response
        .cookies()
        .get_private(SESSION_COOKIE)
        .expect("session cookie")
        .value()
        .to_owned()
}

/// Status of `/json/account_info` using only the given session token.
fn status_with_token(client: &Client, token: &str) -> Status {
    client
        .get("/json/account_info")
        .private_cookie(Cookie::new(SESSION_COOKIE, token.to_owned()))
        .dispatch()
        .status()
}

fn session_count(client: &Client) -> i64 {
    let pool = client.rocket().state::<db::Db>().unwrap().clone();
    let runtime = rocket::tokio::runtime::Runtime::new().unwrap();
    // Only valid for file databases (a separate runtime/connection).
    runtime.block_on(async move {
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap()
    })
}

#[test]
fn session_token_is_random_and_not_the_username() {
    let client = client();
    let a = login_token(&client, "admin", "admin");
    assert_eq!(a.len(), 64);
    assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!a.contains("admin"));
    // The old plain `user_name` cookie is meaningless now.
    let response = Client::untracked(super::build(figment("sqlite::memory:")))
        .unwrap()
        .get("/json/account_info")
        .private_cookie(Cookie::new("user_name", "admin"))
        .dispatch()
        .status();
    assert_eq!(response, Status::Unauthorized);
}

#[test]
fn session_is_rotated_on_login() {
    let client = client();
    let first = login_token(&client, "admin", "admin");
    assert_eq!(status_with_token(&client, &first), Status::Ok);
    // Logging in again from the same browser issues a new token and revokes
    // the old one.
    let second = login_token(&client, "admin", "admin");
    assert_ne!(first, second);
    assert_eq!(status_with_token(&client, &first), Status::Unauthorized);
    assert_eq!(status_with_token(&client, &second), Status::Ok);
}

#[test]
fn logout_revokes_the_session_server_side() {
    let client = client();
    let token = login_token(&client, "admin", "admin");
    post_form(&client, "/logout", "");
    // Replaying the captured cookie after logout no longer works.
    assert_eq!(status_with_token(&client, &token), Status::Unauthorized);
}

#[test]
fn logout_everywhere_revokes_all_of_a_users_sessions() {
    let (url, _dir) = file_db(&[("alice", "sunny-river-42")]);
    let laptop = Client::tracked(super::build(figment(&url))).unwrap();
    let phone = Client::tracked(super::build(figment(&url))).unwrap();
    let other = Client::tracked(super::build(figment(&url))).unwrap();
    let laptop_token = login_token(&laptop, "admin", "admin");
    login(&phone, "admin", "admin");
    login(&other, "alice", "sunny-river-42");
    assert_eq!(
        phone.get("/json/account_info").dispatch().status(),
        Status::Ok
    );
    assert_eq!(session_count(&laptop), 3);

    let response = post_form(&laptop, "/logout_all", "");
    assert_eq!(location(&response).as_deref(), Some("/login"));
    let page = laptop.get("/login").dispatch().into_string().unwrap();
    assert!(page.contains("Logged out of all sessions."));

    assert_eq!(
        status_with_token(&laptop, &laptop_token),
        Status::Unauthorized
    );
    assert_eq!(
        phone.get("/json/account_info").dispatch().status(),
        Status::Unauthorized
    );
    // Other users are unaffected.
    assert_eq!(
        other.get("/json/account_info").dispatch().status(),
        Status::Ok
    );
    assert_eq!(session_count(&laptop), 1);

    // Without a session it's a harmless redirect.
    let anonymous = Client::tracked(super::build(figment(&url))).unwrap();
    let response = post_form(&anonymous, "/logout_all", "");
    assert_eq!(location(&response).as_deref(), Some("/login"));
}

#[test]
fn sessions_expire_absolutely() {
    let figment = figment("sqlite::memory:").merge(("session_ttl_secs", 1));
    let client = Client::tracked(super::build(figment)).unwrap();
    login(&client, "admin", "admin");
    assert_eq!(
        client.get("/json/account_info").dispatch().status(),
        Status::Ok
    );
    std::thread::sleep(std::time::Duration::from_millis(1200));
    assert_eq!(
        client.get("/json/account_info").dispatch().status(),
        Status::Unauthorized
    );
    assert_eq!(
        location(&client.get("/user_banking").dispatch()).as_deref(),
        Some("/login")
    );
}

#[test]
fn idle_sessions_expire_but_activity_keeps_them_alive() {
    let figment = figment("sqlite::memory:").merge(("session_idle_secs", 1));
    let client = Client::tracked(super::build(figment)).unwrap();
    login(&client, "admin", "admin");
    // Activity every 0.5s keeps the session alive past the 1s idle limit.
    for _ in 0..4 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert_eq!(
            client.get("/json/account_info").dispatch().status(),
            Status::Ok
        );
    }
    std::thread::sleep(std::time::Duration::from_millis(1200));
    assert_eq!(
        client.get("/json/account_info").dispatch().status(),
        Status::Unauthorized
    );
}

#[test]
fn expired_sessions_are_purged_on_login() {
    let (url, _dir) = file_db(&[]);
    let short = figment(&url).merge(("session_ttl_secs", 1));
    let client = Client::tracked(super::build(short)).unwrap();
    login(&client, "admin", "admin");
    let other =
        Client::tracked(super::build(figment(&url).merge(("session_ttl_secs", 1)))).unwrap();
    login(&other, "admin", "admin");
    assert_eq!(session_count(&client), 2);
    std::thread::sleep(std::time::Duration::from_millis(1200));
    login(&client, "admin", "admin");
    assert_eq!(session_count(&client), 1, "expired rows removed");
}

#[test]
fn logged_in_users_visiting_login_go_to_their_account() {
    let client = client();
    login(&client, "admin", "admin");
    let response = client.get("/login").dispatch();
    assert_eq!(location(&response).as_deref(), Some("/user_banking"));
}

fn login_from<'c>(client: &'c Client, ip: &str, user: &str, password: &str) -> LocalResponse<'c> {
    let token = csrf(client);
    client
        .post("/login")
        .remote(format!("{ip}:40000").parse().unwrap())
        .header(ContentType::Form)
        .body(format!(
            "username={user}&password={password}&csrf_token={token}"
        ))
        .dispatch()
}

#[test]
fn login_attempts_are_rate_limited_per_ip() {
    let figment = figment("sqlite::memory:")
        .merge(("login_rate_limit", 3))
        .merge(("lockout_threshold", 0));
    let client = Client::tracked(super::build(figment)).unwrap();
    for _ in 0..3 {
        let response = login_from(&client, "10.0.0.1", "admin", "wrong");
        assert_eq!(response.status(), Status::SeeOther);
    }
    // 4th attempt from the same IP is refused before the password is checked,
    // even with the right password.
    let response = login_from(&client, "10.0.0.1", "admin", "admin");
    assert_eq!(response.status(), Status::TooManyRequests);
    let retry: u64 = response
        .headers()
        .get_one("Retry-After")
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&retry));
    assert!(
        response
            .into_string()
            .unwrap()
            .contains("Too many attempts")
    );

    // Spoofing X-Real-IP doesn't help (ip_header is disabled).
    let response = client
        .post("/login")
        .remote("10.0.0.1:40000".parse().unwrap())
        .header(rocket::http::Header::new("X-Real-IP", "192.0.2.99"))
        .header(ContentType::Form)
        .body(format!(
            "username=admin&password=admin&csrf_token={}",
            csrf(&client)
        ))
        .dispatch();
    assert_eq!(response.status(), Status::TooManyRequests);

    // A different client IP is unaffected.
    let response = login_from(&client, "10.0.0.2", "admin", "admin");
    assert_eq!(location(&response).as_deref(), Some("/user_banking"));
}

#[test]
fn rate_limit_window_expires() {
    let figment = figment("sqlite::memory:")
        .merge(("login_rate_limit", 1))
        .merge(("rate_limit_window_secs", 1));
    let client = Client::tracked(super::build(figment)).unwrap();
    login_from(&client, "10.0.0.1", "admin", "wrong");
    assert_eq!(
        login_from(&client, "10.0.0.1", "admin", "admin").status(),
        Status::TooManyRequests
    );
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let response = login_from(&client, "10.0.0.1", "admin", "admin");
    assert_eq!(location(&response).as_deref(), Some("/user_banking"));
}

#[test]
fn registration_is_rate_limited_separately() {
    let figment = figment("sqlite::memory:").merge(("login_rate_limit", 2));
    let client = Client::tracked(super::build(figment)).unwrap();
    for name in ["user1", "user2"] {
        let response = register(&client, name, "sunny-river-42", "sunny-river-42");
        assert_eq!(response.status(), Status::SeeOther);
    }
    let response = register(&client, "user3", "sunny-river-42", "sunny-river-42");
    assert_eq!(response.status(), Status::TooManyRequests);
    // Logins have their own budget.
    assert_eq!(
        location(&login(&client, "user1", "sunny-river-42")).as_deref(),
        Some("/user_banking")
    );
}

#[test]
fn account_locks_after_repeated_failures_and_unlocks_later() {
    let (url, _dir) = file_db(&[("alice", "sunny-river-42")]);
    let figment = figment(&url)
        .merge(("lockout_threshold", 3))
        .merge(("lockout_secs", 1))
        .merge(("login_rate_limit", 0));
    let client = Client::tracked(super::build(figment)).unwrap();
    for _ in 0..2 {
        login(&client, "admin", "wrong");
        let page = client.get("/login").dispatch().into_string().unwrap();
        assert!(page.contains("Invalid username/password."));
    }
    login(&client, "admin", "wrong");
    let page = client.get("/login").dispatch().into_string().unwrap();
    assert!(page.contains("temporarily locked"), "3rd failure locks");

    // Even the correct password is refused while locked.
    let response = login(&client, "admin", "admin");
    assert_eq!(location(&response).as_deref(), Some("/login"));
    let page = client.get("/login").dispatch().into_string().unwrap();
    assert!(page.contains("temporarily locked"));
    assert_eq!(
        client.get("/json/account_info").dispatch().status(),
        Status::Unauthorized
    );

    // Other accounts are unaffected.
    assert_eq!(
        location(&login(&client, "alice", "sunny-river-42")).as_deref(),
        Some("/user_banking")
    );

    // After the lock expires the right password works again.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(
        location(&login(&client, "admin", "admin")).as_deref(),
        Some("/user_banking")
    );
}

#[test]
fn successful_login_resets_the_failure_count() {
    let figment = figment("sqlite::memory:")
        .merge(("lockout_threshold", 3))
        .merge(("login_rate_limit", 0));
    let client = Client::tracked(super::build(figment)).unwrap();
    for _ in 0..2 {
        login(&client, "admin", "wrong");
    }
    assert_eq!(
        location(&login(&client, "admin", "admin")).as_deref(),
        Some("/user_banking")
    );
    for _ in 0..2 {
        login(&client, "admin", "wrong");
    }
    // Only 2 consecutive failures since the success: not locked.
    assert_eq!(
        location(&login(&client, "admin", "admin")).as_deref(),
        Some("/user_banking")
    );
}

#[test]
fn unknown_users_take_as_long_as_wrong_passwords() {
    // Unknown usernames are verified against a dummy hash, so they cost
    // about as much as a real wrong password (no cheap user enumeration).
    let figment = figment("sqlite::memory:")
        .merge(("login_rate_limit", 0))
        .merge(("lockout_threshold", 0));
    let client = Client::tracked(super::build(figment)).unwrap();
    login(&client, "nobody", "x"); // warm up the dummy hash
    let time = |user: &str| {
        let start = std::time::Instant::now();
        for _ in 0..3 {
            login(&client, user, "wrong-password");
        }
        start.elapsed()
    };
    let known = time("admin");
    let unknown = time("nobody");
    assert!(
        unknown * 3 > known,
        "unknown {unknown:?} vs known {known:?}: should be comparable"
    );
}

fn header(name: &'static str, value: &str) -> rocket::http::Header<'static> {
    rocket::http::Header::new(name, value.to_owned())
}

#[test]
fn pages_embed_the_csrf_token() {
    let client = client();
    let token = csrf(&client);
    assert_eq!(token.len(), 64);
    let hidden = format!(r#"name="csrf_token" value="{token}""#);
    assert!(
        client
            .get("/login")
            .dispatch()
            .into_string()
            .unwrap()
            .contains(&hidden)
    );
    assert!(
        client
            .get("/register")
            .dispatch()
            .into_string()
            .unwrap()
            .contains(&hidden)
    );
    login(&client, "admin", "admin");
    let token = csrf(&client);
    let page = client
        .get("/user_banking")
        .dispatch()
        .into_string()
        .unwrap();
    assert!(page.contains(&format!(r#"<meta name="csrf-token" content="{token}""#)));
    assert!(page.contains(&format!(r#"name="csrf_token" value="{token}""#)));
}

#[test]
fn login_without_a_valid_token_is_rejected() {
    let client = client();
    csrf(&client);
    for body in [
        "username=admin&password=admin".to_owned(),
        "username=admin&password=admin&csrf_token=".to_owned(),
        format!(
            "username=admin&password=admin&csrf_token={}",
            "0".repeat(64)
        ),
    ] {
        let response = client
            .post("/login")
            .header(ContentType::Form)
            .body(&body)
            .dispatch();
        assert_eq!(location(&response).as_deref(), Some("/login"), "{body}");
        let page = client.get("/login").dispatch().into_string().unwrap();
        assert!(page.contains("This form has expired"), "{body}");
    }
    assert_eq!(
        client.get("/json/account_info").dispatch().status(),
        Status::Unauthorized
    );
    // A fresh browser with no CSRF cookie at all is rejected too.
    let fresh = Client::tracked(super::build(figment("sqlite::memory:"))).unwrap();
    let response = fresh
        .post("/login")
        .header(ContentType::Form)
        .body(format!(
            "username=admin&password=admin&csrf_token={}",
            "a".repeat(64)
        ))
        .dispatch();
    assert_eq!(location(&response).as_deref(), Some("/login"));
}

#[test]
fn json_api_requires_the_csrf_header() {
    let client = client();
    login(&client, "admin", "admin");
    for token in [None, Some(String::new()), Some("f".repeat(64))] {
        let mut request = client
            .post("/json/deposit")
            .header(ContentType::JSON)
            .body(r#"{"amount": 5}"#);
        if let Some(token) = token {
            request = request.header(header(CSRF_HEADER, &token));
        }
        let response = request.dispatch();
        assert_eq!(response.status(), Status::Forbidden);
        let json: Value = response.into_json().unwrap();
        assert_eq!(json["success"], false);
        assert!(json["message"].as_str().unwrap().contains("CSRF"));
    }
    assert_eq!(balance(&client), "0.00");
    assert_eq!(
        post_json(&client, "/json/deposit", r#"{"amount": 5}"#).0,
        Status::Ok
    );
}

#[test]
fn logout_buttons_require_the_token() {
    let client = client();
    login(&client, "admin", "admin");
    for path in ["/logout", "/logout_all"] {
        let response = client
            .post(path)
            .header(ContentType::Form)
            .body("csrf_token=nope")
            .dispatch();
        assert_eq!(response.status(), Status::Forbidden, "{path}");
    }
    // Still logged in.
    assert_eq!(
        client.get("/json/account_info").dispatch().status(),
        Status::Ok
    );
}

#[test]
fn registration_requires_the_token() {
    let client = client();
    csrf(&client);
    let response = client
        .post("/register")
        .header(ContentType::Form)
        .body("username=mallory&password=sunny-river-42&confirm=sunny-river-42")
        .dispatch();
    assert_eq!(location(&response).as_deref(), Some("/register"));
    assert!(
        client
            .get("/register")
            .dispatch()
            .into_string()
            .unwrap()
            .contains("This form has expired")
    );
    login(&client, "mallory", "sunny-river-42");
    assert_eq!(
        client.get("/json/account_info").dispatch().status(),
        Status::Unauthorized
    );
}

#[test]
fn csrf_token_rotates_on_login_and_logout() {
    let client = client();
    let before = csrf(&client);
    login(&client, "admin", "admin");
    let after_login = csrf(&client);
    assert_ne!(before, after_login);
    post_form(&client, "/logout", "");
    assert_ne!(after_login, csrf(&client));
}

#[test]
fn cross_origin_posts_are_rejected_even_with_a_token() {
    let client = client();
    login(&client, "admin", "admin");
    let token = csrf(&client);
    let deposit = |origin: Option<(&'static str, &str)>| {
        let mut request = client
            .post("/json/deposit")
            .header(header("Host", "localhost:8080"))
            .header(ContentType::JSON)
            .header(header(CSRF_HEADER, &token))
            .body(r#"{"amount": 1}"#);
        if let Some((name, value)) = origin {
            request = request.header(header(name, value));
        }
        request.dispatch().status()
    };
    assert_eq!(
        deposit(Some(("Origin", "https://evil.example"))),
        Status::Forbidden
    );
    assert_eq!(deposit(Some(("Origin", "null"))), Status::Forbidden);
    assert_eq!(
        deposit(Some(("Origin", "http://localhost:8080.evil.example"))),
        Status::Forbidden
    );
    assert_eq!(
        deposit(Some(("Referer", "https://evil.example/page"))),
        Status::Forbidden
    );
    assert_eq!(balance(&client), "0.00");
    // Same origin (any letter case) and header-less clients are fine.
    assert_eq!(
        deposit(Some(("Origin", "http://localhost:8080"))),
        Status::Ok
    );
    assert_eq!(
        deposit(Some(("Origin", "http://LOCALHOST:8080"))),
        Status::Ok
    );
    assert_eq!(
        deposit(Some(("Referer", "http://localhost:8080/user_banking"))),
        Status::Ok
    );
    assert_eq!(deposit(None), Status::Ok);
    assert_eq!(balance(&client), "4.00");

    // Forms are checked too (403 before the token is even looked at).
    let response = client
        .post("/logout")
        .header(header("Host", "localhost:8080"))
        .header(header("Origin", "https://evil.example"))
        .header(ContentType::Form)
        .body(format!("csrf_token={token}"))
        .dispatch();
    assert_eq!(response.status(), Status::Forbidden);
}

#[test]
fn allowed_origins_config_overrides_host_matching() {
    let figment = figment("sqlite::memory:")
        .merge(("allowed_origins", vec!["https://bank.example".to_owned()]));
    let client = Client::tracked(super::build(figment)).unwrap();
    login(&client, "admin", "admin");
    let token = csrf(&client);
    let deposit = |origin: &str| {
        client
            .post("/json/deposit")
            .header(header("Host", "internal:8000"))
            .header(header("Origin", origin))
            .header(ContentType::JSON)
            .header(header(CSRF_HEADER, &token))
            .body(r#"{"amount": 1}"#)
            .dispatch()
            .status()
    };
    assert_eq!(deposit("https://bank.example"), Status::Ok);
    assert_eq!(
        deposit("http://bank.example"),
        Status::Forbidden,
        "scheme matters"
    );
    assert_eq!(deposit("http://internal:8000"), Status::Forbidden);
}
