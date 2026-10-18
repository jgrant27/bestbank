//! Failure-path tests: database errors injected with SQLite triggers, schema
//! changes and lock contention, plus configuration and startup errors. These
//! keep every error branch exercised (see README "Coverage").

use rocket::figment::Figment;
use rocket::http::{ContentType, Header, Status};
use rocket::local::blocking::Client;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use std::str::FromStr;
use std::time::Duration;

use crate::csrf::CSRF_HEADER;
use crate::db::{self, AppConfig, Db, TransferError};
use crate::sessions;
use crate::tests::{
    balance, csrf, figment, file_db, location, login, page_text, post_form, post_json,
};

const ALICE: (&str, &str) = ("alice", "sunny-river-42");
const BOB: (&str, &str) = ("bob", "quiet-forest-17");

/// Run raw SQL against a file database from outside the app.
fn sql(url: &str, statements: &[&str]) {
    let runtime = rocket::tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let pool = sqlx::SqlitePool::connect(url).await.unwrap();
        for statement in statements {
            sqlx::query(sqlx::AssertSqlSafe(statement.to_string()))
                .execute(&pool)
                .await
                .unwrap();
        }
        pool.close().await;
    });
}

/// `RAISE(ABORT)` trigger for `event` (e.g. `INSERT ON transactions`).
fn fail_on(event: &str) -> String {
    let name: String = event
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!(
        "CREATE TRIGGER fail_{name} BEFORE {event} BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
    )
}

fn app(url: &str) -> Client {
    Client::tracked(super::build(figment(url))).unwrap()
}

fn logged_in(url: &str, (user, password): (&str, &str)) -> Client {
    let client = app(url);
    assert_eq!(
        location(&login(&client, user, password)).as_deref(),
        Some("/user_banking")
    );
    client
}

fn flash_after_login(client: &Client, user: &str, password: &str) -> String {
    let response = login(client, user, password);
    assert_eq!(location(&response).as_deref(), Some("/login"));
    page_text(&client.get("/login").dispatch().into_string().unwrap())
}

fn json_with_origin(client: &Client, path: &str, body: &str, origin: &str) -> Status {
    client
        .post(path.to_owned())
        .header(ContentType::JSON)
        .header(Header::new(CSRF_HEADER, csrf(client)))
        .header(Header::new("Origin", origin.to_owned()))
        .body(body)
        .dispatch()
        .status()
}

#[test]
fn json_api_rejects_cross_origin_requests() {
    let (url, _dir) = file_db(&[ALICE]);
    let client = logged_in(&url, ALICE);
    for path in ["/json/deposit", "/json/withdraw", "/json/transfer"] {
        let status = json_with_origin(
            &client,
            path,
            r#"{"to": "bob", "amount": 1}"#,
            "https://evil.example",
        );
        assert_eq!(status, Status::Forbidden, "{path}");
    }
}

#[test]
fn write_failures_are_500s_and_change_nothing() {
    let (url, _dir) = file_db(&[ALICE, BOB]);
    let alice = logged_in(&url, ALICE);
    assert_eq!(
        post_json(&alice, "/json/deposit", r#"{"amount": 10}"#).0,
        Status::Ok
    );
    sql(&url, &[&fail_on("INSERT ON transactions")]);
    for (path, body) in [
        ("/json/deposit", r#"{"amount": 1}"#),
        ("/json/withdraw", r#"{"amount": 1}"#),
        ("/json/transfer", r#"{"to": "bob", "amount": 1}"#),
    ] {
        let (status, json) = post_json(&alice, path, body);
        assert_eq!(status, Status::InternalServerError, "{path}");
        assert_eq!(json["message"], "Something went wrong, please try again.");
    }
    assert_eq!(balance(&alice), "10.00");
}

#[test]
fn deposits_are_refused_at_the_balance_limit() {
    let (url, _dir) = file_db(&[ALICE]);
    sql(
        &url,
        &[&format!(
            "INSERT INTO transactions (user_id, amount_cents, created_at) \
             SELECT id, {}, 0 FROM users WHERE username = 'alice'",
            crate::money::Cents::MAX
        )],
    );
    let alice = logged_in(&url, ALICE);
    let (status, json) = post_json(&alice, "/json/deposit", r#"{"amount": 0.01}"#);
    assert_eq!(status, Status::UnprocessableEntity);
    assert_eq!(json["message"], "Balance limit exceeded.");
}

#[test]
fn read_failures_are_500s() {
    let (url, _dir) = file_db(&[ALICE, BOB]);
    let alice = logged_in(&url, ALICE);
    let admin = logged_in(&url, ("admin", "admin"));

    // History query fails (column gone), balance still works.
    sql(&url, &["ALTER TABLE transactions DROP COLUMN created_at"]);
    assert_eq!(
        alice.get("/json/account_info").dispatch().status(),
        Status::InternalServerError
    );
    assert_eq!(
        admin.get("/dump").dispatch().status(),
        Status::InternalServerError
    );

    // Balance query fails (table gone).
    sql(
        &url,
        &["ALTER TABLE transactions RENAME TO transactions_gone"],
    );
    assert_eq!(
        alice.get("/user_banking").dispatch().status(),
        Status::InternalServerError
    );
    assert_eq!(
        alice.get("/json/account_info").dispatch().status(),
        Status::InternalServerError
    );
    assert_eq!(
        admin.get("/dump").dispatch().status(),
        Status::InternalServerError
    );
}

#[test]
fn undecodable_user_rows_are_500s_not_panics() {
    let (url, _dir) = file_db(&[ALICE, BOB]);
    let alice = logged_in(&url, ALICE);
    let admin = logged_in(&url, ("admin", "admin"));
    // A row whose username is a BLOB can't be decoded as a String, and a
    // BLOB password hash breaks loading bob's row.
    sql(
        &url,
        &[
            "INSERT INTO users (username, password_hash, created_at) VALUES (x'ff00', 'x', 0)",
            "UPDATE users SET password_hash = x'00' WHERE username = 'bob'",
        ],
    );
    assert_eq!(
        admin.get("/dump").dispatch().status(),
        Status::InternalServerError
    );
    let (status, _) = post_json(&alice, "/json/transfer", r#"{"to": "bob", "amount": 1}"#);
    assert_eq!(status, Status::InternalServerError);
    let client = app(&url);
    assert!(flash_after_login(&client, "bob", BOB.1).contains("Something went wrong"));
}

#[test]
fn login_bookkeeping_failures_show_a_generic_error() {
    let (url, _dir) = file_db(&[ALICE]);
    sql(&url, &[&fail_on("UPDATE ON users")]);
    let client = app(&url);
    // Recording the failed attempt fails...
    assert!(flash_after_login(&client, "alice", "wrong-password").contains("Something went wrong"));
    // ...and so does clearing the counter after a good password.
    assert!(flash_after_login(&client, "alice", ALICE.1).contains("Something went wrong"));

    let (url, _dir) = file_db(&[ALICE]);
    sql(&url, &[&fail_on("INSERT ON sessions")]);
    let client = app(&url);
    assert!(flash_after_login(&client, "alice", ALICE.1).contains("Something went wrong"));
    assert_eq!(
        client.get("/json/account_info").dispatch().status(),
        Status::Unauthorized
    );
}

#[test]
fn logout_still_clears_the_cookie_when_the_database_fails() {
    let (url, _dir) = file_db(&[ALICE]);
    let first = logged_in(&url, ALICE);
    let second = logged_in(&url, ALICE);
    sql(&url, &[&fail_on("DELETE ON sessions")]);
    for (client, path) in [(&first, "/logout"), (&second, "/logout_all")] {
        let response = post_form(client, path, "");
        assert_eq!(location(&response).as_deref(), Some("/login"), "{path}");
        assert!(
            response
                .cookies()
                .get_private(crate::sessions::SESSION_COOKIE)
                .is_none()
        );
        assert_eq!(
            client.get("/json/account_info").dispatch().status(),
            Status::Unauthorized,
            "{path}"
        );
    }
}

#[test]
fn registration_database_failure_shows_a_generic_error() {
    let (url, _dir) = file_db(&[]);
    sql(&url, &[&fail_on("INSERT ON users")]);
    let client = Client::tracked(super::build(
        figment(&url).merge(("seed_demo_admin", false)),
    ))
    .unwrap();
    let response = post_form(
        &client,
        "/register",
        "username=carol&password=sunny-river-42&confirm=sunny-river-42",
    );
    assert_eq!(location(&response).as_deref(), Some("/register"));
    let page = page_text(&client.get("/register").dispatch().into_string().unwrap());
    assert!(page.contains("Something went wrong"), "{page}");
}

fn ignite(figment: Figment) -> Result<(), String> {
    let runtime = rocket::tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        super::build(figment).ignite().await.map(drop).map_err(|e| {
            let kind = format!("{:?}", e.kind());
            e.pretty_print();
            kind
        })
    })
}

#[test]
fn startup_fails_cleanly_on_bad_configuration_or_database() {
    // Wrong type for a setting.
    let error = ignite(figment("sqlite::memory:").merge(("login_rate_limit", "lots"))).unwrap_err();
    assert!(error.contains("FailedFairings"), "{error}");
    // Unparseable URL, and a directory that doesn't exist.
    for url in [
        "sqlite://x.db?no_such_option=1",
        "sqlite:///nonexistent-dir/x/bestbank.db",
    ] {
        let error = ignite(figment(url)).unwrap_err();
        assert!(error.contains("FailedFairings"), "{url}: {error}");
    }
    // Migrations that don't match what was applied before.
    let (url, _dir) = file_db(&[]);
    sql(
        &url,
        &[
            "UPDATE _sqlx_migrations SET checksum = x'00' WHERE version = (SELECT MIN(version) FROM _sqlx_migrations)",
        ],
    );
    assert!(ignite(figment(&url)).is_err());
    // Seeding the demo admin fails: insert refused...
    let (url, _dir) = file_db(&[]);
    sql(&url, &[&fail_on("INSERT ON users")]);
    assert!(ignite(figment(&url)).is_err());
    assert!(ignite(figment(&url).merge(("seed_demo_admin", false))).is_ok());
    // ...or the existing admin row can't be read.
    let (url, _dir) = file_db(&[("admin", "admin")]);
    sql(
        &url,
        &["UPDATE users SET password_hash = x'00' WHERE username = 'admin'"],
    );
    assert!(ignite(figment(&url)).is_err());
}

#[test]
fn config_defaults_apply_when_settings_are_missing() {
    let config: AppConfig = Figment::new().extract().unwrap();
    assert_eq!(config.database_url, "sqlite://bestbank.db");
    assert!(config.seed_demo_admin);
    assert!(config.allow_registration);
    assert_eq!(config.session_ttl_secs, 8 * 60 * 60);
    assert_eq!(config.session_idle_secs, 30 * 60);
    assert_eq!(config.session_check_secs, 15);
    assert_eq!(config.login_rate_limit, 10);
    assert_eq!(config.rate_limit_window_secs, 60);
    assert_eq!(config.lockout_threshold, 5);
    assert_eq!(config.lockout_secs, 15 * 60);
    assert_eq!(config.allowed_origins, Vec::<String>::new());
    // Rocket.toml spells out the same defaults.
    let from_file: AppConfig = rocket::Config::figment().extract().unwrap();
    assert_eq!(from_file.session_ttl_secs, config.session_ttl_secs);
    assert_eq!(from_file.login_rate_limit, config.login_rate_limit);
    assert_eq!(from_file.lockout_secs, config.lockout_secs);
}

/// A database with no tables: every query fails.
async fn empty_db() -> Db {
    crate::tests::init_tracing();
    let options = SqliteConnectOptions::from_str("sqlite::memory:").unwrap();
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap()
}

fn test_config() -> AppConfig {
    Figment::new().extract().unwrap()
}

#[rocket::async_test]
async fn database_functions_report_errors() {
    let db = empty_db().await;
    let config = test_config();
    assert!(
        sessions::create(&db, &config, 1, Some("old"))
            .await
            .is_err()
    );
    assert!(sessions::create(&db, &config, 1, None).await.is_err());
    assert!(sessions::authenticate(&db, &config, "t").await.is_err());
    assert!(sessions::is_active(&db, &config, "s").await.is_err());
    assert!(sessions::delete(&db, "t").await.is_err());
    assert!(sessions::delete_all_for_user(&db, 1).await.is_err());
    assert!(sessions::purge_expired(&db, &config).await.is_err());
    assert!(db::deposit(&db, 1, 100).await.is_err());
    assert!(db::withdraw(&db, 1, 100).await.is_err());
    assert!(db::transfer(&db, 1, 2, 100).await.is_err());
    assert!(db::record_failed_login(&db, 1, 5, 60).await.is_err());
    assert!(db::record_successful_login(&db, 1).await.is_err());
}

/// A real (migrated) file database with alice and bob, alice holding $10.
async fn funded_db(journal: SqliteJournalMode) -> (Db, i64, i64, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("t.db").display());
    let setup = db::connect(&url).await.unwrap();
    let alice = db::create_user(&setup, "alice", "x").await.unwrap();
    let bob = db::create_user(&setup, "bob", "x").await.unwrap();
    assert!(db::deposit(&setup, alice, 1000).await.unwrap());
    setup.close().await;
    let options = SqliteConnectOptions::from_str(&url)
        .unwrap()
        .journal_mode(journal)
        .busy_timeout(Duration::from_millis(50))
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .unwrap();
    (pool, alice, bob, dir)
}

#[rocket::async_test]
async fn transfer_failures_roll_back() {
    let (db, alice, bob, _dir) = funded_db(SqliteJournalMode::Wal).await;

    // Unknown recipient id: the debit violates the foreign key.
    assert!(db::transfer(&db, alice, 999_999, 100).await.is_err());
    assert_eq!(db::balance(&db, alice).await.unwrap(), 1000);

    // The credit fails: the debit must not stick.
    sqlx::query(sqlx::AssertSqlSafe(fail_on(
        "INSERT ON transactions WHEN NEW.kind = 'transfer_in'",
    )))
    .execute(&db)
    .await
    .unwrap();
    assert!(db::transfer(&db, alice, bob, 100).await.is_err());
    assert_eq!(db::balance(&db, alice).await.unwrap(), 1000);
    assert_eq!(db::balance(&db, bob).await.unwrap(), 0);
    sqlx::query("DROP TRIGGER fail_INSERT_ON_transactions_WHEN_NEW_kind____transfer_in_")
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(db::transfer(&db, alice, bob, 100).await.unwrap(), Ok(()));

    // Another writer holds the lock: BEGIN IMMEDIATE times out.
    let writer = db.begin_with("BEGIN IMMEDIATE").await.unwrap();
    assert!(db::transfer(&db, alice, bob, 100).await.is_err());
    writer.rollback().await.unwrap();
    assert_eq!(
        db::transfer(&db, alice, bob, 100_000).await.unwrap(),
        Err(TransferError::InsufficientFunds)
    );
}

#[rocket::async_test]
async fn transfer_commit_failure_is_an_error() {
    // In rollback-journal mode COMMIT needs an exclusive lock, which an open
    // reader blocks, so the commit itself fails (after the busy timeout).
    let (db, alice, bob, _dir) = funded_db(SqliteJournalMode::Delete).await;
    let mut reader = db.begin().await.unwrap();
    let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM transactions")
        .fetch_one(&mut *reader)
        .await
        .unwrap();
    assert!(db::transfer(&db, alice, bob, 100).await.is_err());
    reader.rollback().await.unwrap();
    assert_eq!(db::balance(&db, alice).await.unwrap(), 1000);
    assert_eq!(db::balance(&db, bob).await.unwrap(), 0);
}

#[test]
fn logout_without_a_session_just_redirects() {
    let client = app("sqlite::memory:");
    let response = post_form(&client, "/logout", "");
    assert_eq!(location(&response).as_deref(), Some("/login"));
}

#[test]
fn incomplete_or_malformed_forms_are_rejected() {
    let client = app("sqlite::memory:");
    let token = csrf(&client);
    for (path, body) in [
        ("/login", format!("password=x&csrf_token={token}")),
        ("/login", format!("username=x&csrf_token={token}")),
        (
            "/login",
            "username=x&password=y&username=z&bogus=1".to_owned(),
        ),
        ("/register", format!("username=carol&csrf_token={token}")),
        (
            "/register",
            format!("password=a&confirm=a&csrf_token={token}"),
        ),
        ("/register", "confirm=x".to_owned()),
    ] {
        let status = client
            .post(path)
            .header(ContentType::Form)
            .body(body.clone())
            .dispatch()
            .status();
        assert!(
            status == Status::UnprocessableEntity || status == Status::SeeOther,
            "{path} {body}: {status}"
        );
        assert_ne!(status, Status::InternalServerError);
    }
    // multipart/form-data works too.
    let boundary = "XyZ";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nadmin\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nadmin\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n{token}\r\n\
         --{boundary}--\r\n"
    );
    let response = client
        .post("/login")
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch();
    assert_eq!(location(&response).as_deref(), Some("/user_banking"));
}
