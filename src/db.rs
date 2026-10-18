//! SQLite persistence via `sqlx`.
//!
//! The database URL comes from the `database_url` config key (see
//! `Rocket.toml`, or `ROCKET_DATABASE_URL`). Migrations in `migrations/` are
//! embedded in the binary and applied at startup. All money is integer cents.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use rocket::fairing::AdHoc;
use rocket::serde::Deserialize;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};

use crate::money::Cents;

pub type Db = SqlitePool;

/// Application settings read from Rocket's configuration.
#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct AppConfig {
    /// e.g. `sqlite://bestbank.db` or `sqlite::memory:`.
    #[serde(default = "default_database_url")]
    pub database_url: String,
    /// Create the demo `admin`/`admin` account if it doesn't exist.
    #[serde(default = "default_true")]
    pub seed_demo_admin: bool,
    /// Allow new users to sign up at `/register`.
    #[serde(default = "default_true")]
    pub allow_registration: bool,
}

fn default_database_url() -> String {
    "sqlite://bestbank.db".into()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TransactionRow {
    pub amount_cents: Cents,
    pub created_at: i64,
}

impl TransactionRow {
    pub fn timestamp(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.created_at).unwrap_or_default()
    }
}

fn now_millis() -> i64 {
    Utc::now().timestamp_millis()
}

/// Open (creating if needed) the database and run migrations.
pub async fn connect(url: &str) -> Result<Db, sqlx::Error> {
    let in_memory = url.contains(":memory:") || url.contains("mode=memory");
    let options = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = if in_memory {
        // Every connection to `:memory:` is a separate database, so keep
        // exactly one connection alive for the lifetime of the pool.
        SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await?
    } else {
        SqlitePoolOptions::new()
            .connect_with(options.journal_mode(SqliteJournalMode::Wal))
            .await?
    };
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// Fairing: connect, migrate, optionally seed, and manage the pool.
pub fn stage() -> AdHoc {
    AdHoc::try_on_ignite("SQLite database", |rocket| async move {
        let config: AppConfig = match rocket.figment().extract() {
            Ok(config) => config,
            Err(e) => {
                tracing::error!(error = %e, "invalid app configuration");
                return Err(rocket);
            }
        };
        let pool = match connect(&config.database_url).await {
            Ok(pool) => pool,
            Err(e) => {
                tracing::error!(error = %e, url = %config.database_url, "database setup failed");
                return Err(rocket);
            }
        };
        if config.seed_demo_admin
            && let Err(e) = seed_demo_admin(&pool).await
        {
            tracing::error!(error = %e, "seeding demo admin failed");
            return Err(rocket);
        }
        tracing::info!(url = %config.database_url, "database ready");
        Ok(rocket.manage(pool).manage(config))
    })
}

async fn seed_demo_admin(db: &Db) -> Result<(), sqlx::Error> {
    if find_user(db, "admin").await?.is_none() {
        let hash = rocket::tokio::task::spawn_blocking(|| crate::hashing::hash_password("admin"))
            .await
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        create_user(db, "admin", &hash).await?;
        tracing::warn!("seeded demo account admin/admin; never use this outside a demo");
    }
    Ok(())
}

pub async fn find_user(db: &Db, username: &str) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as("SELECT id, username, password_hash FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(db)
        .await
}

/// Insert a user, returning its id. Fails on a duplicate username.
pub async fn create_user(db: &Db, username: &str, password_hash: &str) -> Result<i64, sqlx::Error> {
    let result =
        sqlx::query("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)")
            .bind(username)
            .bind(password_hash)
            .bind(now_millis())
            .execute(db)
            .await?;
    Ok(result.last_insert_rowid())
}

/// All `(id, username)` pairs, oldest first.
pub async fn list_users(db: &Db) -> Result<Vec<(i64, String)>, sqlx::Error> {
    sqlx::query_as("SELECT id, username FROM users ORDER BY id")
        .fetch_all(db)
        .await
}

pub async fn balance(db: &Db, user_id: i64) -> Result<Cents, sqlx::Error> {
    sqlx::query_scalar("SELECT COALESCE(SUM(amount_cents), 0) FROM transactions WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(db)
        .await
}

/// Transaction history, newest first.
pub async fn transactions(db: &Db, user_id: i64) -> Result<Vec<TransactionRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT amount_cents, created_at FROM transactions WHERE user_id = ? ORDER BY id DESC",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
}

/// Credit `cents` (> 0). Returns `false` if the balance would overflow.
pub async fn deposit(db: &Db, user_id: i64, cents: Cents) -> Result<bool, sqlx::Error> {
    // Single conditional INSERT, so the check and the write are atomic.
    let result = sqlx::query(
        "INSERT INTO transactions (user_id, amount_cents, created_at)
         SELECT ?1, ?2, ?3
         WHERE (SELECT COALESCE(SUM(amount_cents), 0) FROM transactions WHERE user_id = ?1)
               <= ?4 - ?2",
    )
    .bind(user_id)
    .bind(cents)
    .bind(now_millis())
    .bind(Cents::MAX)
    .execute(db)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Debit `cents` (> 0). Returns `false` (and writes nothing) if funds are
/// insufficient. The balance check and insert are a single atomic statement,
/// so concurrent withdrawals can't overdraw the account.
pub async fn withdraw(db: &Db, user_id: i64, cents: Cents) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO transactions (user_id, amount_cents, created_at)
         SELECT ?1, -?2, ?3
         WHERE (SELECT COALESCE(SUM(amount_cents), 0) FROM transactions WHERE user_id = ?1) >= ?2",
    )
    .bind(user_id)
    .bind(cents)
    .bind(now_millis())
    .execute(db)
    .await?;
    Ok(result.rows_affected() == 1)
}
