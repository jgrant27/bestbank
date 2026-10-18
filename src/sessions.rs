//! Server-side sessions.
//!
//! The client holds a random 256-bit token in an encrypted, `HttpOnly`,
//! `SameSite=Strict` private cookie. The server stores only the token's
//! SHA-256, with an absolute expiry (`session_ttl_secs`) and an idle timeout
//! (`session_idle_secs`). Sessions are rotated on login, deleted on logout,
//! and "log out everywhere" revokes all of a user's sessions.

use std::fmt::Write;

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::db::{AppConfig, Db};

/// Name of the private session cookie.
pub const SESSION_COOKIE: &str = "session";

/// A freshly created session: the raw token goes in the cookie.
pub struct NewSession {
    pub token: String,
}

/// An authenticated session looked up from a token.
#[derive(Debug, Clone)]
pub struct SessionUser {
    pub session_id: String,
    pub user_id: i64,
    pub username: String,
}

fn now_millis() -> i64 {
    Utc::now().timestamp_millis()
}

fn secs_to_millis(secs: u64) -> i64 {
    i64::try_from(secs)
        .unwrap_or(i64::MAX / 1000)
        .saturating_mul(1000)
}

/// Server-side id for a token: lowercase hex SHA-256.
pub fn session_id(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Create a session for `user_id`, first deleting `previous_token`'s
/// session (rotation) and any expired sessions.
pub async fn create(
    db: &Db,
    config: &AppConfig,
    user_id: i64,
    previous_token: Option<&str>,
) -> Result<NewSession, sqlx::Error> {
    if let Some(previous) = previous_token {
        delete(db, previous).await?;
    }
    purge_expired(db, config).await?;
    let token = crate::telemetry::random_hex(32);
    let now = now_millis();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, created_at, last_seen, expires_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(session_id(&token))
    .bind(user_id)
    .bind(now)
    .bind(now)
    .bind(now.saturating_add(secs_to_millis(config.session_ttl_secs)))
    .execute(db)
    .await?;
    Ok(NewSession { token })
}

/// Look up a live session for `token` and refresh its idle timer.
/// Returns `None` if the session doesn't exist, has expired or is idle.
pub async fn authenticate(
    db: &Db,
    config: &AppConfig,
    token: &str,
) -> Result<Option<SessionUser>, sqlx::Error> {
    let id = session_id(token);
    let now = now_millis();
    let idle_cutoff = now.saturating_sub(secs_to_millis(config.session_idle_secs));
    // Refresh last_seen only if the session is still valid; RETURNING tells
    // us whether it was.
    let row: Option<(i64, String)> = sqlx::query_as(
        "UPDATE sessions SET last_seen = ?2
         WHERE id = ?1 AND expires_at > ?2 AND last_seen > ?3
         RETURNING user_id, (SELECT username FROM users WHERE users.id = sessions.user_id)",
    )
    .bind(&id)
    .bind(now)
    .bind(idle_cutoff)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(user_id, username)| SessionUser {
        session_id: id,
        user_id,
        username,
    }))
}

/// Is the session with this server-side id still valid? (No refresh.)
pub async fn is_active(db: &Db, config: &AppConfig, session_id: &str) -> Result<bool, sqlx::Error> {
    let now = now_millis();
    let idle_cutoff = now.saturating_sub(secs_to_millis(config.session_idle_secs));
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE id = ? AND expires_at > ? AND last_seen > ?",
    )
    .bind(session_id)
    .bind(now)
    .bind(idle_cutoff)
    .fetch_one(db)
    .await?;
    Ok(count > 0)
}

/// Delete the session for `token` (logout).
pub async fn delete(db: &Db, token: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(session_id(token))
        .execute(db)
        .await?;
    Ok(())
}

/// Delete every session belonging to `user_id`. Returns how many.
pub async fn delete_all_for_user(db: &Db, user_id: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(result.rows_affected())
}

/// Remove expired and idle sessions.
pub async fn purge_expired(db: &Db, config: &AppConfig) -> Result<u64, sqlx::Error> {
    let now = now_millis();
    let idle_cutoff = now.saturating_sub(secs_to_millis(config.session_idle_secs));
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?")
        .bind(now)
        .bind(idle_cutoff)
        .execute(db)
        .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_is_sha256_hex() {
        assert_eq!(
            session_id("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
