//! User registration.

use std::collections::HashMap;

use rocket::State;
use rocket::form::Form;
use rocket::request::FlashMessage;
use rocket::response::{Flash, Redirect};
use rocket_dyn_templates::Template;

use crate::db::{self, AppConfig, Db};
use crate::login::User;
use crate::telemetry::RequestId;

pub const USERNAME_MIN: usize = 3;
pub const USERNAME_MAX: usize = 32;
pub const PASSWORD_MIN: usize = 8;
pub const PASSWORD_MAX: usize = 128;

/// A tiny deny-list of the most common passwords; enough for a demo.
const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "12345678",
    "123456789",
    "1234567890",
    "qwertyui",
    "qwerty123",
    "11111111",
    "iloveyou",
    "letmein1",
    "abcd1234",
    "bestbank",
    "admin123",
    "welcome1",
];

#[derive(FromForm)]
pub struct Registration {
    pub username: String,
    pub password: String,
    pub confirm: String,
}

/// Check a username: 3–32 characters from `[A-Za-z0-9_.-]`.
pub fn validate_username(username: &str) -> Result<(), &'static str> {
    if !(USERNAME_MIN..=USERNAME_MAX).contains(&username.len()) {
        return Err("Username must be 3-32 characters long.");
    }
    if !username
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err("Username may only contain letters, digits, '_', '.' and '-'.");
    }
    Ok(())
}

/// Password strength rules: 8–128 characters, not a very common password,
/// and must not contain the username.
pub fn validate_password(username: &str, password: &str) -> Result<(), &'static str> {
    let chars = password.chars().count();
    if chars < PASSWORD_MIN {
        return Err("Password must be at least 8 characters long.");
    }
    if chars > PASSWORD_MAX {
        return Err("Password must be at most 128 characters long.");
    }
    let lower = password.to_lowercase();
    if COMMON_PASSWORDS.contains(&lower.as_str()) {
        return Err("That password is too common; please choose another.");
    }
    if lower.contains(&username.to_lowercase()) {
        return Err("Password must not contain your username.");
    }
    Ok(())
}

fn validate(form: &Registration) -> Result<(), &'static str> {
    validate_username(&form.username)?;
    validate_password(&form.username, &form.password)?;
    if form.password != form.confirm {
        return Err("Passwords do not match.");
    }
    Ok(())
}

fn registration_enabled(config: &AppConfig) -> Option<()> {
    config.allow_registration.then_some(())
}

fn error(message: &str) -> Flash<Redirect> {
    Flash::error(Redirect::to(uri!(register_page)), message)
}

/// Already logged in: go to the account page.
#[get("/register")]
pub fn register_logged_in(_user: User) -> Redirect {
    Redirect::to(uri!(crate::banking::user_banking))
}

#[get("/register", rank = 1)]
pub fn register_page(
    config: &State<AppConfig>,
    flash: Option<FlashMessage<'_>>,
) -> Option<Template> {
    registration_enabled(config)?;
    let mut context: HashMap<&str, &str> = HashMap::new();
    if let Some(ref flash) = flash {
        context.insert("flash", flash.message());
        context.insert("flash_kind", flash.kind());
    }
    Some(Template::render("register", &context))
}

#[post("/register", data = "<form>")]
pub async fn register(
    db: &State<Db>,
    config: &State<AppConfig>,
    form: Form<Registration>,
    request_id: RequestId,
) -> Option<Flash<Redirect>> {
    registration_enabled(config)?;
    if let Err(message) = validate(&form) {
        return Some(error(message));
    }
    let password = form.password.clone();
    let Ok(hash) =
        rocket::tokio::task::spawn_blocking(move || crate::hashing::hash_password(&password)).await
    else {
        return Some(error("Something went wrong, please try again."));
    };
    match db::create_user(db, &form.username, &hash).await {
        Ok(_) => {
            tracing::info!(request_id = %request_id.0, username = ?form.username, "user registered");
            Some(Flash::success(
                Redirect::to(uri!(crate::login::login_page)),
                "Account created. Please log in.",
            ))
        }
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            tracing::info!(request_id = %request_id.0, username = ?form.username, "registration rejected: username taken");
            Some(error("That username is already taken."))
        }
        Err(e) => {
            tracing::error!(request_id = %request_id.0, error = %e, "registration failed");
            Some(error("Something went wrong, please try again."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames() {
        for ok in ["bob", "alice_1", "a.b-c", &"x".repeat(32)] {
            assert!(validate_username(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "ab",
            &"x".repeat(33),
            "has space",
            "bad/char",
            "émile",
            "<script>",
        ] {
            assert!(validate_username(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn passwords() {
        assert!(validate_password("alice", "correct horse").is_ok());
        assert!(validate_password("alice", "short").is_err());
        assert!(validate_password("alice", &"x".repeat(129)).is_err());
        assert!(validate_password("alice", "Password1").is_err(), "common");
        assert!(
            validate_password("alice", "xxALICExx1").is_err(),
            "contains username"
        );
    }
}
