use std::collections::HashMap;

use rocket::State;
use rocket::form::Form;
use rocket::http::{Cookie, CookieJar, SameSite, Status};
use rocket::outcome::IntoOutcome;
use rocket::request::{self, FlashMessage, FromRequest, Request};
use rocket::response::{Flash, Redirect};

use rocket_dyn_templates::Template;

use crate::db::{self, AppConfig, Db};
use crate::telemetry::RequestId;

use crate::ratelimit::LoginAttempt;
use crate::sessions;
pub use crate::sessions::SESSION_COOKIE;

pub const LOCKED_MESSAGE: &str =
    "This account is temporarily locked after too many failed logins. Please try again later.";

#[derive(FromForm)]
pub struct Login {
    pub username: String,
    pub password: String,
}

/// A logged-in user, authenticated via a live server-side session.
#[derive(Debug)]
pub struct User {
    pub id: i64,
    pub name: String,
    /// Server-side session id (SHA-256 of the cookie token).
    pub session_id: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // The session cookie is a Rocket *private* cookie (encrypted and
        // authenticated with the secret key) holding a random token; the
        // token must match a live, unexpired server-side session.
        let Some(token) = request
            .cookies()
            .get_private(SESSION_COOKIE)
            .map(|cookie| cookie.value().to_owned())
        else {
            return request::Outcome::Forward(Status::Unauthorized);
        };
        let (Some(db), Some(config)) = (
            request.rocket().state::<Db>(),
            request.rocket().state::<AppConfig>(),
        ) else {
            return request::Outcome::Forward(Status::InternalServerError);
        };
        match sessions::authenticate(db, config, &token).await {
            Ok(session) => session
                .map(|s| User {
                    id: s.user_id,
                    name: s.username,
                    session_id: s.session_id,
                })
                .or_forward(Status::Unauthorized),
            Err(e) => {
                tracing::error!(error = %e, "session lookup failed");
                request::Outcome::Error((Status::InternalServerError, ()))
            }
        }
    }
}

fn session_cookie(token: String, config: &AppConfig) -> Cookie<'static> {
    // SameSite=Strict stops browsers sending the session cookie on
    // cross-site requests; HttpOnly keeps it away from page scripts.
    Cookie::build((SESSION_COOKIE, token))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(rocket::time::Duration::seconds(
            i64::try_from(config.session_ttl_secs).unwrap_or(i64::MAX),
        ))
        .build()
}

fn something_went_wrong() -> Box<Flash<Redirect>> {
    Box::new(Flash::error(
        Redirect::to(uri!(login_page)),
        "Something went wrong, please try again.",
    ))
}

#[post("/login", data = "<login>")]
pub async fn login(
    db: &State<Db>,
    config: &State<AppConfig>,
    jar: &CookieJar<'_>,
    _attempt: LoginAttempt,
    login: Form<Login>,
    request_id: RequestId,
) -> Result<Redirect, Box<Flash<Redirect>>> {
    let invalid = || {
        Box::new(Flash::error(
            Redirect::to(uri!(login_page)),
            "Invalid username/password.",
        ))
    };
    let user = db::find_user(db, &login.username).await.map_err(|e| {
        tracing::error!(request_id = %request_id.0, error = %e, "user lookup failed");
        something_went_wrong()
    })?;
    if user.as_ref().is_some_and(db::UserRow::is_locked) {
        tracing::warn!(request_id = %request_id.0, username = ?login.username, "login refused: account locked");
        return Err(Box::new(Flash::error(
            Redirect::to(uri!(login_page)),
            LOCKED_MESSAGE,
        )));
    }
    // Argon2 is deliberately slow; keep it off the async executor. Unknown
    // users are checked against a dummy hash so response timing doesn't
    // reveal which usernames exist.
    let password = login.password.clone();
    let hash = user.as_ref().map(|u| u.password_hash.clone());
    let verified = rocket::tokio::task::spawn_blocking(move || {
        if let Some(hash) = hash {
            crate::hashing::verify_password(&password, &hash)
        } else {
            crate::hashing::verify_password(&password, crate::hashing::dummy_hash());
            false
        }
    })
    .await
    .unwrap_or(false);

    let Some(user) = user else {
        tracing::warn!(request_id = %request_id.0, username = ?login.username, "login failed: unknown user");
        return Err(invalid());
    };
    if !verified {
        let locked = db::record_failed_login(db, user.id, config.lockout_threshold, config.lockout_secs)
            .await
            .map_err(|e| {
                tracing::error!(request_id = %request_id.0, error = %e, "recording failed login failed");
                something_went_wrong()
            })?;
        tracing::warn!(request_id = %request_id.0, username = ?user.username, locked, "login failed: bad password");
        if locked {
            return Err(Box::new(Flash::error(
                Redirect::to(uri!(login_page)),
                LOCKED_MESSAGE,
            )));
        }
        return Err(invalid());
    }

    db::record_successful_login(db, user.id).await.map_err(|e| {
        tracing::error!(request_id = %request_id.0, error = %e, "resetting login failures failed");
        something_went_wrong()
    })?;
    // Always issue a fresh session (rotation), revoking any previous one
    // presented by this browser.
    let previous = jar
        .get_private(SESSION_COOKIE)
        .map(|c| c.value().to_owned());
    let session = sessions::create(db, config, user.id, previous.as_deref())
        .await
        .map_err(|e| {
            tracing::error!(request_id = %request_id.0, error = %e, "session creation failed");
            something_went_wrong()
        })?;
    jar.add_private(session_cookie(session.token, config));
    // Debug-format user input so control characters can't forge log lines.
    tracing::info!(request_id = %request_id.0, username = ?user.username, "login succeeded");
    Ok(Redirect::to(uri!(crate::banking::user_banking)))
}

/// Already logged in: go to the account page.
#[get("/login")]
pub fn login_user(_user: User) -> Redirect {
    Redirect::to(uri!(crate::banking::user_banking))
}

#[get("/login", rank = 1)]
pub fn login_page(config: &State<AppConfig>, flash: Option<FlashMessage<'_>>) -> Template {
    let mut context: HashMap<&str, &str> = HashMap::new();
    if config.allow_registration {
        context.insert("allow_registration", "true");
    }
    if let Some(ref flash) = flash {
        context.insert("flash", flash.message());
        context.insert("flash_kind", flash.kind());
    }
    Template::render("login", &context)
}

/// Log out: delete this browser's server-side session and its cookie.
#[post("/logout")]
pub async fn logout(db: &State<Db>, jar: &CookieJar<'_>, request_id: RequestId) -> Flash<Redirect> {
    if let Some(cookie) = jar.get_private(SESSION_COOKIE) {
        match sessions::delete(db, cookie.value()).await {
            Ok(()) => tracing::info!(request_id = %request_id.0, "logout"),
            Err(e) => {
                tracing::error!(request_id = %request_id.0, error = %e, "session delete failed");
            }
        }
    }
    jar.remove_private(Cookie::build(SESSION_COOKIE).path("/"));
    Flash::success(Redirect::to(uri!(login_page)), "Successfully logged out.")
}

/// Log out everywhere: revoke every session belonging to this user.
#[post("/logout_all")]
pub async fn logout_all(
    db: &State<Db>,
    jar: &CookieJar<'_>,
    user: User,
    request_id: RequestId,
) -> Flash<Redirect> {
    match sessions::delete_all_for_user(db, user.id).await {
        Ok(n) => {
            tracing::info!(request_id = %request_id.0, username = ?user.name, sessions = n, "logged out everywhere");
        }
        Err(e) => {
            tracing::error!(request_id = %request_id.0, error = %e, "session revocation failed");
        }
    }
    jar.remove_private(Cookie::build(SESSION_COOKIE).path("/"));
    Flash::success(
        Redirect::to(uri!(login_page)),
        "Logged out of all sessions.",
    )
}

/// `POST /logout_all` without a session: nothing to revoke.
#[post("/logout_all", rank = 2)]
pub fn logout_all_anonymous() -> Redirect {
    Redirect::to(uri!(login_page))
}

#[get("/")]
pub fn index() -> Redirect {
    Redirect::to(uri!(login_page))
}
