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

/// Name of the (private, encrypted) session cookie.
pub const SESSION_COOKIE: &str = "user_name";

#[derive(FromForm)]
pub struct Login {
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
pub struct User {
    pub id: i64,
    pub name: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // The session cookie is a Rocket *private* cookie: it is encrypted and
        // authenticated with the app's secret key, so a client cannot forge or
        // tamper with it. We additionally check that the user still exists.
        let Some(name) = request
            .cookies()
            .get_private(SESSION_COOKIE)
            .map(|cookie| cookie.value().to_owned())
        else {
            return request::Outcome::Forward(Status::Unauthorized);
        };
        let Some(db) = request.rocket().state::<Db>() else {
            return request::Outcome::Forward(Status::InternalServerError);
        };
        match db::find_user(db, &name).await {
            Ok(user) => user
                .map(|row| User {
                    id: row.id,
                    name: row.username,
                })
                .or_forward(Status::Unauthorized),
            Err(e) => {
                tracing::error!(error = %e, "user lookup failed");
                request::Outcome::Error((Status::InternalServerError, ()))
            }
        }
    }
}

#[post("/login", data = "<login>")]
pub async fn login(
    db: &State<Db>,
    jar: &CookieJar<'_>,
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
        Box::new(Flash::error(
            Redirect::to(uri!(login_page)),
            "Something went wrong, please try again.",
        ))
    })?;
    let verified = match &user {
        Some(user) => {
            // Argon2 is deliberately slow; keep it off the async executor.
            let (password, hash) = (login.password.clone(), user.password_hash.clone());
            rocket::tokio::task::spawn_blocking(move || {
                crate::hashing::verify_password(&password, &hash)
            })
            .await
            .unwrap_or(false)
        }
        None => false,
    };
    if let (true, Some(user)) = (verified, user) {
        // SameSite=Strict stops browsers sending the session cookie on
        // cross-site requests, which is the CSRF protection for our POST
        // routes. HttpOnly keeps it away from page scripts.
        jar.add_private(
            Cookie::build((SESSION_COOKIE, user.username.clone()))
                .http_only(true)
                .same_site(SameSite::Strict),
        );
        // Debug-format user input so control characters can't forge log lines.
        tracing::info!(request_id = %request_id.0, username = ?user.username, "login succeeded");
        Ok(Redirect::to(uri!(crate::banking::user_banking)))
    } else {
        tracing::warn!(request_id = %request_id.0, username = ?login.username, "login failed");
        Err(invalid())
    }
}

#[get("/login")]
pub fn login_user(_user: User) -> Redirect {
    Redirect::to(uri!(login_page))
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

#[post("/logout")]
pub fn logout(jar: &CookieJar<'_>, request_id: RequestId) -> Flash<Redirect> {
    if let Some(cookie) = jar.get_private(SESSION_COOKIE) {
        tracing::info!(request_id = %request_id.0, username = ?cookie.value(), "logout");
    }
    jar.remove_private(Cookie::from(SESSION_COOKIE));
    Flash::success(Redirect::to(uri!(login_page)), "Successfully logged out.")
}

#[get("/")]
pub fn index() -> Redirect {
    Redirect::to(uri!(login_page))
}
