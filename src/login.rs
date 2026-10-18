use std::collections::HashMap;
use std::sync::Mutex;

use rocket::http::{Cookie, CookieJar, Status};
use rocket::outcome::IntoOutcome;
use rocket::request::{self, FlashMessage, FromRequest, Request};
use rocket::response::{Flash, Redirect};
use rocket::State;
use rocket::form::Form;

use rocket_dyn_templates::Template;


use crate::storage::Storage;

/// Name of the (private, encrypted) session cookie.
pub const SESSION_COOKIE: &str = "user_name";

#[derive(FromForm)]
pub struct Login {
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
pub struct User {
    pub name: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // The session cookie is a Rocket *private* cookie: it is encrypted and
        // authenticated with the app's secret key, so a client cannot forge or
        // tamper with it. We additionally check that the user still exists.
        let name = request
            .cookies()
            .get_private(SESSION_COOKIE)
            .map(|cookie| cookie.value().to_owned());
        let exists = match (&name, request.rocket().state::<Mutex<Storage>>()) {
            (Some(name), Some(state)) => crate::storage::lock(state).credentials.contains_key(name),
            _ => false,
        };
        name.filter(|_| exists)
            .map(|name| User { name })
            .or_forward(Status::Unauthorized)
    }
}

#[post("/login", data = "<login>")]
pub fn login(
    state: &State<Mutex<Storage>>,
    jar: &CookieJar<'_>,
    login: Form<Login>,
) -> Result<Redirect, Flash<Redirect>> {
    // Copy the stored hash out so the (deliberately slow) Argon2 check
    // runs without holding the storage lock.
    let stored_hash = crate::storage::lock(state)
        .credentials
        .get(&login.username)
        .cloned();
    if stored_hash.is_some_and(|hash| crate::hashing::verify_password(&login.password, &hash)) {
        jar.add_private(Cookie::new(SESSION_COOKIE, login.username.clone()));
        Ok(Redirect::to(uri!(crate::banking::user_banking)))
    } else {
        Err(Flash::error(
            Redirect::to(uri!(login_page)),
            "Invalid username/password.",
        ))
    }
}

#[get("/login")]
pub fn login_user(_user: User) -> Redirect {
    Redirect::to(uri!(login_page))
}

#[get("/login", rank = 1)]
pub fn login_page(_flash: Option<FlashMessage>) -> Template {
    let context: HashMap<String, String> = HashMap::new();

    // if let Some(ref msg) = flash {
    //     context.insert("flash", msg.msg());
    // }

    Template::render("login", &context)
}

#[post("/logout")]
pub fn logout(jar: &CookieJar<'_>) -> Flash<Redirect> {
    jar.remove_private(Cookie::from(SESSION_COOKIE));
    Flash::success(Redirect::to(uri!(login_page)), "Successfully logged out.")
}

#[get("/")]
pub fn index() -> Redirect {
    Redirect::to(uri!(login_page))
}
