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
        request
            .cookies()
            .get("user_name")
            .and_then(|cookie| cookie.value().parse().ok())
            .map(|name| User { name: name })
            .or_forward(Status::Ok)
    }
}

#[post("/login", data = "<login>")]
pub fn login(
    state: &State<Mutex<Storage>>,
    jar: &CookieJar<'_>,
    login: Form<Login>,
) -> Result<Redirect, Flash<Redirect>> {
    let storage = state.lock().unwrap();
    if storage.credentials.contains_key(&login.username)
        && *storage.credentials.get(&login.username).unwrap()
            == crate::hashing::calculate_hash(&login.password).to_string()
    {
        jar.add(Cookie::new("user_name", login.username.to_owned()));
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
pub fn login_page(flash: Option<FlashMessage>) -> Template {
    let mut context: HashMap<String, String> = HashMap::new();

    // if let Some(ref msg) = flash {
    //     context.insert("flash", msg.msg());
    // }

    Template::render("login", &context)
}

#[post("/logout")]
pub fn logout(jar: &CookieJar<'_>) -> Flash<Redirect> {
    jar.remove(Cookie::named("user_name"));
    Flash::success(Redirect::to(uri!(login_page)), "Successfully logged out.")
}

#[get("/")]
pub fn index() -> Redirect {
    Redirect::to(uri!(login_page))
}
