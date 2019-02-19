use std::collections::HashMap;
use std::sync::Mutex;

use rocket::outcome::IntoOutcome;
use rocket::request::{self, Form, FlashMessage, FromRequest, Request};
use rocket::response::{Redirect, Flash};
use rocket::http::{Cookie, Cookies};
use rocket::State;

use rocket_contrib::templates::Template;

extern crate rocket_contrib;

use crate::storage::Storage;
use crate::hashing::*;


#[derive(FromForm)]
pub struct Login {
    pub username: String,
    pub password: String
}

#[derive(Debug)]
pub struct User{
    pub name: String
}

impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = !;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<User, !> {
        request.cookies()
            .get_private("user_name")
            .and_then(|cookie| cookie.value().parse().ok())
            .map(|name| User {name: name})
            .or_forward(())
    }
}

#[post("/login", data = "<login>")]
pub fn login(state: State<Mutex<Storage>>,
         mut cookies: Cookies, login: Form<Login>) -> Result<Redirect, Flash<Redirect>> {
    let storage = state.lock().unwrap();
    if storage.credentials.contains_key(&login.username) &&
        *storage.credentials.get(&login.username).unwrap() ==
        calculate_hash(&login.password).to_string() {
            cookies.add_private(Cookie::new("user_name", login.username.to_owned()));
            Ok(Redirect::to(uri!(index)))
        } else {
            Err(Flash::error(Redirect::to(uri!(login_page)), "Invalid username/password."))
        }
}

#[post("/logout")]
pub fn logout(mut cookies: Cookies) -> Flash<Redirect> {
    cookies.remove_private(Cookie::named("user_name"));
    Flash::success(Redirect::to(uri!(login_page)), "Successfully logged out.")
}

#[get("/login")]
pub fn login_user(_user: User) -> Redirect {
    Redirect::to(uri!(index))
}

#[get("/login", rank = 2)]
pub fn login_page(flash: Option<FlashMessage>) -> Template {
    let mut context = HashMap::new();
    if let Some(ref msg) = flash {
        context.insert("flash", msg.msg());
    }

    Template::render("login", &context)
}

#[get("/", rank = 2)]
pub fn index() -> Redirect {
    Redirect::to(uri!(login_page))
}
