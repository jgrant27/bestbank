#![warn(clippy::all, clippy::pedantic)]
// Rocket request guards (e.g. `User`, `Form<T>`) are taken by value by design.
#![allow(clippy::needless_pass_by_value)]

#[macro_use]
extern crate rocket;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_ws;

mod banking;
mod db;
mod events;
mod hashing;
mod login;
mod money;
mod register;
mod sessions;
mod telemetry;

use rocket::figment::Figment;
use rocket::fs::FileServer;
use rocket::http::Status;
use rocket::serde::json::{Value, json};
use rocket::{Build, Rocket, State};
use rocket_dyn_templates::Template;

use db::Db;

/// Debug dump of users and balances. Admin only. (Password hashes are not
/// included.)
#[get("/dump")]
async fn dump(db: &State<Db>, user: login::User) -> Result<Value, Status> {
    if user.name != "admin" {
        return Err(Status::Forbidden);
    }
    let mut users = Vec::new();
    for (id, username) in db::list_users(db)
        .await
        .map_err(|e| banking::db_error(&e))?
    {
        let balance = db::balance(db, id)
            .await
            .map_err(|e| banking::db_error(&e))?;
        let transactions = db::transactions(db, id)
            .await
            .map_err(|e| banking::db_error(&e))?;
        users.push(json!({
            "username": username,
            "balance": money::format_cents(balance),
            "transactions": transactions.len(),
        }));
    }
    Ok(json!({ "users": users }))
}

/// Build the Rocket instance from a configuration figment (so tests can
/// point `database_url` at a throwaway database).
fn build(figment: Figment) -> Rocket<Build> {
    rocket::custom(figment)
        .attach(telemetry::RequestLogger)
        .attach(Template::fairing())
        .attach(db::stage())
        .mount(
            "/",
            routes![
                login::index,
                login::login,
                login::logout,
                login::logout_all,
                login::logout_all_anonymous,
                login::login_user,
                login::login_page,
                register::register_page,
                register::register_logged_in,
                register::register,
                banking::user_banking,
                banking::user_banking_login,
                banking::account_info,
                banking::withdraw,
                banking::deposit,
                events::ws,
                dump,
            ],
        )
        // Static assets (favicon). Mounted under /static so its 404s don't
        // mask the 401s from guarded routes. Path is relative to the working
        // directory (like `templates/`).
        .mount("/static", FileServer::from("static"))
        .manage(events::Events::default())
}

#[launch]
fn rocket() -> _ {
    telemetry::init();
    build(rocket::Config::figment())
}
