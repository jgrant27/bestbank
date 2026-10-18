#![warn(clippy::all, clippy::pedantic)]
// Rocket request guards (e.g. `User`, `Form<T>`) are taken by value by design.
#![allow(clippy::needless_pass_by_value)]

#[macro_use]
extern crate rocket;

#[cfg(test)]
mod tests;

mod banking;
mod events;
mod hashing;
mod login;
mod money;
mod storage;
mod telemetry;

use std::collections::HashMap;
use std::sync::Mutex;

use rocket::fs::{FileServer, relative};
use rocket::http::Status;
use rocket::{Build, Rocket, State};
use rocket_dyn_templates::Template;

use storage::{SharedStorage, Storage};

/// Debug dump of all storage. Admin only.
#[get("/dump")]
fn dump(state: &State<SharedStorage>, user: login::User) -> Result<String, Status> {
    if user.name == "admin" {
        Ok(format!("{:?}", *storage::lock(state)))
    } else {
        Err(Status::Forbidden)
    }
}

/// Seed the in-memory store with the demo `admin`/`admin` account.
fn demo_storage() -> Storage {
    Storage {
        credentials: HashMap::from([(String::from("admin"), hashing::hash_password("admin"))]),
        transactions: HashMap::from([(String::from("admin"), Vec::new())]),
    }
}

/// Build the Rocket instance around the given storage.
fn build(storage: Storage) -> Rocket<Build> {
    rocket::build()
        .attach(telemetry::RequestLogger)
        .attach(Template::fairing())
        .mount(
            "/",
            routes![
                login::index,
                login::login,
                login::logout,
                login::login_user,
                login::login_page,
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
        // mask the 401s from guarded routes.
        .mount("/static", FileServer::from(relative!("static")))
        .manage(Mutex::new(storage))
        .manage(events::Events::default())
}

#[launch]
fn rocket() -> _ {
    telemetry::init();
    build(demo_storage())
}
