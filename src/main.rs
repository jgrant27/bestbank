#![warn(clippy::all, clippy::pedantic)]

#[macro_use]
extern crate maplit;
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate serde_derive;

#[cfg(test)]
mod tests;

mod banking;
mod hashing;
mod login;
mod storage;
use banking::*;
use hashing::*;
use login::*;
use storage::*;

use std::sync::Mutex;
//use chrono::prelude::*;
use rocket::State;
//use rocket::response::content;
use rocket_contrib::serve::StaticFiles;
use rocket_contrib::templates::Template;

#[get("/dump")]
fn dump(state: State<Mutex<storage::Storage>>, user: User) -> String {
    if "admin" == user.name {
        format!("{:?}", state.lock().unwrap())
    } else {
        format!("{:?}", "Only admin can do this.")
    }
}

#[launch]
fn rocket() -> rocket::Rocket {
    let credentials = hashmap! {String::from("admin") =>
    calculate_hash(&"admin").to_string()};
    //let history = vec![(Utc::now(), 999.99f64)]; // chrono
    let history = vec![];
    let transactions = hashmap! {String::from("admin") => history};
    let storage = Storage {
        credentials,
        transactions,
    };

    // Start WebSocket listener
    use std::thread;
    use ws::listen;
    thread::spawn(move || listen("0.0.0.0:8081", |out| move |msg| out.broadcast(msg)).unwrap());

    // Ignite Rocket !!!
    rocket::ignite()
        .attach(Template::fairing())
        .mount("/", StaticFiles::from("static"))
        .mount(
            "/",
            routes![
                index,
                user_banking,
                user_banking_login,
                login,
                logout,
                login_user,
                login_page,
                dump,
                account_info,
                withdraw,
                deposit
            ],
        )
        .manage(Mutex::new(storage))
}
