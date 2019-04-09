#![warn(clippy::all, clippy::pedantic)]
#![feature(proc_macro_hygiene, decl_macro, never_type)]

#[macro_use] extern crate maplit;
#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_contrib;
#[macro_use] extern crate serde_derive;

#[cfg(test)] mod tests;

mod hashing;
mod storage;
mod login;
mod banking;
use hashing::*;
use storage::*;
use login::*;
use banking::*;

use std::sync::Mutex;
//use chrono::prelude::*;
use rocket::State;
//use rocket::response::content;
use rocket_contrib::templates::Template;
use rocket_contrib::serve::StaticFiles;


#[get("/dump")]
fn dump(state: State<Mutex<storage::Storage>>, user: User) -> String {
    if "admin" == user.name {
        format!("{:?}", state.lock().unwrap())
    } else {
        format!("{:?}", "Only admin can do this.")
    }
}

fn rocket() -> rocket::Rocket {
    let credentials = hashmap!{String::from("admin") =>
                               calculate_hash(&"admin").to_string()};
    //let history = vec![(Utc::now(), 999.99f64)]; // chrono
    let history = vec![];
    let transactions = hashmap!{String::from("admin") => history};
    let storage = Storage {credentials, transactions};
    rocket::ignite()
        .attach(Template::fairing())
        .mount("/", StaticFiles::from("static"))
        .mount("/", routes![index,
                            user_banking, user_banking_login,
                            login, logout, login_user, login_page,
                            dump, account_info, withdraw, deposit])
        .manage(Mutex::new(storage))
}

fn main() {
    // Start WebSocket listener
    use ws::listen;
    use std::thread;
    thread::spawn(move || {
        listen("0.0.0.0:8081", |out| {
            move |msg| {
                out.broadcast(msg)
            }
        }).unwrap()
    });

    // Start rocket
    rocket().launch();
}
