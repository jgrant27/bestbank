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
use chrono::prelude::*;
use rocket::State;
//use rocket::response::content;
use rocket_contrib::templates::Template;
use rocket_contrib::serve::StaticFiles;


#[get("/dump")]
fn dump(state: State<Mutex<storage::Storage>>) -> String {
    dbg!(calculate_hash(&"admin").to_string());
    format!("{:?}", state.lock().unwrap())
}

fn rocket() -> rocket::Rocket {
    let credentials = hashmap!{String::from("admin") =>
                               calculate_hash(&"admin").to_string()};
    let history = vec![(Utc::now(), 999.99f64)];
    let transactions = hashmap!{String::from("admin") => history};
    let storage = Storage {credentials, transactions};
    rocket::ignite()
        .attach(Template::fairing())
        .mount("/", StaticFiles::from("static"))
        .mount("/", routes![index, user_index,
                            login, logout, login_user, login_page,
                            dump, account_info, withdraw, deposit])
        .manage(Mutex::new(storage))
}

fn main() {
    rocket().launch();
}
