#![warn(clippy::all, clippy::pedantic)]

#[macro_use]
extern crate maplit;
#[macro_use]
extern crate rocket;
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
use storage::*;

use std::sync::Mutex;
use rocket::State;
use rocket_dyn_templates::Template;


#[get("/dump")]
fn dump(state: &State<Mutex<storage::Storage>>, user: login::User) -> String {
    if "admin" == user.name {
        format!("{:?}", state.lock().unwrap())
    } else {
        format!("{:?}", "Only admin can do this.")
    }
}

#[launch]
fn rocket() -> _ {
    let credentials = hashmap! {String::from("admin") =>
                                calculate_hash(&"admin").to_string()};
    //let history = vec![(Utc::now(), 999.99f64)]; // chrono
    let history = vec![];
    let transactions = hashmap! {String::from("admin") => history};
    let storage = Storage {
        credentials,
        transactions,
    };

    //use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    //let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);

    // Start WebSocket listener
    std::thread::spawn(move ||
                       ws::listen("0.0.0.0:8081", |out| move |msg| {
                           out.broadcast(msg) }).unwrap());
    // static_response_handler! {
    //     "/favicon.ico" => favicon => "/static/favicon.ico",
    // }

    // Ignite Rocket !!!
    rocket::build()
        .attach(Template::fairing())
        .mount(
            "/",
            routes![
                //favicon,
                login::index,
                user_banking,
                user_banking_login,
                login::login,
                login::logout,
                login::login_user,
                login::login_page,
                dump,
                account_info,
                withdraw,
                deposit
            ],
        )
        .manage(Mutex::new(storage))

}
