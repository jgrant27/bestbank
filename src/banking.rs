use std::collections::HashMap;
use std::sync::Mutex;

use crate::storage::Storage;
use crate::login::User;

use rocket::State;
use rocket_contrib::templates::Template;
use rocket_contrib::json::{Json, JsonValue};

use chrono::prelude::*;


#[get("/")]
pub fn user_index(state: State<Mutex<Storage>>, user: User) -> Template {
    let storage = state.lock().unwrap();
    let transactions = storage.transactions.get(&user.name).unwrap();
    let balance = transactions.iter().fold(0.0, |sum, (_, amount)| sum + *amount);
    let mut context = HashMap::new();
    context.insert("user_name", user.name);
    context.insert("balance", format!("{:.*}", 2, balance));
    context.insert("transactions", format!("{:?}", transactions));
    Template::render("index", &context)
}

#[get("/json/account_info")]
pub fn account_info(state: State<Mutex<Storage>>, user: User) -> JsonValue {
    let storage = state.lock().unwrap();
    let transactions = storage.transactions.get(&user.name).unwrap();
    let mut transactions_json: Vec<(String, &f64)> = transactions.iter().map(|(datetime, amount)| {
        (datetime.to_rfc2822(), amount)
    }).collect();
    transactions_json.reverse();
    let balance = transactions.iter().fold(0.0, |sum, (_, amount)| sum + *amount);
    json!({
        "user_name": user.name,
        "balance": format!("{:.*}", 2, balance),
        "transactions":  transactions_json
    })
}

#[derive(Deserialize)]
pub struct Payload {
    amount: f64,
}

#[post("/json/withdraw", data = "<payload>")]
pub fn withdraw(payload: Json<Payload>,
                state: State<Mutex<Storage>>, user: User) -> JsonValue {
    let mut storage = state.lock().unwrap();
    let transactions = storage.transactions.get_mut(&user.name).unwrap();
    let balance = transactions.iter().fold(0.0, |sum, (_, amount)| sum + *amount);
    if balance > payload.amount {
        if payload.amount <= 0.0 {
            json!({ "success": false,
                     "message": "Withdrawal amount must be greater than 💵0." })
        } else {
            transactions.push((Utc::now(), -payload.amount));
            json!({ "success": true })
        }
    } else {
        json!({ "success": false,
                 "message": "Insufficient funds available." })
    }

}

#[post("/json/deposit", data = "<payload>")]
pub fn deposit(payload: Json<Payload>,
                state: State<Mutex<Storage>>, user: User) -> JsonValue {
    let mut storage = state.lock().unwrap();
    let transactions = storage.transactions.get_mut(&user.name).unwrap();
    if payload.amount > 0.0 {
        transactions.push((Utc::now(), payload.amount));
        json!({ "success": true })
    } else {
        json!({ "success": false,
                 "message": "Deposit amount must be greater than 💵0." })
    }
}
