use std::collections::HashMap;

use crate::events::Events;
use crate::login::User;
use crate::money::{Cents, format_cents, parse_amount};
use crate::storage::{self, SharedStorage};

use rocket::State;
use rocket::http::Status;
use rocket::response::Redirect;
use rocket::serde::json::{self, Json, Value, json};
use rocket_dyn_templates::Template;

use chrono::prelude::*;

fn balance_of(transactions: &[(DateTime<Utc>, Cents)]) -> Cents {
    transactions.iter().map(|(_, amount)| amount).sum()
}

#[get("/user_banking", rank = 1)]
pub fn user_banking_login() -> Redirect {
    Redirect::to(uri!(crate::login::login_page))
}

#[get("/user_banking")]
pub fn user_banking(state: &State<SharedStorage>, user: User) -> Template {
    let storage = storage::lock(state);
    let transactions = storage.transactions.get(&user.name).map_or(&[][..], Vec::as_slice);
    let mut context = HashMap::new();
    context.insert("balance", format_cents(balance_of(transactions)));
    context.insert("user_name", user.name);
    Template::render("banking", &context)
}

#[get("/json/account_info")]
pub fn account_info(state: &State<SharedStorage>, user: User) -> Value {
    let storage = storage::lock(state);
    let transactions = storage.transactions.get(&user.name).map_or(&[][..], Vec::as_slice);
    let transactions_json: Vec<(String, String)> = transactions
        .iter()
        .rev()
        .map(|(datetime, amount)| (datetime.to_rfc2822(), format_cents(*amount)))
        .collect();
    json!({
        "user_name": user.name,
        "balance": format_cents(balance_of(transactions)),
        "transactions": transactions_json
    })
}

/// Request body for deposits and withdrawals. `amount` is a decimal number
/// of dollars (e.g. `12.34`) and is converted to integer cents.
#[derive(serde::Deserialize)]
pub struct Payload {
    amount: f64,
}

type ApiResponse = (Status, Value);

fn failure(status: Status, message: &str) -> ApiResponse {
    (status, json!({ "success": false, "message": message }))
}

fn validate(payload: Result<Json<Payload>, json::Error<'_>>) -> Result<Cents, ApiResponse> {
    let payload = payload.map_err(|_| {
        failure(Status::BadRequest, "Request body must be JSON like {\"amount\": 12.34}.")
    })?;
    parse_amount(payload.amount).map_err(|msg| failure(Status::UnprocessableEntity, msg))
}

#[post("/json/withdraw", data = "<payload>")]
pub fn withdraw(
    payload: Result<Json<Payload>, json::Error<'_>>,
    state: &State<SharedStorage>,
    events: &State<Events>,
    user: User,
) -> ApiResponse {
    let cents = match validate(payload) {
        Ok(cents) => cents,
        Err(resp) => return resp,
    };
    let user_name = user.name;
    let mut storage = storage::lock(state);
    let transactions = storage.transactions.entry(user_name.clone()).or_default();
    if balance_of(transactions) < cents {
        return failure(Status::UnprocessableEntity, "Insufficient funds available.");
    }
    transactions.push((Utc::now(), -cents));
    drop(storage);
    events.publish(&user_name, format!("Successful withdrawal for 💵{}", format_cents(cents)));
    (Status::Ok, json!({ "success": true }))
}

#[post("/json/deposit", data = "<payload>")]
pub fn deposit(
    payload: Result<Json<Payload>, json::Error<'_>>,
    state: &State<SharedStorage>,
    events: &State<Events>,
    user: User,
) -> ApiResponse {
    let cents = match validate(payload) {
        Ok(cents) => cents,
        Err(resp) => return resp,
    };
    let user_name = user.name;
    let mut storage = storage::lock(state);
    let transactions = storage.transactions.entry(user_name.clone()).or_default();
    if balance_of(transactions).checked_add(cents).is_none() {
        return failure(Status::UnprocessableEntity, "Balance limit exceeded.");
    }
    transactions.push((Utc::now(), cents));
    drop(storage);
    events.publish(&user_name, format!("Successful deposit for 💵{}", format_cents(cents)));
    (Status::Ok, json!({ "success": true }))
}
