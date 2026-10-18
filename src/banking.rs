use std::collections::HashMap;

use crate::csrf::{CsrfError, CsrfHeader, CsrfToken};
use crate::db::{self, Db};
use crate::events::Events;
use crate::login::User;
use crate::money::{Cents, format_cents, parse_amount};
use crate::telemetry::RequestId;

use rocket::State;
use rocket::http::Status;
use rocket::response::Redirect;
use rocket::serde::json::{self, Json, Value, json};
use rocket_dyn_templates::Template;

/// Log a database error and turn it into a 500.
pub fn db_error(e: &sqlx::Error) -> Status {
    tracing::error!(error = %e, "database error");
    Status::InternalServerError
}

#[get("/user_banking", rank = 1)]
pub fn user_banking_login() -> Redirect {
    Redirect::to(uri!(crate::login::login_page))
}

#[get("/user_banking")]
pub async fn user_banking(db: &State<Db>, user: User, csrf: CsrfToken) -> Result<Template, Status> {
    let balance = db::balance(db, user.id).await.map_err(|e| db_error(&e))?;
    let mut context = HashMap::new();
    context.insert("csrf_token", csrf.0);
    context.insert("balance", format_cents(balance));
    context.insert("user_name", user.name);
    Ok(Template::render("banking", &context))
}

#[get("/json/account_info")]
pub async fn account_info(db: &State<Db>, user: User) -> Result<Value, Status> {
    let balance = db::balance(db, user.id).await.map_err(|e| db_error(&e))?;
    let transactions = db::transactions(db, user.id)
        .await
        .map_err(|e| db_error(&e))?;
    let transactions_json: Vec<(String, String)> = transactions
        .iter()
        .map(|tx| (tx.timestamp().to_rfc2822(), format_cents(tx.amount_cents)))
        .collect();
    Ok(json!({
        "user_name": user.name,
        "balance": format_cents(balance),
        "transactions": transactions_json
    }))
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

fn csrf_failure(error: &CsrfError) -> ApiResponse {
    let message = match error {
        CsrfError::CrossOrigin => "Cross-origin requests are not allowed.",
        CsrfError::BadToken => "Missing or invalid CSRF token. Reload the page and try again.",
    };
    failure(Status::Forbidden, message)
}

fn server_error(e: &sqlx::Error) -> ApiResponse {
    failure(db_error(e), "Something went wrong, please try again.")
}

fn validate(payload: Result<Json<Payload>, json::Error<'_>>) -> Result<Cents, ApiResponse> {
    let payload = payload.map_err(|_| {
        failure(
            Status::BadRequest,
            "Request body must be JSON like {\"amount\": 12.34}.",
        )
    })?;
    parse_amount(payload.amount).map_err(|msg| failure(Status::UnprocessableEntity, msg))
}

#[post("/json/withdraw", data = "<payload>")]
pub async fn withdraw(
    payload: Result<Json<Payload>, json::Error<'_>>,
    db: &State<Db>,
    events: &State<Events>,
    user: User,
    csrf: Result<CsrfHeader, CsrfError>,
    request_id: RequestId,
) -> ApiResponse {
    if let Err(e) = csrf {
        return csrf_failure(&e);
    }
    let cents = match validate(payload) {
        Ok(cents) => cents,
        Err(resp) => return resp,
    };
    match db::withdraw(db, user.id, cents).await {
        Ok(true) => {}
        Ok(false) => return failure(Status::UnprocessableEntity, "Insufficient funds available."),
        Err(e) => return server_error(&e),
    }
    tracing::info!(request_id = %request_id.0, username = ?user.name, cents, kind = "withdrawal", "transaction");
    events.publish(
        &user.name,
        format!("Successful withdrawal for 💵{}", format_cents(cents)),
    );
    (Status::Ok, json!({ "success": true }))
}

#[post("/json/deposit", data = "<payload>")]
pub async fn deposit(
    payload: Result<Json<Payload>, json::Error<'_>>,
    db: &State<Db>,
    events: &State<Events>,
    user: User,
    csrf: Result<CsrfHeader, CsrfError>,
    request_id: RequestId,
) -> ApiResponse {
    if let Err(e) = csrf {
        return csrf_failure(&e);
    }
    let cents = match validate(payload) {
        Ok(cents) => cents,
        Err(resp) => return resp,
    };
    match db::deposit(db, user.id, cents).await {
        Ok(true) => {}
        Ok(false) => return failure(Status::UnprocessableEntity, "Balance limit exceeded."),
        Err(e) => return server_error(&e),
    }
    tracing::info!(request_id = %request_id.0, username = ?user.name, cents, kind = "deposit", "transaction");
    events.publish(
        &user.name,
        format!("Successful deposit for 💵{}", format_cents(cents)),
    );
    (Status::Ok, json!({ "success": true }))
}
