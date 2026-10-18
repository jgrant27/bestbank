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
use rocket_dyn_templates::{Template, context};

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
    Ok(Template::render(
        "banking",
        context! {
            csrf_token: csrf.0,
            balance: format_cents(balance),
            user_name: user.name,
        },
    ))
}

#[get("/json/account_info")]
pub async fn account_info(db: &State<Db>, user: User) -> Result<Value, Status> {
    let balance = db::balance(db, user.id).await.map_err(|e| db_error(&e))?;
    let transactions = db::transactions(db, user.id)
        .await
        .map_err(|e| db_error(&e))?;
    let transactions_json: Vec<Value> = transactions
        .iter()
        .map(|tx| {
            json!({
                "time": tx.timestamp().to_rfc2822(),
                "amount": format_cents(tx.amount_cents),
                "kind": tx.kind,
                "counterparty": tx.counterparty,
            })
        })
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

/// Request body for transfers: recipient username and decimal amount.
#[derive(serde::Deserialize)]
pub struct TransferPayload {
    to: String,
    amount: f64,
}

#[post("/json/transfer", data = "<payload>")]
pub async fn transfer(
    payload: Result<Json<TransferPayload>, json::Error<'_>>,
    db: &State<Db>,
    events: &State<Events>,
    user: User,
    csrf: Result<CsrfHeader, CsrfError>,
    request_id: RequestId,
) -> ApiResponse {
    if let Err(e) = csrf {
        return csrf_failure(&e);
    }
    let Ok(payload) = payload else {
        return failure(
            Status::BadRequest,
            "Request body must be JSON like {\"to\": \"bob\", \"amount\": 12.34}.",
        );
    };
    let cents = match parse_amount(payload.amount) {
        Ok(cents) => cents,
        Err(msg) => return failure(Status::UnprocessableEntity, msg),
    };
    let to_name = payload.to.trim();
    if to_name.is_empty() {
        return failure(Status::UnprocessableEntity, "Choose who to send money to.");
    }
    let recipient = match db::find_user(db, to_name).await {
        Ok(Some(recipient)) => recipient,
        Ok(None) => return failure(Status::UnprocessableEntity, "No such recipient."),
        Err(e) => return server_error(&e),
    };
    if recipient.id == user.id {
        return failure(
            Status::UnprocessableEntity,
            "You can't transfer money to yourself.",
        );
    }
    match db::transfer(db, user.id, recipient.id, cents).await {
        Ok(Ok(())) => {}
        Ok(Err(db::TransferError::InsufficientFunds)) => {
            return failure(Status::UnprocessableEntity, "Insufficient funds available.");
        }
        Ok(Err(db::TransferError::RecipientLimit)) => {
            return failure(
                Status::UnprocessableEntity,
                "The recipient can't receive that amount.",
            );
        }
        Err(e) => return server_error(&e),
    }
    let amount = format_cents(cents);
    tracing::info!(
        request_id = %request_id.0,
        from = ?user.name,
        to = ?recipient.username,
        cents,
        kind = "transfer",
        "transaction"
    );
    events.publish(
        &user.name,
        format!("Sent 💵{amount} to {}", recipient.username),
    );
    events.publish(
        &recipient.username,
        format!("Received 💵{amount} from {}", user.name),
    );
    (Status::Ok, json!({ "success": true }))
}
