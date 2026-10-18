//! The Rocket application: routes, fairings, catchers and managed state.

use rocket::figment::Figment;
use rocket::fs::FileServer;
use rocket::http::Status;
use rocket::serde::json::{Value, json};
use rocket::{Build, Rocket, State};
use rocket_dyn_templates::Template;

use crate::{banking, csrf, events, headers, health, login, money, ratelimit, register, telemetry};

use crate::db::{self, Db};

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

/// The template fairing: minijinja 2 with autoescaping (on for `.html.j2`)
/// and "semi-strict" undefined handling, so printing a variable the handler
/// didn't provide is a render error (a 500, caught by tests) instead of
/// silently rendering nothing. `{% if missing %}` is still allowed.
fn templates() -> impl rocket::fairing::Fairing {
    Template::custom(|engines| {
        engines
            .minijinja
            .set_undefined_behavior(minijinja::UndefinedBehavior::SemiStrict);
    })
}

/// Build the Rocket instance from a configuration figment (so tests can
/// point `database_url` at a throwaway database).
pub fn build(figment: Figment) -> Rocket<Build> {
    rocket::custom(figment)
        .attach(telemetry::RequestLogger)
        .attach(headers::shield())
        .attach(headers::SecurityHeaders)
        .attach(templates())
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
                banking::transfer,
                events::ws,
                csrf::token,
                health::healthz,
                dump,
            ],
        )
        // Static assets (favicon, CSS, JS). Mounted under /static so its 404s don't
        // mask the 401s from guarded routes. Path is relative to the working
        // directory (like `templates/`).
        .mount("/static", FileServer::from("static"))
        .register("/", catchers![ratelimit::too_many_requests])
        .manage(events::Events::default())
}
