use std::collections::HashMap;

use rocket::http::{ContentType, Cookie, SameSite, Status};
use rocket::local::blocking::{Client, LocalResponse};
use rocket::serde::json::Value;

use crate::hashing::hash_password;
use crate::login::SESSION_COOKIE;
use crate::storage::Storage;

/// Storage with the given `(user, password)` accounts. Only users listed in
/// `with_history` get a transaction history entry.
fn storage(users: &[(&str, &str)], with_history: &[&str]) -> Storage {
    Storage {
        credentials: users
            .iter()
            .map(|(u, p)| ((*u).to_owned(), hash_password(p)))
            .collect(),
        transactions: with_history
            .iter()
            .map(|u| ((*u).to_owned(), Vec::new()))
            .collect::<HashMap<_, _>>(),
    }
}

fn client() -> Client {
    Client::tracked(super::build(super::demo_storage())).expect("valid rocket instance")
}

fn client_with(storage: Storage) -> Client {
    Client::tracked(super::build(storage)).expect("valid rocket instance")
}

fn login<'c>(client: &'c Client, user: &str, password: &str) -> LocalResponse<'c> {
    client
        .post("/login")
        .header(ContentType::Form)
        .body(format!("username={user}&password={password}"))
        .dispatch()
}

fn location(response: &LocalResponse<'_>) -> Option<String> {
    response.headers().get_one("Location").map(str::to_owned)
}

fn post_json(client: &Client, path: &str, body: &str) -> (Status, Value) {
    let response = client
        .post(path.to_owned())
        .header(ContentType::JSON)
        .body(body)
        .dispatch();
    let status = response.status();
    (status, response.into_json().expect("JSON response"))
}

fn balance(client: &Client) -> String {
    let info: Value = client
        .get("/json/account_info")
        .dispatch()
        .into_json()
        .expect("JSON account info");
    info["balance"].as_str().expect("balance string").to_owned()
}

#[test]
fn login_page_renders() {
    let client = client();
    let response = client.get("/login").dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::HTML));
    let body = response.into_string().unwrap();
    assert!(body.contains("Please Login"));
    assert!(body.contains(r#"name="username""#));
    assert!(body.contains(r#"name="password""#));
    assert!(!body.contains("class=\"flash"), "no flash without a message");
}

#[test]
fn root_and_banking_redirect_to_login_when_logged_out() {
    let client = client();
    for path in ["/", "/user_banking"] {
        let response = client.get(path).dispatch();
        assert_eq!(response.status(), Status::SeeOther, "{path}");
        assert_eq!(location(&response).as_deref(), Some("/login"), "{path}");
    }
}

#[test]
fn bad_login_is_rejected_with_flash() {
    let client = client();
    for (user, pass) in [("admin", "wrong"), ("nobody", "admin"), ("", "")] {
        let response = login(&client, user, pass);
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(location(&response).as_deref(), Some("/login"));
        assert!(response.cookies().get_private(SESSION_COOKIE).is_none());
        let page = client.get("/login").dispatch().into_string().unwrap();
        assert!(page.contains("Invalid username/password."), "{user}/{pass}");
    }
    assert_eq!(client.get("/json/account_info").dispatch().status(), Status::Unauthorized);
}

#[test]
fn good_login_works_and_logout_ends_session() {
    let client = client();
    let response = login(&client, "admin", "admin");
    assert_eq!(response.status(), Status::SeeOther);
    assert_eq!(location(&response).as_deref(), Some("/user_banking"));

    let cookie = response.cookies().get(SESSION_COOKIE).expect("session cookie");
    assert_ne!(cookie.value(), "admin", "session cookie must be encrypted");
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Strict));

    let page = client.get("/user_banking").dispatch();
    assert_eq!(page.status(), Status::Ok);
    assert!(page.into_string().unwrap().contains("Best Bank"));

    let info: Value = client.get("/json/account_info").dispatch().into_json().unwrap();
    assert_eq!(info["user_name"], "admin");
    assert_eq!(info["balance"], "0.00");

    // /dump works for admin.
    assert_eq!(client.get("/dump").dispatch().status(), Status::Ok);

    let response = client.post("/logout").dispatch();
    assert_eq!(response.status(), Status::SeeOther);
    let page = client.get("/login").dispatch().into_string().unwrap();
    assert!(page.contains("Successfully logged out."));
    assert_eq!(client.get("/json/account_info").dispatch().status(), Status::Unauthorized);
    assert_eq!(client.get("/dump").dispatch().status(), Status::Unauthorized);
}

#[test]
fn forged_plain_cookie_is_rejected() {
    let client = Client::untracked(super::build(super::demo_storage())).unwrap();
    let forged = || Cookie::new(SESSION_COOKIE, "admin");

    let response = client.get("/dump").cookie(forged()).dispatch();
    assert_eq!(response.status(), Status::Unauthorized);

    let response = client.get("/user_banking").cookie(forged()).dispatch();
    assert_eq!(response.status(), Status::SeeOther);
    assert_eq!(location(&response).as_deref(), Some("/login"));

    let response = client.get("/json/account_info").cookie(forged()).dispatch();
    assert_eq!(response.status(), Status::Unauthorized);

    let response = client
        .post("/json/deposit")
        .cookie(forged())
        .header(ContentType::JSON)
        .body(r#"{"amount": 100}"#)
        .dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
}

#[test]
fn dump_is_admin_only() {
    let client = client_with(storage(&[("admin", "admin"), ("alice", "pw")], &["admin", "alice"]));
    login(&client, "alice", "pw");
    assert_eq!(client.get("/dump").dispatch().status(), Status::Forbidden);
}

#[test]
fn deposit_validation() {
    let client = client();
    login(&client, "admin", "admin");
    for body in [
        r#"{"amount": 0}"#,
        r#"{"amount": -5}"#,
        r#"{"amount": -0.01}"#,
        r#"{"amount": 1.234}"#,
        r#"{"amount": 0.001}"#,
        r#"{"amount": 1000000.01}"#,
    ] {
        let (status, json) = post_json(&client, "/json/deposit", body);
        assert_eq!(status, Status::UnprocessableEntity, "{body}");
        assert_eq!(json["success"], false, "{body}");
        assert!(json["message"].is_string(), "{body}");
    }
    for body in [r#"{"amount": "abc"}"#, r#"{"amount": null}"#, "{}", "not json", ""] {
        let (status, json) = post_json(&client, "/json/deposit", body);
        assert_eq!(status, Status::BadRequest, "{body:?}");
        assert_eq!(json["success"], false, "{body:?}");
    }
    assert_eq!(balance(&client), "0.00");

    // Integer cents: 0.1 + 0.2 is exactly 0.30, not 0.30000000000000004.
    assert_eq!(post_json(&client, "/json/deposit", r#"{"amount": 0.1}"#).0, Status::Ok);
    assert_eq!(post_json(&client, "/json/deposit", r#"{"amount": 0.2}"#).0, Status::Ok);
    assert_eq!(balance(&client), "0.30");
}

#[test]
fn withdraw_validation_and_overdraft() {
    let client = client();
    login(&client, "admin", "admin");

    let (status, json) = post_json(&client, "/json/withdraw", r#"{"amount": 1}"#);
    assert_eq!(status, Status::UnprocessableEntity);
    assert_eq!(json["message"], "Insufficient funds available.");

    for body in [r#"{"amount": 0}"#, r#"{"amount": -5}"#] {
        let (status, json) = post_json(&client, "/json/withdraw", body);
        assert_eq!(status, Status::UnprocessableEntity, "{body}");
        assert_eq!(json["success"], false);
    }

    let (status, json) = post_json(&client, "/json/deposit", r#"{"amount": 10.10}"#);
    assert_eq!((status, json["success"].as_bool()), (Status::Ok, Some(true)));
    let (status, _) = post_json(&client, "/json/withdraw", r#"{"amount": 10.11}"#);
    assert_eq!(status, Status::UnprocessableEntity, "overdraft by one cent");
    let (status, json) = post_json(&client, "/json/withdraw", r#"{"amount": 10.10}"#);
    assert_eq!((status, json["success"].as_bool()), (Status::Ok, Some(true)));
    assert_eq!(balance(&client), "0.00");

    let info: Value = client.get("/json/account_info").dispatch().into_json().unwrap();
    let txs = info["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 2);
    assert_eq!(txs[0][1], "-10.10", "newest first");
    assert_eq!(txs[1][1], "10.10");
}

#[test]
fn user_without_history_does_not_panic() {
    // "bob" can log in but has no transaction history entry; this used to
    // panic on `.unwrap()` and poison the storage mutex.
    let client = client_with(storage(&[("admin", "admin"), ("bob", "pw")], &["admin"]));
    login(&client, "bob", "pw");
    assert_eq!(client.get("/user_banking").dispatch().status(), Status::Ok);
    assert_eq!(balance(&client), "0.00");
    let (status, _) = post_json(&client, "/json/withdraw", r#"{"amount": 1}"#);
    assert_eq!(status, Status::UnprocessableEntity);
    assert_eq!(post_json(&client, "/json/deposit", r#"{"amount": 5}"#).0, Status::Ok);
    assert_eq!(balance(&client), "5.00");
}

#[test]
fn valid_session_for_unknown_user_is_rejected_and_app_keeps_working() {
    let client = client();
    // A correctly encrypted cookie for a user that isn't in storage.
    let response = client
        .get("/json/account_info")
        .private_cookie(Cookie::new(SESSION_COOKIE, "ghost"))
        .dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    let response = client
        .get("/user_banking")
        .private_cookie(Cookie::new(SESSION_COOKIE, "ghost"))
        .dispatch();
    assert_eq!(response.status(), Status::SeeOther);

    // The app (and its storage mutex) is still healthy afterwards.
    login(&client, "admin", "admin");
    assert_eq!(balance(&client), "0.00");
}

#[test]
fn websocket_requires_login() {
    let client = Client::untracked(super::build(super::demo_storage())).unwrap();
    let response = client
        .get("/ws")
        .header(rocket::http::Header::new("Connection", "Upgrade"))
        .header(rocket::http::Header::new("Upgrade", "websocket"))
        .header(rocket::http::Header::new("Sec-WebSocket-Version", "13"))
        .header(rocket::http::Header::new("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="))
        .dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
}

#[test]
fn favicon_is_served() {
    let client = client();
    let response = client.get("/static/favicon.ico").dispatch();
    assert_eq!(response.status(), Status::Ok);
}
