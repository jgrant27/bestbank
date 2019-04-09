use super::rocket;
use self::rocket::local::Client;
use self::rocket::http::{Status, ContentType, Cookie};

#[test]
fn login_page() {
    let client = Client::new(super::rocket()).expect("valid rocket instance");
    //let response = client.post("/login").dispatch();
    // let response = client.post("/login")
    //     .body("username=admin&password=5755620910692865178")
    //     .header(ContentType::Form).dispatch();
    // let response = client
    //     .get("/dump")
    //     .cookie(Cookie::build("user_name", "admin").secure(true).finish())
    //     .dispatch();
    let mut response = client.get("/login").dispatch();
    assert_eq!(response.status(), Status::Ok);
    let content = response.body_string().unwrap();
    assert_eq!(content.len(), 704);
    assert_eq!(content.contains("Please Login"), true);
}
