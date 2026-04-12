use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let test_cases = [serde_json::json!({}), serde_json::json!({ "token": 123 })];

    for test_case in test_cases.iter() {
        let response = app.post_verify_token(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_valid_token() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    let token = auth_cookie.value().to_owned();

    let response = app
        .post_verify_token(&serde_json::json!({ "token": token }))
        .await;
    assert_eq!(response.status().as_u16(), 200);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;

    let response = app
        .post_verify_token(&serde_json::json!({ "token": "invalid_token" }))
        .await;

    let status = response.status().as_u16();
    let error = response
        .json::<ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse")
        .error;

    app.clean_up().await;

    assert_eq!(status, 401);
    assert_eq!(error, "Invalid auth token".to_owned());
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    let token = auth_cookie.value().to_owned();

    // Logout to ban the token
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);

    // verify-token with the now-banned token should return 401
    let response = app
        .post_verify_token(&serde_json::json!({ "token": token }))
        .await;
    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}
