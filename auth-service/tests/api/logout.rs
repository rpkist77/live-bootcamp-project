use auth_service::utils::constants::JWT_COOKIE_NAME;
use reqwest::Url;

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let mut app = TestApp::new().await;

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 400);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let mut app = TestApp::new().await;

    // First, sign up a new user to get a valid JWT cookie
    let random_email = crate::helpers::get_random_email();
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let login_response = app.post_login(&login_body).await;
    assert_eq!(
        login_response.status().as_u16(),
        200,
        "Login failed with valid credentials"
    );

    let auth_cookie = login_response
        .cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    let token = auth_cookie.value().to_owned();

    // Now, call the logout route with the valid JWT cookie
    let logout_response = app.post_logout().await;
    assert_eq!(logout_response.status().as_u16(), 200);

    // Verify the token was added to the banned token store
    let is_banned = app
        .banned_token_store
        .read()
        .await
        .contains_token(&token)
        .await
        .unwrap();
    assert!(
        is_banned,
        "Token should be in the banned store after logout"
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let mut app = TestApp::new().await;

    // First, sign up a new user to get a valid JWT cookie
    let random_email = crate::helpers::get_random_email();
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let login_response = app.post_login(&login_body).await;
    assert_eq!(
        login_response.status().as_u16(),
        200,
        "Login failed with valid credentials"
    );

    // Call the logout route for the first time (should succeed)
    let first_logout_response = app.post_logout().await;
    assert_eq!(first_logout_response.status().as_u16(), 200);

    // Call the logout route again immediately (should fail with 400)
    let second_logout_response = app.post_logout().await;
    assert_eq!(second_logout_response.status().as_u16(), 400);

    app.clean_up().await;
}
