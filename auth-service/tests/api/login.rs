use crate::helpers::{get_random_email, TestApp};
use auth_service::routes::TwoFactorAuthResponse;
use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use reqwest::Response;

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new().await;
    let random_email = get_random_email();

    let test_cases = [
        // missing email
        serde_json::json!({
            "password": "password123"
        }),
        // email wrong type
        serde_json::json!({
            "email": 123,
            "password": "password123"
        }),
        // missing password
        serde_json::json!({
            "email": random_email
        }),
        // password wrong type
        serde_json::json!({
            "email": random_email,
            "password": true
        }),
        // empty body
        serde_json::json!({}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
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
async fn should_return_400_if_invalid_input() {
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message.
    let no_at_symbol_request = serde_json::json!({
        "email": "testtest.com",
        "password": "password123"
    });

    let empty_email_request = serde_json::json!({
        "email": "",
        "password": "password123"
    });

    let short_password_request = serde_json::json!({
        "email": "test@test.com",
        "password": "short"
    });

    let invalid_inputs = [
        no_at_symbol_request,
        empty_email_request,
        short_password_request,
    ];

    let mut app = TestApp::new().await;

    for input in invalid_inputs.iter() {
        let response = app.post_login(input).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            input
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.
    let mut app = TestApp::new().await;

    let credentials = serde_json::json!({
        "email": get_random_email(),
        "password": "password123"
    });

    let response = app.post_login(&credentials).await;
    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid credentials".to_owned()
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
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
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response: Response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    assert_eq!(
        response
            .json::<TwoFactorAuthResponse>()
            .await
            .expect("Could not deserialize response body to TwoFactorAuthResponse")
            .message,
        "2FA required".to_owned()
    );

    app.clean_up().await;
}
