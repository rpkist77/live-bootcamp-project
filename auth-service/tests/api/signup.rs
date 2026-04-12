use crate::helpers::{get_random_email, TestApp};
use auth_service::services::mock_email_client::MockEmailClient;
use auth_service::{
    app_state::{AppState, BannedTokenStoreType},
    routes::{signup, SignupRequest, SignupResponse},
    services::data_stores::{HashmapTwoFACodeStore, HashmapUserStore, HashsetBannedTokenStore},
    ErrorResponse,
};
use axum::{body::to_bytes, extract::State, response::IntoResponse, Json};
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email(); // Call helper method to generate email

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": 321,
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": "Y"
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "passwordonly",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await; // call `post_signup`
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let signup_request = SignupRequest {
        email: "test@test.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: false,
    };

    let banned_token_store: BannedTokenStoreType =
        Arc::new(RwLock::new(HashsetBannedTokenStore::default()));

    let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
    let email_client = Arc::new(RwLock::new(MockEmailClient));

    let state = AppState::new(
        HashmapUserStore::default(),
        banned_token_store,
        two_fa_code_store,
        email_client,
    );

    let response = signup(State(state), Json(signup_request))
        .await
        .into_response();
    assert_eq!(response.status().as_u16(), 201);

    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    let body = to_bytes(response.into_response().into_body(), usize::MAX)
        .await
        .unwrap();

    let body = serde_json::from_slice::<SignupResponse>(&body).ok();
    let body = body.expect("Could not deserialize response body to SignupResponse");

    assert_eq!(body, expected_response);
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // The signup route should return a 400 HTTP status code if an invalid input is sent.
    // The input is considered invalid if:
    // - The email is empty or does not contain '@'
    // - The password is less than 8 characters

    // Create an array of invalid inputs. Then, iterate through the array and
    // make HTTP calls to the signup route. Assert a 400 HTTP status code is returned.
    let no_at_symbol_request = SignupRequest {
        email: "testtest.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: true,
    };

    let empty_email_request = SignupRequest {
        email: "".to_string(),
        password: "password123".to_string(),
        requires_2fa: true,
    };

    let short_password_request = SignupRequest {
        email: "test@test.com".to_string(),
        password: "short".to_string(),
        requires_2fa: true,
    };

    let invalid_inputs = vec![
        no_at_symbol_request,
        empty_email_request,
        short_password_request,
    ];

    let app = TestApp::new().await;

    for i in invalid_inputs.iter() {
        let response = app.post_signup(i).await;
        assert_eq!(response.status().as_u16(), 400, "Failed for input: {:?}", i);

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;

    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    let signup_request = SignupRequest {
        email: "test@test.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: true,
    };

    let response = app.post_signup(&signup_request).await;
    assert_eq!(response.status().as_u16(), 201);

    let signup_request = SignupRequest {
        email: "test@test.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: true,
    };

    let response = app.post_signup(&signup_request).await;
    assert_eq!(response.status().as_u16(), 409);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );
}
