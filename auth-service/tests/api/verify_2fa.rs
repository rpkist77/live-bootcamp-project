use auth_service::{
    domain::Email, routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME, ErrorResponse,
};
use secrecy::{ExposeSecret, SecretString};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;
    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({}),
        serde_json::json!({
            "email": random_email,
            "loginAttemptId": "not-a-uuid"
        }),
        serde_json::json!({
            "email": random_email,
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": random_email,
            "loginAttemptId": "not-a-uuid",
            "2FACode": 123456
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;
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
    let mut app = TestApp::new().await;

    let invalid_inputs = [
        serde_json::json!({
            "email": "invalid-email",
            "loginAttemptId": uuid::Uuid::new_v4().to_string(),
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": get_random_email(),
            "loginAttemptId": "not-a-uuid",
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": get_random_email(),
            "loginAttemptId": uuid::Uuid::new_v4().to_string(),
            "2FACode": "123"
        }),
    ];

    for input in invalid_inputs.iter() {
        let response = app.post_verify_2fa(input).await;
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
    let mut app = TestApp::new().await;
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    let verify_body = serde_json::json!({
        "email": get_random_email(),
        "loginAttemptId": uuid::Uuid::new_v4().to_string(),
        "2FACode": "123456"
    });

    let response = app.post_verify_2fa(&verify_body).await;
    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Incorrect credentials".to_owned()
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let mut app = TestApp::new().await;
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": signup_body["email"],
        "password": "password123"
    });

    let first_login = app.post_login(&login_body).await;
    assert_eq!(first_login.status().as_u16(), 206);

    let email = Email::parse(SecretString::from(
        signup_body["email"].as_str().unwrap().to_owned(),
    ))
    .unwrap();
    let (old_login_attempt_id, old_code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&email)
        .await
        .expect("Expected code in store after first login");

    let second_login = app.post_login(&login_body).await;
    assert_eq!(second_login.status().as_u16(), 206);

    let verify_body = serde_json::json!({
        "email": signup_body["email"],
        "loginAttemptId": old_login_attempt_id.as_ref().expose_secret(),
        "2FACode": old_code.as_ref().expose_secret()
    });

    let response = app.post_verify_2fa(&verify_body).await;
    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let mut app = TestApp::new().await;
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": signup_body["email"],
        "password": "password123"
    });

    let login_response = app.post_login(&login_body).await;
    assert_eq!(login_response.status().as_u16(), 206);

    let response_body = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize login response");

    let email = Email::parse(SecretString::from(
        signup_body["email"].as_str().unwrap().to_owned(),
    ))
    .unwrap();
    let (_, code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&email)
        .await
        .expect("Expected code in store after login");

    let verify_body = serde_json::json!({
        "email": signup_body["email"],
        "loginAttemptId": response_body.login_attempt_id,
        "2FACode": code.as_ref().expose_secret()
    });

    let response = app.post_verify_2fa(&verify_body).await;
    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let mut app = TestApp::new().await;
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": signup_body["email"],
        "password": "password123"
    });
    let login_response = app.post_login(&login_body).await;
    assert_eq!(login_response.status().as_u16(), 206);

    let response_body = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize login response");

    let email = Email::parse(SecretString::from(
        signup_body["email"].as_str().unwrap().to_owned(),
    ))
    .unwrap();
    let (_, code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&email)
        .await
        .expect("Expected code in store after login");

    let verify_body = serde_json::json!({
        "email": signup_body["email"],
        "loginAttemptId": response_body.login_attempt_id,
        "2FACode": code.as_ref().expose_secret()
    });

    let first_response = app.post_verify_2fa(&verify_body).await;
    assert_eq!(first_response.status().as_u16(), 200);

    let second_response = app.post_verify_2fa(&verify_body).await;
    assert_eq!(second_response.status().as_u16(), 401);

    app.clean_up().await;
}
