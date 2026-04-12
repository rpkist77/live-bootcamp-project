use axum::{extract::State, http, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use http::status::StatusCode;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, Password, TwoFACode, UserStore},
    ErrorResponse,
};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn login<T: UserStore>(
    State(state): State<AppState<T>>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email: Email = match Email::parse(request.email) {
        Ok(email) => email,
        Err(e) => {
            eprintln!("Invalid email format: {:?}", e);
            return (
                jar,
                Ok((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Invalid credentials".to_string(),
                    }),
                )
                    .into_response()),
            );
        }
    };
    let password = match Password::parse(request.password) {
        Ok(password) => password,
        Err(e) => {
            eprintln!("Invalid password format: {:?}", e);
            return (
                jar,
                Ok((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Invalid credentials".to_string(),
                    }),
                )
                    .into_response()),
            );
        }
    };

    let user_store = state.user_store.read().await;
    if let Err(error) = user_store.validate_user(&email, password).await {
        eprintln!("Login failed: {:?}", error);
        return (
            jar,
            Ok((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid credentials".to_string(),
                }),
            )
                .into_response()),
        );
    }

    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    dbg!(&user);

    // Handle request based on user's 2FA configuration
    match user.requires_2fa {
        true => {
            let (jar, result) = handle_2fa(&email, &state, jar).await;
            (jar, result.map(|r| r.into_response()))
        }
        false => {
            let (jar, result) = handle_no_2fa(&user.email, jar).await;
            (jar, result.map(|r| r.into_response()))
        }
    }
}

// New!
async fn handle_2fa<T: UserStore>(
    email: &Email,       // New!
    state: &AppState<T>, // New!
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // First, we must generate a new random login attempt ID and 2FA code
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    // TODO: Store the ID and code in our 2FA code store. Return `AuthAPIError::UnexpectedError` if the operation fails
    let two_fa_result = state
        .two_fa_code_store
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
        .await
        .map_err(|_| AuthAPIError::UnexpectedError);

    if let Err(err) = two_fa_result {
        return (jar, Err(err));
    }

    let email_result = state
        .email_client
        .read()
        .await
        .send_email(email, "2FA Code", two_fa_code.as_ref())
        .await;

    if let Err(_) = email_result {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    // Finally, we need to return the login attempt ID to the client
    let response = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().to_owned(), // Add the generated login attempt ID
    }));

    (jar, Ok((StatusCode::PARTIAL_CONTENT, response)))
}

// New!
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Call the generate_auth_cookie function defined in the auth module.
    // If the function call fails return AuthAPIError::UnexpectedError.
    let auth_cookie = match crate::utils::auth::generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(_) => {
            eprintln!("Failed to generate auth cookie");
            return (jar, Err(AuthAPIError::UnexpectedError));
        }
    };

    let updated_jar = jar.add(auth_cookie);

    (
        updated_jar,
        Ok((StatusCode::OK, Json(LoginResponse::RegularAuth)).into_response()),
    )
}

//...

// The login route can return 2 possible success responses.
// This enum models each response!
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}
