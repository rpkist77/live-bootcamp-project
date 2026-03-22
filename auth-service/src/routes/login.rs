use axum::{extract::State, http, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use http::status::StatusCode;
use serde::Deserialize;

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, UserStore},
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

    // Call the generate_auth_cookie function defined in the auth module.
    // If the function call fails return AuthAPIError::UnexpectedError.
    let auth_cookie = match crate::utils::auth::generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(_) => {
            eprintln!("Failed to generate auth cookie");
            return (
                jar,
                Ok((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Unexpected error".to_string(),
                    }),
                )
                    .into_response()),
            );
        }
    };

    let updated_jar = jar.add(auth_cookie);

    (updated_jar, Ok(StatusCode::OK.into_response()))
}
