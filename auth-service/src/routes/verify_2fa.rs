use axum::{http, response::IntoResponse};
use http::status::StatusCode;

pub async fn verify_2fa() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
