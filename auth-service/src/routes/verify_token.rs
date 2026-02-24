use axum::{http, response::IntoResponse};
use http::status::StatusCode;

pub async fn verify_token() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
