use axum::{http, response::IntoResponse};
use http::status::StatusCode;

pub async fn login() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
