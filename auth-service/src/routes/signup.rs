use axum::{http, response::IntoResponse};
use http::status::StatusCode;

pub async fn signup() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
