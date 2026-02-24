use axum::{http, response::IntoResponse};
use http::status::StatusCode;

pub async fn logout() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
