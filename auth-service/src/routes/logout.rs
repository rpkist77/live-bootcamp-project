use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie::Cookie, CookieJar};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, UserStore},
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout<T: UserStore>(
    State(state): State<AppState<T>>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    if let Err(_) = validate_token(&token, state.banned_token_store.clone()).await {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    if let Err(e) = state
        .banned_token_store
        .write()
        .await
        .add_banned_token(token)
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    let jar = jar.remove(Cookie::new(JWT_COOKIE_NAME, ""));
    (jar, Ok(StatusCode::OK))
}
