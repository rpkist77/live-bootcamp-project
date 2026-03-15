use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User, UserStore, UserStoreError},
};

pub async fn signup<T: UserStore>(
    State(state): State<AppState<T>>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email)?;
    let password: Password = Password::parse(request.password)?;

    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    let does_user_already_exist = user_store.get_user(user.email.clone()).await;
    match does_user_already_exist {
        Ok(_) => return Err(AuthAPIError::UserAlreadyExists),
        Err(UserStoreError::UserNotFound) => (),
        Err(e) => {
            eprintln!("Unexpected error when checking if user exists: {:?}", e);
            return Err(AuthAPIError::UnexpectedError);
        }
    }

    if let Err(e) = user_store.add_user(user).await {
        eprintln!("Unexpected error when adding user: {:?}", e);
        return Err(AuthAPIError::UnexpectedError);
    }

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

//...

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SignupResponse {
    pub message: String,
}

impl SignupResponse {
    pub fn json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
