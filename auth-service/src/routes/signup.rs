use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::{ser::SerializeStruct, Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, HashedPassword, User, UserStore, UserStoreError},
};

#[tracing::instrument(name = "Signup", skip_all)]
pub async fn signup<T: UserStore>(
    State(state): State<AppState<T>>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password: HashedPassword = HashedPassword::parse(request.password)
        .await
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    let does_user_already_exist = user_store.get_user(&user.email).await;
    match does_user_already_exist {
        Ok(_) => return Err(AuthAPIError::UserAlreadyExists),
        Err(UserStoreError::UserNotFound) => (),
        Err(e) => return Err(AuthAPIError::UnexpectedError(e.into())),
    }

    if let Err(e) = user_store.add_user(user).await {
        return Err(AuthAPIError::UnexpectedError(e.into()));
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

#[derive(Deserialize, Debug)]
pub struct SignupRequest {
    pub email: SecretString,
    pub password: SecretString,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

impl Serialize for SignupRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SignupRequest", 3)?;
        state.serialize_field("email", self.email.expose_secret())?;
        state.serialize_field("password", self.password.expose_secret())?;
        state.serialize_field("requires2FA", &self.requires_2fa)?;
        state.end()
    }
}
