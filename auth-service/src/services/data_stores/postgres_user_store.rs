use sqlx::PgPool;
use secrecy::{ExposeSecret, SecretString};

use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    Email, HashedPassword, User,
};

#[derive(Clone)]
pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        sqlx::query!(
            r#"
            INSERT INTO users (email, password_hash, requires_2fa)
            VALUES ($1, $2, $3)
            "#,
            user.email.as_ref().expose_secret(),
            user.password.as_ref().expose_secret(),
            user.requires_2fa,
        )
        .execute(&self.pool)
        .await
        .map_err(|err| {
            if let Some(db_err) = err.as_database_error() {
                if db_err.code().as_deref() == Some("23505") {
                    return UserStoreError::UserAlreadyExists;
                }
            }
            UserStoreError::UnexpectedError(err.into())
        })?;

        Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let row = sqlx::query!(
            r#"
            SELECT email, password_hash, requires_2fa
            FROM users
            WHERE email = $1
            "#,
            email.as_ref().expose_secret(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?
        .ok_or(UserStoreError::UserNotFound)?;

        let email = Email::parse(SecretString::from(row.email))
            .map_err(UserStoreError::UnexpectedError)?;
        let password = HashedPassword::parse_password_hash(SecretString::from(row.password_hash))
            .map_err(UserStoreError::UnexpectedError)?;

        Ok(User::new(email, password, row.requires_2fa))
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn validate_user(
        &self,
        email: &Email,
        raw_password: &SecretString,
    ) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;

        user.password
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}
