use std::collections::HashMap;

use crate::domain::{Email, User, UserStore, UserStoreError};

#[derive(Default, Clone)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            None => Err(UserStoreError::UserNotFound),
            Some(user) => Ok(user.clone()),
        }
    }

    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;

        user.password
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::HashedPassword;

    #[tokio::test]
    async fn test_add_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com".to_string()).unwrap(),
            HashedPassword::parse("password123".to_string())
                .await
                .unwrap(),
            false,
        );
        assert!(user_store.add_user(user.clone()).await.is_ok());
        assert_eq!(
            user_store.add_user(user).await.unwrap_err(),
            UserStoreError::UserAlreadyExists
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com".to_string()).unwrap(),
            HashedPassword::parse("password123".to_string())
                .await
                .unwrap(),
            false,
        );
        user_store.add_user(user.clone()).await.unwrap();

        assert_eq!(
            user_store
                .get_user(&Email::parse("test@example.com".to_string()).unwrap())
                .await
                .unwrap(),
            user
        );

        assert_eq!(
            user_store
                .get_user(&Email::parse("nonexistent@example.com".to_string()).unwrap())
                .await
                .unwrap_err(),
            UserStoreError::UserNotFound
        );
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com".to_string()).unwrap(),
            HashedPassword::parse("password123".to_string())
                .await
                .unwrap(),
            false,
        );
        user_store.add_user(user.clone()).await.unwrap();

        assert!(user_store
            .validate_user(
                &Email::parse("test@example.com".to_string()).unwrap(),
                "password123",
            )
            .await
            .is_ok());

        assert_eq!(
            user_store
                .validate_user(
                    &Email::parse("test@example.com".to_string()).unwrap(),
                    "wrongpassword",
                )
                .await
                .unwrap_err(),
            UserStoreError::InvalidCredentials
        );

        assert_eq!(
            user_store
                .validate_user(
                    &Email::parse("nonexistent@example.com".to_string()).unwrap(),
                    "password123",
                )
                .await
                .unwrap_err(),
            UserStoreError::UserNotFound
        );
    }
}
