use std::collections::HashMap;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

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
        let searched_user = self.users.get(&email);
        match searched_user {
            None => Err(UserStoreError::UserNotFound),
            Some(user) => Ok(user.clone()),
        }
    }

    async fn validate_user(&self, email: &Email, password: Password) -> Result<(), UserStoreError> {
        let user = self.get_user(email)?;
        if user.password != password {
            return Err(UserStoreError::InvalidCredentials);
        }
        Ok(())
    }
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    pub fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let searched_user = self.users.get(&email);
        match searched_user {
            None => Err(UserStoreError::UserNotFound),
            Some(user) => Ok(user.clone()),
        }
    }

    pub fn validate_user(&self, email: &Email, password: Password) -> Result<(), UserStoreError> {
        let user = self.get_user(email)?;
        if user.password != password {
            return Err(UserStoreError::InvalidCredentials);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com".to_string()).unwrap(),
            Password::parse("password".to_string()).unwrap(),
            false,
        );
        assert!(user_store.add_user(user.clone()).is_ok());
        assert_eq!(
            user_store.add_user(user).unwrap_err(),
            UserStoreError::UserAlreadyExists
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com".to_string()).unwrap(),
            Password::parse("password".to_string()).unwrap(),
            false,
        );
        user_store.add_user(user.clone()).unwrap();
        assert_eq!(
            user_store
                .get_user(&Email::parse("test@example.com".to_string()).unwrap())
                .unwrap(),
            user
        );
        assert_eq!(
            user_store
                .get_user(&Email::parse("nonexistent@example.com".to_string()).unwrap())
                .unwrap_err(),
            UserStoreError::UserNotFound
        );
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com".to_string()).unwrap(),
            Password::parse("password".to_string()).unwrap(),
            false,
        );
        user_store.add_user(user.clone()).unwrap();
        assert!(user_store
            .validate_user(
                &Email::parse("test@example.com".to_string()).unwrap(),
                Password::parse("password".to_string()).unwrap()
            )
            .is_ok());
        assert_eq!(
            user_store
                .validate_user(
                    &Email::parse("test@example.com".to_string()).unwrap(),
                    Password::parse("wrongpassword".to_string()).unwrap()
                )
                .unwrap_err(),
            UserStoreError::InvalidCredentials
        );
        assert_eq!(
            user_store
                .validate_user(
                    &Email::parse("nonexistent@example.com".to_string()).unwrap(),
                    Password::parse("password".to_string()).unwrap()
                )
                .unwrap_err(),
            UserStoreError::UserNotFound
        );
    }
}
