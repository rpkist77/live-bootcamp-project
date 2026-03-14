use std::collections::HashMap;

use crate::domain::{User, UserStore, UserStoreError};

#[derive(Default, Clone)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
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

    async fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        let searched_user = self.users.get(email);
        match searched_user {
            None => Err(UserStoreError::UserNotFound),
            Some(user) => Ok(user.clone()),
        }
    }

    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
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

    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        let searched_user = self.users.get(email);
        match searched_user {
            None => Err(UserStoreError::UserNotFound),
            Some(user) => Ok(user.clone()),
        }
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
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
            "test@example.com".to_string(),
            "password".to_string(),
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
        let user: User = User::new(
            "test@example.com".to_string(),
            "password".to_string(),
            false,
        );
        user_store.add_user(user.clone()).unwrap();
        assert_eq!(user_store.get_user("test@example.com").unwrap(), user);
        assert_eq!(
            user_store.get_user("nonexistent@example.com").unwrap_err(),
            UserStoreError::UserNotFound
        );
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            "test@example.com".to_string(),
            "password".to_string(),
            false,
        );
        user_store.add_user(user.clone()).unwrap();
        assert!(user_store
            .validate_user("test@example.com", "password")
            .is_ok());
        assert_eq!(
            user_store
                .validate_user("test@example.com", "wrongpassword")
                .unwrap_err(),
            UserStoreError::InvalidCredentials
        );
        assert_eq!(
            user_store
                .validate_user("nonexistent@example.com", "password")
                .unwrap_err(),
            UserStoreError::UserNotFound
        );
    }
}
