use std::collections::HashMap;

use async_trait::async_trait;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email);
        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        match self.codes.get(email) {
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
            Some(pair) => Ok(pair.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_code_success() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse("123456".to_string()).unwrap();

        let result = store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_code_success() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse("123456".to_string()).unwrap();

        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        let result = store.get_code(&email).await;
        assert!(result.is_ok());
        let (returned_id, returned_code) = result.unwrap();
        assert_eq!(returned_id, login_attempt_id);
        assert_eq!(returned_code, code);
    }

    #[tokio::test]
    async fn test_get_code_not_found() {
        let store = HashmapTwoFACodeStore::default();
        let email = Email::parse("notfound@example.com".to_string()).unwrap();

        let result = store.get_code(&email).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TwoFACodeStoreError::LoginAttemptIdNotFound
        );
    }

    #[tokio::test]
    async fn test_remove_code_success() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse("123456".to_string()).unwrap();

        store
            .add_code(email.clone(), login_attempt_id, code)
            .await
            .unwrap();
        let result = store.remove_code(&email).await;
        assert!(result.is_ok());
        assert!(store.get_code(&email).await.is_err());
    }

    #[tokio::test]
    async fn test_remove_non_existent_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("notfound@example.com".to_string()).unwrap();

        let result = store.remove_code(&email).await;
        assert!(result.is_ok());
    }
}
