use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};
use secrecy::{ExposeSecret, SecretString};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    banned_tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_banned_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError> {
        self.banned_tokens.insert(token.expose_secret().to_owned());
        Ok(())
    }

    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        Ok(self.banned_tokens.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_and_contains_banned_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = SecretString::from("test_token".to_owned());

        assert!(!store.contains_token(&token).await.unwrap());

        store
            .add_banned_token(SecretString::from(token.expose_secret().to_owned()))
            .await
            .unwrap();

        assert!(store.contains_token(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_contains_nonexistent_token() {
        let store = HashsetBannedTokenStore::default();
        assert!(!store
            .contains_token(&SecretString::from("nonexistent".to_owned()))
            .await
            .unwrap());
    }
}
