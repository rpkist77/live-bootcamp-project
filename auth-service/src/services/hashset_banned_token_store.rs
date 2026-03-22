use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    banned_tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_banned_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.banned_tokens.insert(token);
        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.banned_tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_and_contains_banned_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = "test_token".to_owned();

        assert!(!store.contains_token(&token).await.unwrap());

        store.add_banned_token(token.clone()).await.unwrap();

        assert!(store.contains_token(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_contains_nonexistent_token() {
        let store = HashsetBannedTokenStore::default();
        assert!(!store.contains_token("nonexistent").await.unwrap());
    }
}
