use crate::domain::{email_client, BannedTokenStore, EmailClient, TwoFACodeStore, UserStore};
use crate::services::hashmap_user_store::HashmapUserStore;
use std::sync::Arc;
use tokio::sync::RwLock;

// Using a type alias to improve readability!
pub type UserStoreType = Arc<RwLock<HashmapUserStore>>;
pub type BannedTokenStoreType = Arc<RwLock<dyn BannedTokenStore + Send + Sync>>;
pub type TwoFACodeStoreType = Arc<RwLock<dyn TwoFACodeStore + Send + Sync>>;
pub type EmailClientType = Arc<RwLock<dyn EmailClient + Send + Sync>>;

#[derive(Clone)]
pub struct AppState<T: UserStore> {
    pub user_store: Arc<RwLock<T>>,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType,
    pub email_client: EmailClientType, // New!
}

impl<T: UserStore> AppState<T> {
    pub fn new(
        user_store: T,
        banned_token_store: BannedTokenStoreType,
        two_fa_code_store: TwoFACodeStoreType,
        email_client: EmailClientType,
    ) -> Self {
        Self {
            user_store: Arc::new(RwLock::new(user_store)),
            banned_token_store,
            two_fa_code_store,
            email_client,
        }
    }
}
