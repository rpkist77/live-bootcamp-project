use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    domain::{BannedTokenStore, UserStore},
    services::hashmap_user_store::HashmapUserStore,
};

// Using a type alias to improve readability!
pub type UserStoreType = Arc<RwLock<HashmapUserStore>>;
pub type BannedTokenStoreType = Arc<RwLock<dyn BannedTokenStore + Send + Sync>>;

#[derive(Clone)]
pub struct AppState<T: UserStore> {
    pub user_store: Arc<RwLock<T>>,
    pub banned_token_store: BannedTokenStoreType,
}

impl<T: UserStore> AppState<T> {
    pub fn new(user_store: T, banned_token_store: BannedTokenStoreType) -> Self {
        Self {
            user_store: Arc::new(RwLock::new(user_store)),
            banned_token_store,
        }
    }
}
