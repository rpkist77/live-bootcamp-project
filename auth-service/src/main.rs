use auth_service::{
    app_state::{AppState, BannedTokenStoreType},
    get_postgres_pool,
    services::{
        hashmap_two_fa_code_store::HashmapTwoFACodeStore, mock_email_client::MockEmailClient,
        HashmapUserStore, HashsetBannedTokenStore,
    },
    utils::constants::{prod, DATABASE_URL},
    Application,
};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let _pg_pool = configure_postgresql().await;

    let user_store = HashmapUserStore::default();
    let banned_token_store: BannedTokenStoreType =
        Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
    let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
    let email_client = Arc::new(RwLock::new(MockEmailClient));

    let app_state = AppState::new(
        user_store,
        banned_token_store,
        two_fa_code_store,
        email_client,
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}
