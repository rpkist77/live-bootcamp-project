use auth_service::{
    app_state::{AppState, UserStoreType},
    domain::UserStore,
    services::HashmapUserStore,
    Application,
};

#[tokio::main]
async fn main() {
    let user_store = HashmapUserStore::default();
    let app_state = AppState::new(user_store);

    let app = Application::build(app_state, "0.0.0.0:3000")
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
