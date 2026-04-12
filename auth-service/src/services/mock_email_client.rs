use crate::domain::{Email, EmailClient};
use color_eyre::eyre::Result;

pub struct MockEmailClient;

#[async_trait::async_trait]
impl EmailClient for MockEmailClient {
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<()> {
        let _ = recipient;
        let _ = content;
        tracing::debug!(
            "Sending email with subject '{}'",
            subject
        );

        Ok(())
    }
}
