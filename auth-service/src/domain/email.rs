use color_eyre::eyre::{eyre, Result};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Self> {
        if email.is_empty() || !email.contains('@') {
            return Err(eyre!("invalid email format"));
        }
        Ok(Self(email))
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_parse() {
        let email = Email::parse("test@example.com".to_string()).unwrap();
        assert_eq!(email.as_ref(), "test@example.com");

        let invalid_email = Email::parse("invalid".to_string());
        assert!(invalid_email.is_err());
    }
}
