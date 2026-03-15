use crate::domain::AuthAPIError;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Self, AuthAPIError> {
        if password.len() < 8 {
            return Err(AuthAPIError::InvalidCredentials);
        }
        Ok(Self(password))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_parse() {
        let password = Password::parse("password".to_string()).unwrap();
        assert_eq!(password.as_ref(), "password");
        let invalid_password = Password::parse("short".to_string());
        assert!(invalid_password.is_err());
    }
}
