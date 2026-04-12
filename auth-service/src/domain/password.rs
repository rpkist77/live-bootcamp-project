use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use color_eyre::eyre::{Context, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct HashedPassword(String);

impl HashedPassword {
    pub async fn parse(s: String) -> Result<Self> {
        if s.is_empty() || s.len() < 8 {
            return Err(color_eyre::eyre::eyre!(
                "Password must be at least 8 characters"
            ));
        }

        let password_hash = compute_password_hash(&s).await?;

        Ok(Self(password_hash))
    }

    pub fn parse_password_hash(hash: String) -> Result<HashedPassword> {
        PasswordHash::new(&hash).wrap_err("invalid argon2 hash")?;
        Ok(HashedPassword(hash))
    }

    #[tracing::instrument(name = "Verify password hash", skip_all)]
    pub async fn verify_raw_password(&self, password_candidate: &str) -> Result<()> {
        let current_span: tracing::Span = tracing::Span::current();
        let password_hash = self.as_ref().to_owned();
        let password_candidate = password_candidate.to_owned();

        let result = tokio::task::spawn_blocking(move || {
            current_span.in_scope(|| {
                let expected_password_hash = PasswordHash::new(&password_hash)?;

                Argon2::default()
                    .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                    .wrap_err("failed to verify password hash")
            })
        })
        .await;

        result?
    }
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: &str) -> Result<String> {
    let current_span: tracing::Span = tracing::Span::current();
    let password = password.to_owned();

    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt: SaltString = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

            Ok(password_hash)
        })
    })
    .await;

    result?
}

impl AsRef<str> for HashedPassword {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::HashedPassword;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Algorithm, Argon2, Params, PasswordHasher, Version,
    };

    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = "".to_owned();
        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
        let password = "1234567".to_owned();
        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[test]
    fn can_parse_valid_argon2_hash() {
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hash_password = HashedPassword::parse_password_hash(hash_string.clone()).unwrap();

        assert_eq!(hash_password.as_ref(), hash_string.as_str());
        assert!(hash_password.as_ref().starts_with("$argon2id$v=19$"));
    }

    #[tokio::test]
    async fn can_verify_raw_password() {
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hash_password = HashedPassword::parse_password_hash(hash_string).unwrap();

        let result = hash_password.verify_raw_password(raw_password).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn valid_passwords_are_parsed_successfully() {
        assert!(HashedPassword::parse("password123".to_owned())
            .await
            .is_ok());
        assert!(HashedPassword::parse("another_good_password".to_owned())
            .await
            .is_ok());
    }
}
