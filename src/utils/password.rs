use argon2::password_hash::{rand_core::OsRng, Error, PasswordHash, PasswordVerifier, SaltString};
use argon2::{Argon2, PasswordHasher};

pub fn hash_password(password: &str) -> Result<String, Error> {
    #[cfg(test)]
    if password == "\0" {
        return Err(password_hash::Error::Password);
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();
    Ok(password_hash)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
