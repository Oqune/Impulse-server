//! Authentication cryptography: Argon2id password hashing and verification.
//!
//! Kept separate from config so the relay's auth handshake does not depend on
//! config-file plumbing. `argon2_hash` is fallible — under `panic = "abort"`
//! (Cargo.toml release profile) an `.expect()` on a hash failure would kill the
//! whole process instead of surfacing an error.

/// SHA-256 hex of a string (used in tests).
pub fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// SHA-256 hex of arbitrary bytes (used by `relay::users` for fingerprints).
pub fn sha256_hex_bytes(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(input))
}

/// Argon2id hash of a string (used by --hash-password).
pub fn argon2_hash(input: &str) -> anyhow::Result<String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use rand::rngs::OsRng;
    let salt = SaltString::generate(&mut OsRng);
    // Use Argon2id explicitly to match argon2_verify which uses Argon2::new(Argon2id, ...).
    // Argon2::default() may use Argon2i which would cause silent verification failures.
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    );
    argon2
        .hash_password(input.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("Argon2 hashing failed: {}", e))
}

/// Verify a password against an Argon2id encoded hash.
pub fn argon2_verify(password: &str, stored_hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let parsed = match PasswordHash::new(stored_hash) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // Use params from the stored hash, not Argon2::default().
    let params = match argon2::Params::try_from(&parsed) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );
    argon2.verify_password(password.as_bytes(), &parsed).is_ok()
}

#[cfg(test)]
mod tests {
    use super::{argon2_hash, argon2_verify, sha256_hex};

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(
            sha256_hex("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn argon2_hash_roundtrip_and_verify() {
        let hash = argon2_hash("my_secret_password").expect("hash should succeed");
        assert!(hash.starts_with("$argon2"));
        assert!(argon2_verify("my_secret_password", &hash));
        assert!(!argon2_verify("wrong", &hash));
    }
}
