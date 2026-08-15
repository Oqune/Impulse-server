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
    // OWASP-recommended Argon2id parameters (AGENTS.md §22-23 / SPEC X1):
    //   m = 47104 KiB, t = 3 iterations, p = 1 lane.
    // Never weaken — these are the canonical strength the client must also use
    // (transmitted in the AuthChallenge, SPEC N1).
    let params = argon2::Params::new(47104, 3, 1, None)
        .map_err(|e| anyhow::anyhow!("failed to build OWASP Argon2 params: {e}"))?;
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
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

/// Extract the raw 32-byte Argon2id output directly from a stored hash string.
///
/// The client's Auth HMAC key is `HMAC(Argon2id(password, salt), nonce)`. Because the stored
/// hash string encodes exactly `Argon2id(password, salt)`, its embedded output field *is* that
/// key. The server therefore verifies the client's HMAC with this key **without ever receiving
/// the password** (C3, §4.2) — fail-closed: if the stored hash has no output, verification
/// cannot proceed.
pub fn hmac_key_from_stored_hash(stored_hash: &str) -> anyhow::Result<Vec<u8>> {
    use argon2::password_hash::PasswordHash;
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| anyhow::anyhow!("failed to parse stored hash: {e}"))?;
    match &parsed.hash {
        Some(h) => Ok(h.as_bytes().to_vec()),
        None => anyhow::bail!("stored Argon2 hash has no output field"),
    }
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
