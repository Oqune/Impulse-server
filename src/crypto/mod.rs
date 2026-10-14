//! Authentication cryptography: Argon2id password hashing and verification.
//!
//! Kept separate from config so the relay's auth handshake does not depend on
//! config-file plumbing. `argon2_hash` is fallible — under `panic = "abort"`
//! (Cargo.toml release profile) an `.expect()` on a hash failure would kill the
//! whole process instead of surfacing an error.

/// Parameters parsed from a validated server password hash and advertised to clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthHashParameters {
    pub salt_b64: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Validate the PHC hash shape and resource bounds used by the auth handshake.
///
/// This rejects unsupported hashes before startup can accept sessions. Bounds are
/// deliberately narrow: minimums preserve the canonical OWASP setting, while the
/// maxima match the current client's supported parameters.
pub fn validate_auth_hash(stored_hash: &str) -> anyhow::Result<AuthHashParameters> {
    use argon2::password_hash::PasswordHash;

    const MAX_ENCODED_HASH_BYTES: usize = 512;
    const MIN_SALT_BYTES: usize = 16;
    const AUTH_OUTPUT_BYTES: usize = 32;

    if stored_hash.len() > MAX_ENCODED_HASH_BYTES {
        anyhow::bail!("password_hash exceeds the supported encoded length");
    }
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|_| anyhow::anyhow!("password_hash is not a valid Argon2id PHC string"))?;
    if parsed.algorithm.as_str() != "argon2id" || parsed.version != Some(19) {
        anyhow::bail!("password_hash must use Argon2id version 19");
    }

    let salt = parsed
        .salt
        .ok_or_else(|| anyhow::anyhow!("password_hash is missing its salt"))?;
    let mut salt_buf = [0u8; 64];
    let salt_bytes = salt
        .decode_b64(&mut salt_buf)
        .map_err(|_| anyhow::anyhow!("password_hash has an invalid salt"))?;
    if salt_bytes.len() < MIN_SALT_BYTES {
        anyhow::bail!("password_hash salt must contain at least 16 bytes");
    }

    let output = parsed
        .hash
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("password_hash is missing its output"))?;
    if output.as_bytes().len() != AUTH_OUTPUT_BYTES {
        anyhow::bail!("password_hash output must be exactly 32 bytes");
    }

    let params = argon2::Params::try_from(&parsed)
        .map_err(|_| anyhow::anyhow!("password_hash has invalid Argon2 parameters"))?;
    let (memory_kib, iterations, parallelism) =
        (params.m_cost(), params.t_cost(), params.p_cost());
    if !(47_104..=65_536).contains(&memory_kib)
        || !(3..=6).contains(&iterations)
        || !(1..=2).contains(&parallelism)
    {
        anyhow::bail!("password_hash Argon2 parameters are outside supported bounds");
    }

    Ok(AuthHashParameters {
        salt_b64: salt.to_string(),
        memory_kib,
        iterations,
        parallelism,
    })
}

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
    // Keep generated hashes at the canonical minimum. Config validation also
    // permits bounded stronger tuples, which the AuthChallenge advertises exactly.
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
    use super::{argon2_hash, argon2_verify, sha256_hex, validate_auth_hash};

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

    #[test]
    fn accepts_noncanonical_supported_parameters_and_extracts_exact_values() {
        let salt = argon2::password_hash::SaltString::encode_b64(b"0123456789abcdef")
            .expect("salt is valid");
        let output = argon2::password_hash::Output::new(&[7u8; 32]).expect("output is valid");
        let hash = format!("$argon2id$v=19$m=49152,t=4,p=2${}${}", salt, output);
        let parsed = validate_auth_hash(&hash).expect("supported tuple should validate");
        assert_eq!(parsed.salt_b64, salt.as_str());
        assert_eq!(
            (parsed.memory_kib, parsed.iterations, parsed.parallelism),
            (49152, 4, 2)
        );
    }

    #[test]
    fn rejects_unsupported_auth_hash_shapes_and_costs() {
        let cases = [
            "$argon2i$v=19$m=47104,t=3,p=1$MDEyMzQ1Njc4OWFiY2RlZg$BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "$argon2id$v=16$m=47104,t=3,p=1$MDEyMzQ1Njc4OWFiY2RlZg$BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "$argon2id$v=19$m=8192,t=1,p=1$MDEyMzQ1Njc4OWFiY2RlZg$BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "$argon2id$v=19$m=65537,t=3,p=1$MDEyMzQ1Njc4OWFiY2RlZg$BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "$argon2id$v=19$m=47104,t=3,p=3$MDEyMzQ1Njc4OWFiY2RlZg$BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "$argon2id$v=19$m=47104,t=3,p=1$MDEyMzQ1Njc4OWFiY2RlZg$BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "$argon2id$v=19$m=47104,t=3,p=1$MDEyMzQ1Njc4OQ$BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
        ];
        for hash in cases {
            assert!(validate_auth_hash(hash).is_err(), "must reject invalid hash shape");
        }
        let error = validate_auth_hash("sensitive-invalid-value").unwrap_err();
        assert!(!error.to_string().contains("sensitive-invalid-value"));
    }
}
