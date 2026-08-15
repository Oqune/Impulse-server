//! Shared helpers for integration tests (single source for the Argon2+HMAC
//! client-side auth packet builder and the server-side verification path).
//! Replaces the triplicated helpers that used to live in `src/tests.rs`.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use impulse_server::crypto::hmac_key_from_stored_hash;
use impulse_server::protocol::{Opcode, PacketReader, PacketWriter};

type HmacSha256 = Hmac<Sha256>;

/// Parse and verify an Auth packet exactly as the server does (C3, §4.2):
/// the client sends only `HMAC(Argon2id(stored_hash), nonce)`, so the server
/// derives the HMAC key directly from the stored hash (no password) and compares.
/// Returns `(hash_ok, nonce_valid)`. In the HMAC-only scheme `hash_ok` collapses
/// into `nonce_valid` (the HMAC verifies iff the correct password-derived key was
/// used). The nonce is single-use (C4, §4): a second verification with an already
/// seen nonce is rejected even when the HMAC is valid.
///
/// `SEEN_NONCES` is a process-global registry shared by all tests in this binary;
/// the real server keys single-use by session, but the helper has no session, so the
/// raw nonce bytes are the key.
static SEEN_NONCES: OnceLock<Mutex<HashSet<Vec<u8>>>> = OnceLock::new();

pub fn server_verify_auth(
    packet: &[u8],
    stored_hash: &str,
    server_nonce: &[u8],
) -> Result<(bool, bool), String> {
    let mut reader = PacketReader::new(packet);
    let opcode = reader.read_opcode().map_err(|e| format!("opcode: {e}"))?;
    if opcode != Opcode::Auth {
        return Err("not an Auth packet".into());
    }

    // C3 (§4.2): HMAC-only frame — [u32 hmac_len=32] [32 hmac_response].
    let hmac_field = reader
        .read_len_prefixed()
        .map_err(|e| format!("hmac_len_prefixed: {e}"))?;
    if hmac_field.len() != 32 {
        return Err("HMAC field must be 32 bytes".into());
    }

    // C4 (§4): single-use nonce. A second verification with the same (already-seen)
    // nonce is rejected even if the HMAC itself is valid.
    {
        let seen = SEEN_NONCES
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .unwrap();
        if seen.contains(server_nonce) {
            return Ok((true, false));
        }
    }

    // Derive the HMAC key directly from the stored hash (no password on the wire, C3).
    let key = hmac_key_from_stored_hash(stored_hash).map_err(|e| e.to_string())?;
    let nonce_valid = {
        let mut mac =
            HmacSha256::new_from_slice(&key).map_err(|e| format!("HMAC key: {e}"))?;
        mac.update(server_nonce);
        mac.verify_slice(&hmac_field).is_ok()
    };

    if nonce_valid {
        SEEN_NONCES
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .unwrap()
            .insert(server_nonce.to_vec());
    }

    // `hash_ok` mirrors `nonce_valid` in the HMAC-only scheme (see doc above).
    Ok((nonce_valid, nonce_valid))
}

/// Derive a 32-byte Argon2id raw key from a password using the salt + params
/// stored in an encoded hash. Mirrors `relay::auth::derive_argon2_key`.
pub fn derive_argon2_key(password: &str, stored_hash: &str) -> Vec<u8> {
    use argon2::password_hash::PasswordHash;
    let parsed = PasswordHash::new(stored_hash).expect("should parse stored hash");
    let salt = parsed.salt.expect("stored hash should have a salt");
    let mut raw_salt_buf = [0u8; 64];
    let raw_salt = salt
        .decode_b64(&mut raw_salt_buf)
        .expect("should decode B64 salt");
    // Use the EXACT parameters stored in the hash (OWASP after the X1 change) so the
    // derived key equals the stored hash's embedded Argon2id output — the very key the
    // server extracts via `hmac_key_from_stored_hash` (C3). A frozen default diverges.
    let params = argon2::Params::try_from(&parsed).expect("should parse Argon2 params");
    let mut output = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.as_bytes(), raw_salt, &mut output)
        .expect("Argon2 derivation should not fail");
    output.to_vec()
}

/// Build a client Auth packet: [0x01] [u32 hmac_len=32] [32 hmac_response].
///
/// C3 (§4.2): the client sends ONLY the HMAC response — the raw password never
/// travels on the wire. The HMAC key is `Argon2id(password, salt)` derived from the
/// stored hash; the server reproduces that key from the stored hash directly.
pub fn build_client_auth(password: &str, server_nonce: &[u8], stored_hash: &str) -> Vec<u8> {
    let key = derive_argon2_key(password, stored_hash);
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(server_nonce);
    let hmac_response = mac.finalize().into_bytes().to_vec();
    let mut w = PacketWriter::with_opcode(Opcode::Auth);
    w.write_len_prefixed(&hmac_response);
    w.into_bytes()
}

/// Assert two byte slices are equal (handy for packet wire-format checks).
#[allow(dead_code)] // Individual integration-test crates do not all use this shared helper.
pub fn assert_bytes_eq(a: &[u8], b: &[u8]) {
    assert_eq!(a, b, "byte slices differ: {a:02x?} vs {b:02x?}");
}
