//! Shared helpers for integration tests (single source for the Argon2+HMAC
//! client-side auth packet builder and the server-side verification path).
//! Replaces the triplicated helpers that used to live in `src/tests.rs`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use impulse_server::protocol::{Opcode, PacketReader, PacketWriter};

type HmacSha256 = Hmac<Sha256>;

/// Parse and verify an Auth packet exactly as the server does
/// (`relay::auth::verify_auth`): Argon2 password check against the stored
/// hash, then HMAC-SHA-256 of the server nonce with the derived Argon2 key.
/// Returns `(hash_ok, nonce_valid)`.
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

    let password_bytes = reader
        .read_len_prefixed()
        .map_err(|e| format!("pwd_len_prefixed: {e}"))?;
    let password =
        String::from_utf8(password_bytes).map_err(|_| String::from("invalid UTF-8 in password"))?;

    let hash_ok = impulse_server::crypto::argon2_verify(&password, stored_hash);

    let nonce_valid = if reader.remaining().is_empty() {
        false
    } else {
        let client_response = reader
            .read_bytes(32)
            .map_err(|e| format!("hmac bytes: {e}"))?;
        if client_response.len() != 32 {
            return Err("HMAC not 32 bytes".into());
        }
        if hash_ok {
            let key = derive_argon2_key(&password, stored_hash);
            let mut mac = HmacSha256::new_from_slice(&key).map_err(|e| format!("HMAC key: {e}"))?;
            mac.update(server_nonce);
            mac.verify_slice(&client_response).is_ok()
        } else {
            false
        }
    };

    Ok((hash_ok, nonce_valid))
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
    let mut output = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), raw_salt, &mut output)
        .expect("Argon2 derivation should not fail");
    output.to_vec()
}

/// Build a client Auth packet: [0x01] [u32 LE pwd_len] [pwd_bytes] [32 raw HMAC].
pub fn build_client_auth(password: &str, server_nonce: &[u8], stored_hash: &str) -> Vec<u8> {
    let key = derive_argon2_key(password, stored_hash);
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(server_nonce);
    let hmac_response = mac.finalize().into_bytes().to_vec();
    let mut w = PacketWriter::with_opcode(Opcode::Auth);
    w.write_len_prefixed(password.as_bytes());
    w.write_raw(&hmac_response);
    w.into_bytes()
}

/// Assert two byte slices are equal (handy for packet wire-format checks).
#[allow(dead_code)] // Individual integration-test crates do not all use this shared helper.
pub fn assert_bytes_eq(a: &[u8], b: &[u8]) {
    assert_eq!(a, b, "byte slices differ: {a:02x?} vs {b:02x?}");
}
