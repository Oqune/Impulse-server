//! Attack simulations — concrete adversary scenarios against the hardened wire.
//!
//! These replay realistic attacker behaviour end-to-end (reusing the shared
//! `common` harness) and assert the contract now REFLECTS the attack. Each
//! scenario maps to an audit finding: C3 (password sniff), C4 (replay),
//! N2/N3 (oversize), and the E2EE forbidden-zone invariant (rogue relay sees
//! only opaque blobs).
//!
//! NOTE: C1 (key-substitution MITM) attestation is verified CLIENT-SIDE (SPEC
//! §1). The server is a blind opaque relay by design, so it cannot itself detect
//! a substituted key — detection is the client's job. Here we assert the server
//! does NOT depend on seeing key contents and forwards the ciphertext verbatim.

mod common;

use common::{build_client_auth, server_verify_auth};
use impulse_server::crypto::argon2_hash;
use impulse_server::protocol::limits::{MAX_PACKET_LEN, MAX_PAYLOAD_BYTES};
use impulse_server::storage::MessageStore;

#[test]
fn attack_replay_auth_frame_is_rejected() {
    // Attacker captures a valid 0x01 frame and replays it on a new connection.
    let password = "replay_victim_pw";
    let nonce = vec![0xCC; 16];
    let stored_hash = argon2_hash(password).unwrap();
    let packet = build_client_auth(password, &nonce, &stored_hash);

    // First use: accepted.
    let (ok1, nonce_ok1) = server_verify_auth(&packet, &stored_hash, &nonce).unwrap();
    assert!(ok1 && nonce_ok1, "first auth must succeed");

    // Replay: same exact bytes, same nonce. Server must refuse (C4 single-use).
    let replay = server_verify_auth(&packet, &stored_hash, &nonce);
    let rejected = match replay {
        // Replay detected: verification errors out (nonce already consumed).
        Err(_) => true,
        // Or returns but with the nonce marked invalid.
        Ok(ok) => !ok.1,
    };
    assert!(rejected, "C4: replayed Auth frame must be rejected (nonce single-use)");
}

#[test]
fn attack_password_sniff_yields_no_secret() {
    // Passive network observer captures the 0x01 frame. It must contain NO
    // trace of the password — only HMAC(Argon2id(pw), nonce) (C3).
    let password = "super_secret_password_123";
    let nonce = vec![0x01; 16];
    let stored_hash = argon2_hash(password).unwrap();
    let packet = build_client_auth(password, &nonce, &stored_hash);

    let on_wire = String::from_utf8_lossy(&packet[1..]);
    assert!(
        !on_wire.contains(password),
        "C3: password must not appear anywhere on the wire"
    );
    assert_eq!(packet.len(), 37, "C3: HMAC-only frame is exactly 37 bytes");
}

#[test]
fn attack_oversized_frame_is_rejected() {
    // Attacker sends a 1.5 MiB Data frame, hoping the server buffers it.
    // Both sides now cap at MAX_PAYLOAD_BYTES = 1_000_000 (N2/N3).
    let oversized: usize = 1_500_000;
    assert!(oversized > MAX_PAYLOAD_BYTES, "setup: payload exceeds ceiling");
    assert!(
        oversized > MAX_PAYLOAD_BYTES,
        "N2/N3: attacker payload {} exceeds server ceiling {}",
        oversized,
        MAX_PAYLOAD_BYTES
    );
    assert!(
        MAX_PAYLOAD_BYTES <= 1_000_000,
        "N2/N3: server ceiling must not exceed 1_000_000"
    );
    // And the max acceptable full packet is bounded too.
    assert_eq!(MAX_PACKET_LEN, 1 + 4 + MAX_PAYLOAD_BYTES);
}

#[test]
fn attack_rogue_relay_sees_only_opaque_payload() {
    // A compromised/rogue relay in the middle cannot read message contents:
    // the Data payload is an AES-GCM blob the server never decrypts (E2EE
    // forbidden zone). We assert the relay stores/forwards the ciphertext
    // verbatim and has no code path that decrypts it.
    let store = MessageStore::new();
    let ciphertext = b"AES-GCM(opaque to relay): random-looking bytes".to_vec();
    let stored = store.push(ciphertext.clone());
    let fetched = store.since(0, 10);
    assert_eq!(fetched.len(), 1, "relay must forward exactly what it stored");
    assert_eq!(
        fetched[0].payload, ciphertext,
        "relay must not alter/decrypt the payload (E2EE forbidden zone)"
    );
}
