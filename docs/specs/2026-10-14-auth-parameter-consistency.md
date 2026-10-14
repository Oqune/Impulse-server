# Auth Hash Parameter Consistency

**Status:** Approved for implementation
**Date:** 2026-10-14

## Problem

The server currently accepts any configured string beginning with `$argon2`, derives its HMAC key from the stored PHC output, but advertises fixed Argon2 parameters (`m=47104,t=3,p=1`) in the authentication challenge. A valid Argon2id hash made with different parameters therefore causes the client and server to derive different authentication keys. Unsupported algorithms, weak work factors, and oversized parameters can also reach runtime without a startup rejection.

## Required behavior

- Validate configured password hashes as Argon2id version 19 (0x13), with exactly 32 output bytes and a decoded salt of at least 16 bytes.
- Accept only `m` in 47104..=65536 KiB, `t` in 3..=6, and `p` in 1..=2. These bounds preserve the existing baseline and the current client-supported upper limits; invalid values must fail configuration/server initialization before accepting sessions.
- Never include any portion of the configured password hash in validation errors or logs.
- Advertise the exact validated `m`, `t`, and `p` values in the existing auth challenge parameter field. Keep the current wire layout unchanged.
- Preserve `encode_auth_challenge(nonce, salt)` as the canonical-parameter helper for existing callers/tests, and add a parameterized helper for the server runtime.
- Use the same validated parameter parser for configuration and session challenge construction, avoiding divergent validation and advertisement.

## Compatibility and security constraints

- No opcode, field, encoding, cryptographic primitive, E2EE behavior, or Wire v3 framing changes.
- Do not lower the current Argon2id minimums. Do not accept other algorithms or versions.
- Valid hashes using non-default parameters within the specified bounds must authenticate consistently because the client receives those exact parameters.

## Verification

- Unit tests cover a valid non-default tuple and the generated challenge tag, canonical-helper compatibility, and rejection of wrong algorithm/version, weak work factors, excessive work factors, short salt, and wrong output length.
- Configuration/startup validation errors must not reveal hash contents.
- Run focused tests plus `cargo build --locked`, `cargo test --locked`, and `cargo clippy --locked --all-targets -- -D warnings` after implementation.
