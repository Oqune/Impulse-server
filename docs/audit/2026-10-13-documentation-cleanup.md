# Documentation cleanup — 2026-10-13

## Changes made

- Added implementation-alignment scope and validation criteria in `docs/specs/2026-10-13-project-docs-alignment.md`.
- Updated root `AGENTS.md` to describe the research prototype and opaque-relay metadata boundary, require no weakening of Argon2id/ML-KEM/AES/signature verification, identify current Dilithium3 signature API, and record current component versions.
- Updated `client/AGENTS.md` to name Dilithium3 as the current signature implementation and keep verification mandatory; current client version is v3.2.0.
- Updated `server/AGENTS.md` to state the 72-hour server TTL, distinguish opaque message bodies from visible metadata, and record current server version v3.1.0.
- Updated root `docs/policies/policies.md` and its `client/docs/policies/policies.md` / `server/docs/policies/policies.md` mirrors: preserved Protocol-Locked SemVer and synchronized-change rule, replaced universal v3 pair compatibility guarantee with a verification-matrix requirement, corrected current signature/privacy/prototype descriptions, and documented allowed log metadata without claiming only lengths/opcodes are logged.
- Updated `docs/policies/release.md` and its `client/docs/policies/release.md` mirror with current client `versionCode=23`, `versionName=3.2.0`, server v3.1.0, and matrix-based compatibility wording. Other release steps were retained for owner review.
- Changed only the signature terminology/example in `docs/policies/ai_engineering.md`, then synchronized the file to client/server policy mirrors. The requirement to verify every signature was preserved.
- Updated `docs/SYSTEM_REGISTRY.md` to current date and code-level references; clarified client TTL as database cleanup, bounded network reachability claims, corrected server/client Data frame descriptions, named current Dilithium3 API, and limited Android Keystore hardware claims to the AES master key. Synchronized the registry to `client/docs/SYSTEM_REGISTRY.md` and `server/docs/SYSTEM_REGISTRY.md`.
- Updated current `PROJECT.md` protocol compatibility wording and C1 status language. SEC-BCK remains closed: backup export and v4 restore use Argon2id `m=47104 KiB, t=3, p=1`; restore for legacy v1–v3 backups retains PBKDF2-HMAC-SHA256 at 600,000 iterations. The earlier audit statement that export used PBKDF2 was incorrect; code inspection confirms `exportKeyBackup` calls `argon2DeriveKey`, while PBKDF2 is only on the legacy restore path. No backup code or format was changed.

## No change

- No project-local `SKILL.md` files were found in the earlier audit. No global user skills were read or edited.
- Original school DOCX files, authored video sources, code, `Cargo.toml`, README files, historical audits/specifications, releases, tags, and git state were not changed by this cleanup.
- No build or test command was run. The scope is documentation only.

## Root/mirror synchronization

The root `docs/policies/policies.md`, `docs/policies/ai_engineering.md`, and `docs/SYSTEM_REGISTRY.md` are copied into their client/server mirror locations. The client release policy mirrors root `docs/policies/release.md`. Root, client, and server AGENTS remain component-specific documents and were edited individually.

## Items for owner review

- Correct the stale top-level comment in `SecureKeyManager.kt` that describes backup export with PBKDF2; leave backup code unchanged in this documentation cleanup.
- Build an explicit supported client/server release-pair compatibility matrix before claiming every Protocol v3 pair is compatible.
- Release workflow steps in `release.md` were not revalidated or rewritten in this cleanup.
