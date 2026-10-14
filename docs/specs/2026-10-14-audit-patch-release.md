# Audit patch release and publication

Owner authorized reviewed fixes, atomic Conventional Commits and final GitHub push. Code changes preserve Wire v3 and existing cryptographic algorithms and minimum parameters. Patch candidates: Client 3.2.1 (versionCode 24) and Server 3.1.1.

Before publishing: final local build/test/lint/clippy gates, live emulator functional/negative checks against the final relay, bounded stability run, root review of all diffs, separate audit/change register and school-project DOCX. Unverified architectures and operational limitations remain explicit. No production-ready or certification claim is permitted solely from these gates.

Keep release notes bilingual, emoji-free, with architecture tables and direct artifact links. Build locally signed Android artifacts using the existing configured signing mechanism without exposing keystore/passwords. Verify signatures and actual release-mode execution. Publish only verified local artifacts or successfully completed CI artifacts. Do not invent download URLs for absent assets or republish prior-version binaries under a new version.

Use fix branches and atomic signed commits according to existing Git settings. Push reviewed changes, open/attach PRs, verify available CI and merge only after required gates. Tags v3.2.1/v3.1.1 target the reviewed revisions after acceptance. Existing tags/releases and source school/video files remain untouched.

Current CI auto-generates release prose without the required architecture/English-Russian contract. Route tag releases to the committed docs/releases/<tag>.md, explicitly fail if mandatory notes are missing, and check out the tagged revision in release jobs. Cross-platform CI compilation is packaging evidence, not device/platform runtime testing. If a gate/platform blocks release, push the reviewed branch with a concrete report and leave the blocked release unpublished.
