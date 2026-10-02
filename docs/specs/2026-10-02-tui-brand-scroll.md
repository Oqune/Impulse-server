# TUI palette and log viewport — 2026-10-02

Owner request: apply Impulse blue palette to Rust host, audit advertised functionality and ensure log scrolling works. Android dynamic/tertiary colour system remains unchanged. Wire and crypto remain unchanged.

Plan: use centralized cobalt/graphite truecolour theme, retain distinct semantic severity colours; correct bottom-relative scrolling; account for wrapped rows; search only visible severity levels; add visible scrollbar and LIVE/PAUSED/HISTORY log state. Test keyboard/wheel scroll state, search/filter interaction, wrapped rendering and responsive sizes. Run cargo build, cargo test, cargo clippy. Report which checks are component tests versus real network/device validation.

Acceptance: Up and wheel-up reveal older rows, Down and End return toward latest rows, Home reaches beginning. Wrapped logs remain reachable. Search jumps to a visible match. Empty and tiny viewports do not panic. Palette does not colour warnings/errors blue. No payload inspection or protocol changes.

Implementation: completed. Additional review fixes: bounded log ingress, terminal cleanup on errors, startup acknowledgement errors, nine-row server information panel and fixed-height certificate panel so QR gets the remaining space. Validation: cargo build --locked; cargo test --locked (126 passed, 2 intentionally ignored); cargo clippy --locked --all-targets -- -D warnings. Windows linker prints an informational library-creation warning during linking; clippy reports no code warnings. Full scope/limits in the dated audit report.
