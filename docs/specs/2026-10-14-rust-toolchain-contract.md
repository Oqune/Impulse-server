# Rust toolchain contract

The charter's MSRV 1.85 statement conflicts with the locked dependency graph: cargo metadata for the Windows target reports rust-version 1.88.0 for ratatui-core/widgets/backends, tui-qrcode and darling. This dependency requirement existed before this audit; lowering library versions would risk unrelated TUI/API changes.

Declare rust-version 1.88 in Cargo.toml to make the current build requirement explicit and update current canonical documentation. Keep edition 2024 and all dependency versions unchanged. Historical documents remain original; explain the discrepancy in the separate school report.

Validation: build/test/clippy on the installed Rust 1.98.1; independently attempt a locked build with Rust 1.88.0 using a separate audit target directory. Only a completed build establishes that tested target's MSRV compatibility. Metadata alone is a dependency floor, not cross-platform validation.
