# Tasks: Enrollment ui

> feature: enrollment-ui

## T-060 — Status query on both daemons [pending]

- Refs: AC-056, AC-057
- Files: crates/openhellod/src/dbus_service.rs, crates/openhellod/src/core.rs, crates/openhello-keyd/src/dbus_service.rs, crates/openhello-cli/src/dbus_client.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: `GetStatus(uid)` on `io.openhello.Biometrics1` (face enrolled) and `io.openhello.Keyd1` (key, PIN). No polkit for the caller's own uid.

## T-061 — Typed failure causes over D-Bus [pending]

- Refs: AC-069
- Files: crates/openhellod/src/backends.rs, crates/openhellod/src/dbus_service.rs, crates/openhello-cli/src/dbus_client.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: distinct D-Bus error names for camera busy, stuck stream, no camera and TPM unavailable; detail stays in the journal.

## T-062 — Owner-only preview frame over a memory file descriptor [pending]

- Refs: AC-063, AC-064
- Files: crates/openhellod/src/dbus_service.rs, crates/openhellod/src/core.rs, crates/openhellod/io.openhello.Biometrics1.policy, crates/openhellod/tests/dbus_service.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-061. `EnrollFrame(handle)` returns a sealed read-only memfd; new polkit action implied by `enroll-begin`; explicit, narrow exception to the no-image-bytes test (P-003, P-010 stay intact).

## T-063 — GUI core: wizard state machine and wording [pending]

- Refs: AC-058, AC-059, AC-060, AC-061, AC-062
- Files: crates/openhello-gui-core/Cargo.toml, crates/openhello-gui-core/src/lib.rs, crates/openhello-gui-core/src/wizard.rs, crates/openhello-gui-core/src/strings.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-060, T-062. No GTK: pure logic and a client trait, fully testable headless.

## T-064 — GUI core: daemon client, test and remove [pending]

- Refs: AC-065, AC-066
- Files: crates/openhello-gui-core/src/client.rs, crates/openhello-gui-core/src/manage.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-063. Reuses the existing D-Bus client from `openhello-cli`.

## T-065 — GTK 4 / libadwaita shell [pending]

- Refs: AC-058, AC-059, AC-062
- Files: crates/openhello-gui/Cargo.toml, crates/openhello-gui/src/main.rs, crates/openhello-gui/src/window.rs, crates/openhello-gui/src/capture_view.rs, Cargo.toml
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-064. Excluded from `default-members` so `cargo test` needs no GTK; oval guide and progress ring drawn over the preview.

## T-066 — Desktop entry and optional installer step [pending]

- Refs: AC-067, AC-068
- Files: packaging/openhello.desktop, scripts/install.sh
- Model: claude-sonnet-5
- Effort: low
- Notes: depends on T-065. Settings category entry; the installer skips the app, with a clear message, when GTK 4 or libadwaita is missing.
