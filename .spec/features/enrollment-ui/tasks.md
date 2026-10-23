# Tasks: Enrollment ui

> feature: enrollment-ui

## T-060 — Status query on both daemons [done]
- Refs: AC-056, AC-057
- Files: crates/openhellod/src/dbus_service.rs, crates/openhellod/src/core.rs, crates/openhello-keyd/src/dbus_service.rs, crates/openhello-cli/src/dbus_client.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: `GetStatus(uid)` on `io.openhello.Biometrics1` (face enrolled) and `io.openhello.Keyd1` (key, PIN). No polkit for the caller's own uid.

## T-061 — Typed failure causes over D-Bus [done]
- Refs: AC-069
- Files: crates/openhellod/src/backends.rs, crates/openhellod/src/dbus_service.rs, crates/openhello-cli/src/dbus_client.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: distinct D-Bus error names for camera busy, stuck stream, no camera and TPM unavailable; detail stays in the journal.

## T-062 — Owner-only preview frame over a memory file descriptor [done]
- Refs: AC-063, AC-064
- Files: crates/openhellod/src/dbus_service.rs, crates/openhellod/src/core.rs, crates/openhellod/io.openhello.Biometrics1.policy, crates/openhellod/tests/dbus_service.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-061. `EnrollFrame(handle)` returns a sealed read-only memfd; new polkit action implied by `enroll-begin`; explicit, narrow exception to the no-image-bytes test (P-003, P-010 stay intact).

## T-063 — GUI core: wizard state machine and wording [done]
- Refs: AC-058, AC-059, AC-060, AC-061, AC-062
- Files: crates/openhello-gui-core/Cargo.toml, crates/openhello-gui-core/src/lib.rs, crates/openhello-gui-core/src/wizard.rs, crates/openhello-gui-core/src/strings.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-060, T-062. No GTK: pure logic and a client trait, fully testable headless.

## T-064 — GUI core: daemon client, test and remove [done]
- Refs: AC-065, AC-066
- Files: crates/openhello-gui-core/src/client.rs, crates/openhello-gui-core/src/manage.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-063. Reuses the existing D-Bus client from `openhello-cli`.

## T-065 — GTK 4 / libadwaita shell [done]
- Refs: AC-058, AC-059, AC-062
- Files: crates/openhello-gui/Cargo.toml, crates/openhello-gui/src/main.rs, Cargo.toml
- Model: claude-sonnet-5
- Effort: high
- Notes: superseded by T-069 (GTK shell removed; see git history f68e6a3). Was excluded from `default-members` so `cargo test` needs no GTK; oval guide and progress ring drawn over the preview.

## T-066 — Desktop entry and installer step [done]
- Refs: AC-067, AC-068
- Files: packaging/openhello.desktop, scripts/install.sh
- Model: claude-sonnet-5
- Effort: low
- Notes: depends on T-069. Settings category entry; the installer builds the window with cargo when `pkg-config` finds fontconfig and freetype2; otherwise it skips the window and names the packages (fontconfig-devel and freetype2-devel on openSUSE/Fedora, libfontconfig-dev and libfreetype-dev on Debian/Ubuntu, fontconfig and freetype2 on Arch).

## T-067 — Remove the PIN step from the wizard [done]
- Refs: AC-058, AC-060, ASM-024
- Files: crates/openhello-gui-core/src/wizard.rs, crates/openhello-gui-core/src/strings.rs, crates/openhello-gui-core/src/client.rs, crates/openhello-gui-core/tests/wizard.rs, crates/openhello-gui-core/tests/strings.rs, crates/openhello-gui-core/tests/common/mod.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: no Pin step, no PinError, no set_pin on the client trait; the order is welcome, identity, capture, recovery code (only when the key was created now), done. The GTK crate keeps compiling only until T-069 replaces it.

## T-068 — Block enrollment when recognition is unavailable [done]
- Refs: AC-070, AC-069
- Files: crates/openhellod/src/dbus_service.rs, crates/openhellod/src/core.rs, crates/openhello-gui-core/src/wizard.rs, crates/openhello-gui-core/src/client.rs, crates/openhello-gui-core/src/strings.rs, crates/openhello-gui-core/tests/wizard.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-067. A readiness check the window runs before the welcome screen enables Get started; it reports the typed causes of T-061 without turning on the camera.

## T-069 — Slint shell replaces the GTK shell [done]
- Refs: AC-058, AC-059, AC-062, AC-065, AC-066, AC-070, ASM-020
- Files: crates/openhello-gui/Cargo.toml, crates/openhello-gui/build.rs, crates/openhello-gui/LICENSE, crates/openhello-gui/src/main.rs, crates/openhello-gui/src/backend.rs, crates/openhello-gui/src/capture.rs, crates/openhello-gui/src/demo.rs, crates/openhello-gui/src/options.rs, crates/openhello-gui/src/stats.rs, crates/openhello-gui/src/view.rs, crates/openhello-gui/ui/app.slint, crates/openhello-gui/ui/components.slint, crates/openhello-gui/ui/texts.slint, crates/openhello-gui/ui/welcome.slint, crates/openhello-gui/ui/identity.slint, crates/openhello-gui/ui/capture.slint, crates/openhello-gui/ui/recovery.slint, crates/openhello-gui/ui/done.slint, crates/openhello-gui/ui/error.slint, crates/openhello-gui/ui/manage.slint, Cargo.toml
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-068. Built from the Slint prototype; the GTK sources are removed; the crate is GPL-3.0-only; T-065 is marked superseded.

## T-070 — Independent size and position fit at enrollment [done]
- Refs: AC-050, AC-051, AC-052, ASM-018
- Files: crates/engine-adapter-face/src/enrollment_quality.rs, crates/engine-adapter-face/src/ffi.rs, crates/openhello-gui/ui/capture.slint, README.md
- Model: claude-sonnet-5
- Effort: medium
- Notes: ideal crop centered with face height 55% of the frame (raised to 62% by T-072); independent indicators, size within 13% of the ideal and center distance within 10% of the frame height, both required, size evaluated first; enrollment only, authentication untouched; the values are fixed in code; the window's guide oval matches the ideal height.

## T-071 — Original wording for the window and the CLI [done]
- Refs: AC-060, ASM-022
- Files: crates/openhello-gui-core/src/strings.rs, crates/openhello-gui-core/tests/strings.rs, crates/openhello-cli/src/lib.rs
- Model: claude-sonnet-5
- Effort: low
- Notes: depends on T-070. Replaces the sentences taken from Windows Hello with original ones (a given copy deck), in the window and in the CLI guidance.


## T-072 — Larger face, longer window and no sample counts [done]
- Refs: AC-004, AC-053, AC-059, AC-060, ASM-018
- Files: crates/engine-adapter-face/src/enrollment_quality.rs, crates/openhello-gui-core/src/strings.rs, crates/openhello-gui-core/src/wizard.rs, crates/openhello-gui-core/tests/strings.rs, crates/openhello-gui-core/tests/wizard.rs, crates/openhello-gui/src/capture.rs, crates/openhello-gui/src/view.rs, crates/openhello-gui/src/demo.rs, crates/openhello-gui/ui/app.slint, crates/openhello-gui/ui/capture.slint, crates/openhello-cli/src/lib.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-071. Ideal face height 62% (range 49%-75%), window oval about 62% of the preview, capture window 30 seconds; the user never sees a sample count (the ring in the window, a percentage in the CLI); no distances in centimeters in user sentences.
