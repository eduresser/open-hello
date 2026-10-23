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
- Files: crates/openhello-gui/Cargo.toml, crates/openhello-gui/build.rs, crates/openhello-gui/LICENSE, crates/openhello-gui/src/main.rs, crates/openhello-gui/src/backend.rs, crates/openhello-gui/src/capture.rs, crates/openhello-gui/src/demo.rs, crates/openhello-gui/src/options.rs, crates/openhello-gui/src/stats.rs, crates/openhello-gui/src/view.rs, crates/openhello-gui/ui/app.slint, crates/openhello-gui/ui/components.slint, crates/openhello-gui/ui/texts.slint, crates/openhello-gui/ui/welcome.slint, crates/openhello-gui/ui/identity.slint, crates/openhello-gui/ui/capture.slint, crates/openhello-gui/ui/done.slint, crates/openhello-gui/ui/error.slint, crates/openhello-gui/ui/manage.slint, Cargo.toml
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

## T-073 — No PIN and no recovery code in the window or the CLI [done]
- Refs: AC-058, AC-031, ASM-024
- Files: crates/openhello-gui-core/src/wizard.rs, crates/openhello-gui-core/src/strings.rs, crates/openhello-gui-core/tests/wizard.rs, crates/openhello-gui-core/tests/common/mod.rs, crates/openhello-gui/src/backend.rs, crates/openhello-gui/src/view.rs, crates/openhello-gui/src/demo.rs, crates/openhello-gui/src/main.rs, crates/openhello-gui/ui/app.slint, crates/openhello-gui/ui/texts.slint, crates/openhello-cli/src/lib.rs, crates/openhello-cli/src/keyd_client.rs, crates/openhello-cli/src/main.rs, crates/openhello-cli/tests/provisioning_flow.rs, crates/openhello-cli/tests/end_to_end.rs, README.md
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-072. Product owner decision 2026-10-23: the order is welcome, identity, capture, done; the key is provisioned right after the commit only when it does not exist, and the returned recovery code is discarded at once; the CLI has no `set-pin` and `enroll` and `provision` print no code; exit code 4 stays for a provisioning failure; `ui/recovery.slint` and the CLI `terminal.rs` are deleted (T-069 no longer lists the screen). The key service keeps the PIN and recovery protectors in its D-Bus API.

## T-074 — Face data removal on the welcome and error screens [done]
- Refs: AC-071, AC-066
- Files: crates/openhello-gui-core/src/wizard.rs, crates/openhello-gui-core/src/strings.rs, crates/openhello-gui-core/tests/wizard.rs, crates/openhello-gui-core/tests/common/mod.rs, crates/openhello-gui/src/backend.rs, crates/openhello-gui/src/view.rs, crates/openhello-gui/ui/app.slint, crates/openhello-gui/ui/components.slint, crates/openhello-gui/ui/confirm.slint, crates/openhello-gui/ui/manage.slint, crates/openhello-gui/ui/welcome.slint, crates/openhello-gui/ui/error.slint, crates/openhello-gui/ui/texts.slint
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-073. Product owner request 2026-10-23: a discreet "Remove face data" link on the welcome screen (only when the status says a face is set up) and on every error screen, opening the same confirmation overlay as the Manage page (now shared in `confirm.slint`); the purge needs no camera; on success the flow resets and starts again, on failure the error screen shows the cause and keeps the link.

## T-075 — Main screen, Test and Set up again, test results shown in place [done]
- Refs: AC-058, AC-065, AC-066, AC-070, AC-071, AC-072, AC-073, AC-074
- Files: crates/openhello-gui-core/src/wizard.rs, crates/openhello-gui-core/src/strings.rs, crates/openhello-gui-core/tests/strings.rs, crates/openhello-gui-core/tests/manage.rs, crates/openhello-gui-core/tests/wizard.rs, crates/openhello-gui/src/backend.rs, crates/openhello-gui/src/view.rs, crates/openhello-gui/src/main.rs, crates/openhello-gui/src/demo.rs, crates/openhello-gui/src/options.rs, crates/openhello-gui/ui/app.slint, crates/openhello-gui/ui/components.slint, crates/openhello-gui/ui/texts.slint, crates/openhello-gui/ui/done.slint, crates/openhello-gui/ui/manage.slint, crates/openhello-gui/ui/welcome.slint, crates/openhello-gui/ui/confirm.slint, crates/openhello-gui/ui/error.slint
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-074. Product owner decision 2026-10-23: three states (welcome without a face with a single Set up button; main screen with a face with Test, Set up again and Delete face data; screen after setup with Test and Set up again); no Close button; a test always returns to the main screen with the result at its top (never a full-screen error); the main screen opens with the cause and Test and Set up again disabled when recognition is unavailable, Delete stays; Set up again goes straight to the identity step; "Remove" becomes "Delete" in every text; the welcome screen no longer offers deletion. Demo flags: `--demo-test` cycles recognized, not recognized and camera in use; `--demo-enrolled` opens the main screen; with `--demo-blocked` it opens blocked.

## T-076 — Camera diagnostics and a bounded stream restart [done]
- Refs: AC-075, AC-011, AC-015
- Files: crates/sensor-adapter-ir/src/session_log.rs, crates/sensor-adapter-ir/src/lazy.rs, crates/sensor-adapter-ir/src/lib.rs, crates/sensor-adapter-ir/src/v4l2_capture.rs, crates/openhellod/src/core.rs, crates/openhellod/tests/logging_redaction.rs, .spec/features/face-recognition-proof/spec.md
- Model: claude-sonnet-5
- Effort: high
- Notes: VM kde-neon 2026-10-23: right after a window enrollment, Test (`Verify`) failed 3 of 3 for about 40 s with "camera keeps delivering incomplete frames" (kernel: xhci short packet), then recovered alone; cause not confirmed. Diagnostics: the error now carries the count and the last bytesused/flags, and the sensor plugin logs `camera-open`, `camera-open-failed` and `camera-release` lines (reason, since_release_ms, open_ms, good_frames); the daemon logs `sensor-release reason=`. Mitigation: only the incomplete-frames start failure reopens the session, up to 2 times with 500 ms and 1500 ms pauses (injectable); everything else fails at once.

## T-077 — First click handling and input trace [done]
- Refs: AC-076, AC-058, AC-062
- Files: crates/openhello-gui/Cargo.toml, crates/openhello-gui/src/main.rs, crates/openhello-gui/src/gate.rs, crates/openhello-gui/src/trace.rs, crates/openhello-gui/src/options.rs, crates/openhello-gui/src/view.rs, crates/openhello-gui/src/backend.rs, crates/openhello-gui/ui/app.slint, crates/openhello-gui/ui/welcome.slint, crates/openhello-gui/ui/error.slint, crates/openhello-gui/ui/capture.slint, README.md
- Model: claude-sonnet-5
- Effort: high
- Notes: owner report 2026-10-23, KDE Plasma Wayland: the first click on Set up, Cancel and Test sometimes does nothing, unpredictable. Slint 1.18.1 and winit 0.30.13 do not drop a press on an unfocused window (the press uses the last CursorMoved position and Wayland sends one on enter), so no focus workaround is added. Set up, Try again and Cancel now share the busy guard of the other buttons (immediate disabled feedback, repeats ignored); `--trace-input` (feature `unstable-winit-030`, API only) prints the timeline to stderr. Real behavior depends on the compositor and is confirmed only on the VM.
