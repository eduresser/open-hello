# Spec: Enrollment UI

> feature: enrollment-ui
> status: draft

## Context

The owner of an OpenHello laptop can enroll, test and remove their face only from the `openhello-cli` terminal; this feature adds a graphical wizard, like the Windows Hello "Set up" flow, with a live camera preview and plain guidance, on any distribution and desktop.

## Stories

### US-019 — Know whether a face is set up

As a laptop owner, I want to see whether my face, my PIN and my login key are set up, so that I know what is missing before I try to sign in.

#### AC-056 — The status reports what is set up

- **Given** a user with no enrolled face
- **When** the client asks for the user's status
- **Then** it reports face not set up, and PIN and login key set up or not according to the key service (`GetStatus` on both daemons)

#### AC-057 — The status follows enrollment and removal

- **Given** the status says the face is not set up
- **When** the user enrolls and the enrollment commits, and later removes the face
- **Then** the status reports the face set up after the commit and not set up after the removal

### US-020 — Guided enrollment

As a laptop owner, I want a step-by-step window that shows me the camera and tells me how to position myself, so that I can enroll my face without the terminal.

#### AC-058 — The wizard follows the Windows Hello order

- **Given** the user opens the app with no face set up
- **When** they press "Get started" and complete each step
- **Then** the app shows, in order: welcome, identity check (system password prompt), capture, and a final "All set" screen with a Close button; when the login key does not exist yet it is created right after the enrollment commits, and the app never asks for, creates or shows a PIN or a recovery code

#### AC-059 — The capture screen shows the preview, the guidance and the progress

- **Given** the capture step is active
- **When** frames arrive from the daemon
- **Then** the window shows the live camera image, one guidance sentence for the latest verdict, and a progress ring around the guide oval that grows with each accepted sample, with no sample counts

#### AC-060 — Every verdict has a sentence in English

- **Given** the interface (English only for now)
- **When** the daemon reports any enrollment verdict (accepted, too-soon, no-face, move-left, move-right, move-up, move-down, too-close, too-far, too-dark, too-bright, yaw-out-of-range, blurred, occluded)
- **Then** the capture screen shows a short sentence written for OpenHello for that verdict (the Windows Hello wording is not copied)

#### AC-061 — Enrollment failures explain what to do

- **Given** the capture step is active
- **When** the 20-second window ends, the camera is busy, or the sensor reports a stuck infrared stream
- **Then** the app shows an error screen with a plain explanation (for a stuck stream: power the computer off completely) and a Try again button, and no template is stored

#### AC-062 — Closing the window discards the enrollment

- **Given** the capture step is active
- **When** the user presses Cancel or closes the window
- **Then** the enrollment session is discarded, the camera is released and no template is stored

### US-021 — Preview for the owner only

As a laptop owner, I want the live image to reach only my own enrollment window, so that the camera image never leaks to other programs or the logs.

#### AC-063 — The preview goes only to the owner of an active enrollment

- **Given** an enrollment session started by a user
- **When** that user asks for the preview frame of the session
- **Then** the daemon returns a read-only memory file descriptor with the latest frame, and refuses the same request from another user, for an unknown or finished session, or without the polkit authorization (`EnrollFrame`, the one method allowed to return image data)

#### AC-064 — No other method returns image data and no frame is logged

- **Given** the daemon is running with debug logging
- **When** an enrollment with preview completes
- **Then** every other D-Bus method still returns no image, embedding or template bytes, and the logs and journal contain no frame bytes (principle P-010)

### US-022 — Manage the face

As a laptop owner, I want to test and remove my face from the same app, so that I do not need the terminal.

#### AC-065 — Test recognition from the app

- **Given** a user with a face set up
- **When** they press "Test" and look at the camera
- **Then** the app shows "recognized" or "not recognized" and releases the camera

#### AC-066 — Removing the face asks for confirmation and reauthentication

- **Given** a user with a face set up
- **When** they press "Remove" and confirm
- **Then** the system asks for the password again, the face and key are erased, and the app shows the face as not set up

### US-023 — Reach the app from any desktop

As a laptop owner on any distribution and desktop, I want to find the app in the application menu and settings, so that I do not depend on one desktop environment.

#### AC-067 — A desktop entry opens the app

- **Given** the package is installed
- **When** the user searches for "Face recognition" in the menu or settings of any desktop that follows the freedesktop standard
- **Then** an entry in the Settings category launches the app (valid `.desktop` file whose `Exec` resolves)

#### AC-068 — The installer builds the window when fontconfig and FreeType headers exist

- **Given** the machine has the Rust toolchain the installer already requires
- **When** the installer runs
- **Then** it builds and installs the window if the fontconfig and FreeType development files are present; if they are missing it installs everything else, says the window was skipped, names the two packages for the detected distribution, and the CLI keeps working

#### AC-069 — The daemon tells the client the cause of a failure

- **Given** an enrollment or recognition fails
- **When** the cause is a busy camera, a stuck infrared stream, a missing camera or an unavailable TPM
- **Then** the D-Bus error carries a distinct cause the client can show, while the journal keeps the detail

### US-024 — Enrollment only where recognition works

As a laptop owner, I want the app to refuse to enroll when face recognition cannot work on this computer, so that I am never led into a setup that cannot sign me in.

#### AC-070 — Enrollment is blocked when recognition is unavailable

- **Given** the daemon reports that the camera is missing or busy, or that the TPM is unavailable
- **When** the user opens the app
- **Then** the welcome screen explains the cause in plain words, its Get started button is disabled, no enrollment session is created, and no PIN or other alternative is offered (the system password remains the sign-in fallback)

## Out of scope

- Creating or showing a PIN or a recovery code in the app or in `openhello-cli` (both protectors stay in the `openhello-keyd` D-Bus API for future integrations).

- "Improve recognition" (adding a second recognition profile): see Q-004.
- A page inside KDE System Settings or GNOME Settings (an optional thin layer later).
- Flatpak packaging, display-manager greeter, fingerprint, gaze or eyes-open checks.
- Any language other than English (the interface is English only for now).

## Decisions

- Product owner decision 2026-10-23: neither a PIN nor a recovery code is created, shown or printed by the window or the CLI; the key service keeps both protectors in its D-Bus API.

## Assumptions

| ID | Assumption | Status | Resolution |
|---|---|---|---|
| ASM-020 | A Slint app (winit backend, fluent style, GPL-3.0-only crate) talking to the daemons over the D-Bus system bus is acceptable on any desktop; it has its own look, identical everywhere, and follows only the system light/dark setting. | confirmed | Chosen by the product owner on 2026-10-23 after comparing a Slint prototype (30 fps preview at about 7% of one core, 23 MB stripped binary, only runtime libraries to run; building it needs the fontconfig and FreeType development files, which the prototype build had only because the GTK packages had pulled them in) with the GTK build. The window crate is GPL-3.0-only; the rest of the project stays Apache-2.0. |
| ASM-021 | One 640x360 8-bit grayscale frame per call, handed over as a sealed memory file descriptor in a method reply, is fast enough for a smooth preview. | open | Method replies carry descriptors reliably; signals do not. Measure on the VM. |
| ASM-022 | The wizard wording is original, written for OpenHello: short, direct, no marketing phrases; the Windows Hello strings were consulted only to learn which situations need a message. | confirmed | Product owner decision, 2026-10-23: do not copy the Windows Hello text. |
| ASM-023 | GTK 4 and libadwaita development packages are installable on the VM. | invalidated | The window no longer uses GTK. |
| ASM-024 | The app and the CLI offer no PIN and show no recovery code: the system password remains the fallback at sign-in and the TPM key can be recreated with `purge` and a new enrollment. | confirmed | Product owner decision, 2026-10-23: when recognition is unavailable the app blocks enrollment instead of offering a PIN; on a personal desktop nothing is encrypted with the key, so the recovery code has no use and is discarded. |

## Open questions

| ID | Question | Status | Answer |
|---|---|---|---|
| Q-004 | What does "Improve recognition" do here? Adding embeddings to a template makes the FAR split stricter (target FAR is divided by the number of embeddings). | open | — |
| Q-005 | Is the preview allowed despite the rule that the daemon returns no image data? | answered | Yes, restricted: owner only, active enrollment, polkit, never logged (product owner, 2026-10-23). |
