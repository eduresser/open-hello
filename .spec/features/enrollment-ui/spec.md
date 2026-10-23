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
- **Then** the app shows, in order: welcome, identity check (system password prompt), PIN creation only if no PIN exists, capture, recovery code, and a final "All set" screen with a Close button

#### AC-059 — The capture screen shows the preview, the guidance and the progress

- **Given** the capture step is active
- **When** frames arrive from the daemon
- **Then** the window shows the live camera image, one guidance sentence for the latest verdict, and "n of 6" progress that grows with each accepted sample

#### AC-060 — Every verdict has a sentence in English

- **Given** the interface (English only for now)
- **When** the daemon reports any enrollment verdict (accepted, too-soon, no-face, move-left, move-right, move-up, move-down, too-close, too-far, too-dark, too-bright, yaw-out-of-range, blurred, occluded)
- **Then** the capture screen shows the sentence for that verdict, taken from the Windows Hello wording where one exists

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

#### AC-068 — The installer degrades without GTK

- **Given** the machine lacks the GTK 4 and libadwaita development libraries
- **When** the installer runs
- **Then** it installs everything else, tells the user the app was skipped and which packages it needs, and the CLI keeps working

#### AC-069 — The daemon tells the client the cause of a failure

- **Given** an enrollment or recognition fails
- **When** the cause is a busy camera, a stuck infrared stream, a missing camera or an unavailable TPM
- **Then** the D-Bus error carries a distinct cause the client can show, while the journal keeps the detail

## Out of scope

- "Improve recognition" (adding a second recognition profile): see Q-004.
- A page inside KDE System Settings or GNOME Settings (an optional thin layer later).
- Flatpak packaging, display-manager greeter, fingerprint, gaze or eyes-open checks.
- Any language other than English (the interface is English only for now).

## Assumptions

| ID | Assumption | Status | Resolution |
|---|---|---|---|
| ASM-020 | A GTK 4 + libadwaita app in Rust, talking to the daemons over the D-Bus system bus, is acceptable on any desktop; it looks foreign on KDE but needs no per-desktop code. | open | Recommended by the toolkit research (2026-10-23); confirm on the KDE neon VM. |
| ASM-021 | One 640x360 8-bit grayscale frame per call, handed over as a sealed memory file descriptor in a method reply, is fast enough for a smooth preview. | open | Method replies carry descriptors reliably; signals do not. Measure on the VM. |
| ASM-022 | The wizard wording reuses the Windows Hello strings extracted from `BioEnrollment` (English wording only for now). | confirmed | Extracted 2026-10-23 from the local Windows install; used for wording only. |
| ASM-023 | GTK 4 and libadwaita development packages are installable on the VM (Ubuntu noble ships libadwaita 1.5). | open | Check with the package manager before the GUI task starts. |

## Open questions

| ID | Question | Status | Answer |
|---|---|---|---|
| Q-004 | What does "Improve recognition" do here? Adding embeddings to a template makes the FAR split stricter (target FAR is divided by the number of embeddings). | open | — |
| Q-005 | Is the preview allowed despite the rule that the daemon returns no image data? | answered | Yes, restricted: owner only, active enrollment, polkit, never logged (product owner, 2026-10-23). |
