# kscreenlocker Face authenticator: start condition

Scope: why `kscreenlocker_greet` starts only `kde-fingerprint` and `kde` workers, never `kde-face`.
Source: kscreenlocker tag `v6.8.0` (commit `0cbc96a9`), links below point to that tag.
VM: KDE neon, kscreenlocker 6.8.0-0zneon build70, plasma-desktop 6.8.0 build89. Read-only checks only.
Marks: **[confirmed]** read in source or observed on the VM; **[inferred]** deduced, not executed.

## Summary

`kde-face` is a user-selectable authenticator, not an automatic one. The greeter starts a `kde-face` worker only when
the active authenticator is `Face`, and `Face` exists in the model only if `[Authenticators] Face=true` is set in
`kscreenlockerrc`. The VM has no `kscreenlockerrc` config, so `Face` is not even in the model.

## Exact start condition

1. Build gate: `KSCREENLOCKER_PAM_FACE_SERVICE` must not be `disabled`. Default `kde-face`.
   [CMakeLists.txt L18-21, L31](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/worker/CMakeLists.txt#L18)
   and constexpr check at [pamauthenticatormodel.cpp L37](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticatormodel.cpp#L37).
   **[confirmed]** on VM: the string `kde-face` is in the binary, so the build is not `disabled`.
2. Config gate: `kscreenlockerrc`, group `[Authenticators]`, key `Face=true` (default false). The descriptor is
   enabled only if gate 1 and gate 2 are both true, and disabled descriptors are filtered out of the model.
   [pamauthenticatormodel.cpp L69-75, L86-89](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticatormodel.cpp#L69).
   `KConfig("kscreenlockerrc")` is read from the usual cascade (user `~/.config`, `/etc/xdg`). **[confirmed]**
   No KCM or UI sets this key: grep over `kcm/` finds nothing. **[confirmed]**
3. Selection gate: the active authenticator must be `Face`. `m_authenticator` is initialised from
   `[Greeter] Authenticator=` in the **state** config (`~/.local/state/kscreenlockerrc`), default `Regular`
   ([pamauthenticators.cpp L56-63](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticators.cpp#L56)).
   It is written only after a successful unlock with that authenticator
   ([L65-72, L199-204](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticators.cpp#L65)).
   The other way to select it is the user clicking the Face button in the lock screen. **[confirmed]**
4. Worker start: `onAuthenticatorChanged` builds `PamAuthenticator("kde-face", user, Face)` for `Face`, and its
   constructor spawns `kscreenlocker_worker kde-face <user>`
   ([pamauthenticators.cpp L176-195](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticators.cpp#L176),
   [pamauthenticator.cpp L27-41, L295-311](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticator.cpp#L295)).

Not required: no D-Bus service check, no hardware check, no fprintd dependency, no PAM file existence check in the
greeter. A grep for `Face`/`face` in greeter C++ finds only the model, the factory and the user avatar. **[confirmed]**

## Why the VM shows only `kde-fingerprint` and `kde`

- `kde` worker: the active authenticator is `Regular` (`~/.local/state/kscreenlockerrc` has `[Greeter] Authenticator=Regular`). **[confirmed]**
- `kde-fingerprint` worker: it is the "implicit" fingerprint authenticator, created whenever the active one is not
  Fingerprint, regardless of config or hardware
  ([pamauthenticators.cpp L138-139, L94-97](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticators.cpp#L138)).
  It runs `pam_fprintd` from `/usr/lib/pam.d/kde-fingerprint`, which is why `net.reactivated.Fprint` is activated. **[confirmed]**
- Face: `~/.config/kscreenlockerrc` and `/etc/xdg/kscreenlockerrc` do not exist, so gate 2 fails and the model holds only `Regular`.
  With a single entry the switcher is hidden (`visible: authenticationTypeRepeater.count > 1`,
  `LockScreenUi.qml` L328 on the VM). **[confirmed]**
- Only the missing config explains the observed behaviour. `/etc/pam.d/kde-face` exists and is correct.
  PAM file presence is irrelevant to the start condition. **[confirmed]**

## When the PAM service is missing or fails

- Missing file: `pam_start` still succeeds, and PAM falls back to the `other` service (deny). Result is `PAM_AUTH_ERR`
  (Failure), not Unavailable. **[inferred]** from [worker/main.cpp L262-285, L311-341](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/worker/main.cpp#L288).
- "PAM service is not available. Cannot authenticate." is a debug log in the greeter when `m_unavailable` is already set
  ([pamauthenticator.cpp L94-97](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticator.cpp#L94)).
  It is not a result of the file being absent. **[confirmed]**
- `m_unavailable` is set when the worker returns `Unavailable`: `rc == PAM_AUTHINFO_UNAVAIL || PAM_MODULE_UNKNOWN`
  ([worker/main.cpp L335-339](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/worker/main.cpp#L335)),
  or by the failure counter below. Then `availableChanged` calls `markDefunct`
  ([pamauthenticators.cpp L205-213](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticators.cpp#L205)).
  The Face button turns disabled and red, and the UI shows "This authentication method is not functioning correctly...".
  Defunct lasts until the greeter restarts (next lock). **[confirmed]**
- Hence `pam_openhello` must never return `PAM_AUTHINFO_UNAVAIL` or `PAM_MODULE_UNKNOWN` for a normal miss.
  The current stack `[success=ignore ignore=2 default=ignore]` ... `pam_deny` ends in `PAM_AUTH_ERR`. **[confirmed]**
  (Face-only fast path of `AUTHINFO_UNAVAIL` is special-cased for fingerprint only, L322-333.)

## Failure counter ("more than 3 failures in 2 s")

[pamauthenticator.cpp L113-132](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticator.cpp#L113):
on each Failure, if less than 2 s passed since the previous failure, `m_failedCount++`, and when it exceeds 3 the
authenticator is marked unavailable (defunct). If 2 s or more passed, the counter resets to 0. **[confirmed]**
Consequence: a Face attempt that blocks about 3 to 5 s waiting for the camera never trips it. A module that fails in
under 2 s repeatedly (for example camera busy or absent) trips it on the 5th consecutive failure (counter starts at 0,
increments from the second failure). **[confirmed]** for the logic, **[inferred]** for the exact count.

## Retry loop and blocking

- Greeter side: the D-Bus call timeout is disabled (`setTimeout(INT_MAX)`,
  [pamauthenticator.cpp L320](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticator.cpp#L320)).
  A module blocking 3-5 s only keeps that worker `busy`. Each authenticator has its own worker process, so the UI and
  the other workers are not blocked. `tryUnlock` returns early while busy, so the 1 s heartbeat timer does not stack calls
  (`LockScreenUi.qml` L167-171, [pamauthenticator.cpp L80-82](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticator.cpp#L80)). **[confirmed]**
- Attempts only run while the UI is visible or when the state is started: `startAuthenticating()` is called at authenticator
  change, on `uiVisible` change, by a 1 s timer that runs only while `uiVisible && !unlocked`, and after each failure
  (`LockScreenUi.qml` L57-70, L158-171). With the screen dark and the UI hidden, the first attempt starts at lock time
  (authenticator-change path) and later ones need user activity. **[confirmed]** from source, **[inferred]** for the practical effect.
- After a Failure, the worker applies PAM's fail delay: `fail_delay` callback sleeps in the worker for the requested time
  and tells the greeter (`StartFailedDelay`) ([worker/main.cpp L166-178, L344-350](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/worker/main.cpp#L344)).
  Whether a delay exists depends on a module calling `pam_fail_delay` (pam_unix does; `pam_deny` does not). **[inferred]**
  Add `auth optional pam_faildelay.so delay=2000000` if a hard 2 s spacing is wanted. **[inferred]**

## Messages and prompts from PAM

[worker/main.cpp L182-253](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/worker/main.cpp#L182):
`PAM_TEXT_INFO` becomes `InfoMessage`, `PAM_ERROR_MSG` becomes `ErrorMessage`, echo-on/off prompts become `Prompt` /
`MaskedPrompt` and block until the greeter answers. **[confirmed]**
UI: info, error and prompt text are appended to the notification area (`LockScreenUi.qml` L57-105, `handleMessage`).
For Face the descriptor is `passwordField=false, expectingPrompt=false, showPrompt=true`
([pamauthenticatormodel.cpp L69-75](https://invent.kde.org/plasma/kscreenlocker/-/blob/v6.8.0/greeter/pamauthenticatormodel.cpp#L69)):
the password box is hidden when Face is clicked (`LockScreenUi.qml` L359-365), a prompt message is shown but cannot be
answered, and success with no prompt calls `Qt.quit()` at once (`onSucceeded`, `LockScreenUi.qml` L75-87). **[confirmed]**
So the Face PAM stack must be prompt-free. The current stack (`use_first_pass`, no prompt) fits. **[confirmed]**
Success on the Face worker also saves `Authenticator=Face` to the state file, so the next lock starts with Face. **[confirmed]**

## `PamTimeout` (VM QML only)

The installed `LockScreenUi.qml` (plasma-desktop build89) reads `authenticator.pamTimeout` (L286-292, L396-401), but
v6.8.0 `PamAuthenticators` has no such property. The VM journal confirms it: "no signal of the target matches the name
`onPamTimeoutChanged`". The property is therefore always `undefined`, the pending-password path never runs, and
`authenticator.respond(password)` is called directly. It does not affect Face. **[confirmed]**

## Minimal supported fix (no KDE patch)

1. Enable the descriptor, system-wide (installer-friendly) or per user:
   - `/etc/xdg/kscreenlockerrc`: `[Authenticators]` `Face=true`, or
   - `kwriteconfig6 --file kscreenlockerrc --group Authenticators --key Face true`.
2. Make Face the starting authenticator: `~/.local/state/kscreenlockerrc` `[Greeter]` `Authenticator=Face`
   (the greeter itself writes it after the first successful Face unlock). Without it the lock starts on `Regular`
   and Face needs one click on the Face button (the switcher appears once `Face=true`, since the model then has 2 entries).
3. Keep `/etc/pam.d/kde-face` as is. Ensure the module never returns `PAM_AUTHINFO_UNAVAIL`/`PAM_MODULE_UNKNOWN` on a miss.

No restart is needed: the greeter is spawned per lock and the model is built at greeter start. **[inferred]**

Alternative (also no patch, distro-wide): the implicit `kde-fingerprint` worker runs at every lock with no config. Overriding
`/etc/pam.d/kde-fingerprint` to include `openhello-lockscreen` would auto-start the face check without any config, but it
replaces the fprintd path, shows fingerprint wording, and treats `PAM_AUTHINFO_UNAVAIL` under 250 ms as unavailable
(L322-333). Not recommended. **[inferred]**

## Risks

- Face is not the default authenticator after a password unlock: `saveAuthenticatorType` writes `Regular`, so the
  next lock reverts to password until Face succeeds or is clicked again. **[confirmed]**
- While Face is active the `kde` (password) worker is not running and the password field is hidden; the user must click
  the Password button. Only one interactive authenticator is active at a time. **[confirmed]**
- A Face PAM stack that prompts (for example `pam_pkcs11` asking for a PIN) shows text but no input field. **[confirmed]**
- Fast failures (camera missing, daemon down) mark Face defunct until the next lock, with a "not functioning correctly"
  message. **[confirmed]**
- Config keys and the `[Greeter]` state file are new in 6.8 (model and `PamAuthenticators` copyright 2026); older Plasma
  (6.5 and earlier) has a single `kde` service and no Face. Other distros may build with `KSCREENLOCKER_PAM_FACE_SERVICE=disabled`.
  Detect with `strings kscreenlocker_greet | grep kde-face` plus the file check. **[inferred]**
- The Face authenticator does not depend on fprintd, D-Bus or camera checks in the greeter. The fprintd activation
  seen in the journal belongs to the implicit fingerprint worker. **[confirmed]**
