# Tasks: Credential login v1b

> feature: credential-login-v1b

## T-014 — Spike: tpm2-pkcs11 + pam_pkcs11 + C_Login override on swtpm [done]
- Refs: AC-019, AC-027
- Files: scripts/spike-pkcs11.sh, .spec/features/credential-login-v1b/spike.md
- Model: claude-sonnet-5
- Effort: high
- Notes: spike finished 2026-10-21 (ASM-006, ASM-007, ASM-010 proved, see spike.md); stays in-progress until AC-019 and AC-027 have proof in T-019 and T-022. First task, blocked the rest. Installs/builds `tpm2-pkcs11`, `pam_pkcs11`, `pamtester` on a test
  prefix; proves ASM-006 (P-256 verified by `pam_pkcs11`), ASM-007 (a wrapper replacing only `C_Login`) and
  ASM-010 (swtpm ECC + dictionary-attack lockout). Writes the result into `spike.md` and updates the assumptions.

## T-015 — Ticket library (HMAC, TTL, single use) [done]
- Refs: AC-020, AC-021, AC-022
- Files: crates/openhello-ticket/Cargo.toml, crates/openhello-ticket/src/lib.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: pure library, no I/O. Independent of the spike.

## T-016 — openhello-keyd: workspace crate and TPM key provisioning [done]
- Refs: AC-016, AC-017, AC-018
- Files: Cargo.toml, crates/openhello-keyd/Cargo.toml, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/src/tpm.rs, crates/openhello-keyd/src/provision.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-014. Idempotent provisioning; non-extractable key; no private bytes in any output (P-004).

## T-017 — openhello-keyd: Protectors (biometric, PIN, recovery) and lockout [done]
- Refs: AC-019, AC-024, AC-025, AC-026, AC-031, AC-032
- Files: crates/openhello-keyd/src/protector.rs, crates/openhello-keyd/src/ticket_socket.rs, crates/openhello-keyd/tests/protectors.rs
- Model: claude-sonnet-5
- Effort: xhigh
- Notes: depends on T-015, T-016. PIN uses the TPM dictionary-attack lockout; the ticket socket checks
  `SO_PEERCRED`. Biometrics only authorize the key, never replace it (P-003).

## T-018 — openhellod: issue a ticket after a successful Verify [done]
- Refs: AC-023, AC-019
- Files: crates/openhellod/src/ticket_client.rs, crates/openhellod/src/core.rs, crates/openhellod/Cargo.toml
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-015. No match, no ticket.

## T-019 — openhello-pkcs11: wrapper module overriding C_Login [done]
- Refs: AC-019, AC-024, AC-025
- Files: Cargo.toml, crates/openhello-pkcs11/Cargo.toml, crates/openhello-pkcs11/src/lib.rs, crates/openhello-pkcs11/tests/login.rs, crates/openhello-keyd/src/unlock_socket.rs, crates/openhello-keyd/src/lib.rs
- Model: claude-sonnet-5
- Effort: xhigh
- Notes: depends on T-014, T-017, T-018. Forwards all other calls to `tpm2-pkcs11`; refuses templates and embeddings. `C_Login` with the fixed placeholder runs the face flow (openhellod `Verify` -> ticket -> keyd grant); any other PIN runs the PIN Protector. The wrapper never holds the Protector longer than the `C_Login` call. keyd gains an unlock socket where the peer uid must equal the target uid (the user's own process), separate from the root-only ticket socket.

## T-020 — openhello-keyd: D-Bus service, polkit and systemd sandbox [done]
- Refs: AC-034
- Files: crates/openhello-keyd/src/main.rs, crates/openhello-keyd/src/dbus_service.rs, crates/openhello-keyd/src/polkit.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/tests/dbus_service.rs, packaging/io.openhello.Keyd1.conf, packaging/openhello-keyd.service
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-016, T-017. Same authorization pattern as `openhellod` (T-010). Methods Provision, SetPin and Purge; the keyd purge itself (evict the TPM key, delete Protectors, remove the token) lives in `purge.rs` so that AC-034 can be tested against a real Purge.

## T-021 — Purge integration and log redaction [done]
- Refs: AC-033, AC-035
- Files: crates/openhello-keyd/src/logging.rs, crates/openhello-keyd/tests/purge_and_logs.rs, crates/openhellod/src/dbus_service.rs, crates/openhellod/src/core.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-020. `openhellod` Purge calls the keyd purge from T-020 (extends P-008); this task proves AC-033 end to end and adds log redaction for PINs, Protector secrets, tickets and recovery codes (AC-035).

## T-024 — keyd: token certificate, root-owned mapping and root-delegated unlock [done]
- Refs: AC-016
- Files: crates/openhello-keyd/src/certificate.rs, crates/openhello-keyd/src/provision.rs, crates/openhello-keyd/src/unlock_socket.rs, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/tests/certificate.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-020, T-021; must run before T-022. `pam_pkcs11` needs a certificate on the token, and its default mapper reads `~/.eid/authorized_certificates`, a file the user controls, so any user could authorize their own software key and pass `sudo`. Provision issues a self-signed certificate for the TPM key and records its digest in a root-owned mapping file; Purge removes both. Under setuid `sudo` the peer of the unlock socket is root, so a root peer may name the target uid (Windows Hello: the privileged logon component asks the key service on behalf of the user); a non-root peer still only acts for its own uid. Partial evidence for AC-027 and AC-029 (signature checks against the certificate) is covered by unlabeled tests; those criteria are proven in T-022.

## T-022 — PAM stack, installer and sudo end-to-end [done]
- Refs: AC-027, AC-029, AC-030
- Files: Cargo.toml, packaging/pam/sudo-openhello, packaging/pam/pam_pkcs11.conf, packaging/pam/pkcs11.conf, packaging/openhello-keyd.service, scripts/install.sh, crates/openhello-pam/Cargo.toml, crates/openhello-pam/src/lib.rs, crates/openhello-cli/Cargo.toml, crates/openhello-cli/tests/pam_sudo.rs, crates/openhello-keyd/src/certificate.rs, crates/openhello-keyd/src/config.rs, crates/openhello-keyd/src/provision.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/src/tpm.rs, crates/openhello-keyd/tests/certificate.rs, crates/openhello-pkcs11/src/lib.rs, crates/openhello-pkcs11/src/config.rs, crates/openhello-pkcs11/tests/privileged_config.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-019, T-020, T-024. Tested with a `pam_wrapper` client (pamtester is not packaged) against a private service file. Fixes the wrapper and module paths in root-owned config instead of the caller's environment, supplies the `C_Login` placeholder to `pam_pkcs11`, and uses the root-owned certificate mapping from T-024. `pam_pkcs11` only accepts the self-signed certificate if it is imported as a trusted CA in a root-owned NSS database (`certutil -A -t "CT,C,C"`; the certificate must carry no extensions): Provision imports it there and Purge removes it.
  `pam_openhello` (new crate) shows "Looking for your face..." and sets the `C_Login` placeholder as the first password; `pam_pkcs11` crashes without a first password, so the stack maps its answer with `[success=ignore ignore=2 default=ignore]` (ignore skips `pam_pkcs11`) and a trailing `pam_openhello.so clear` drops the placeholder before the password module. The PIN is an opt-in second `pam_pkcs11` line (no `use_first_pass`) because a password typed by habit would count against the TPM-wide lockout. The wrapper also exposes only the caller's own token to `pam_pkcs11`, pins the token store from the root-owned config when privileged, and caps `Verify` at 4 s so a silent camera falls through within 5 s.

## T-025 — Token proxy: the wrapper forwards PKCS#11 calls to keyd [done]
- Refs: AC-019, AC-025, AC-027
- Files: crates/openhello-keyd/src/token_socket.rs, crates/openhello-keyd/src/unlock_socket.rs, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/src/main.rs, crates/openhello-keyd/tests/token_proxy.rs, crates/openhello-pkcs11/src/proxy.rs, crates/openhello-pkcs11/src/lib.rs, crates/openhello-pkcs11/src/config.rs, crates/openhello-pkcs11/tests/login.rs, crates/openhello-pkcs11/tests/privileged_config.rs, crates/openhello-pkcs11/Cargo.toml, crates/openhello-keyd/Cargo.toml, crates/openhello-keyd/src/config.rs, crates/openhello-keyd/src/provision.rs, crates/openhello-keyd/tests/support/mod.rs, crates/openhello-keyd/tests/certificate.rs, crates/openhello-keyd/tests/purge_and_logs.rs, crates/openhello-cli/tests/pam_sudo.rs, crates/openhello-pam/src/lib.rs, packaging/openhello-keyd.service, packaging/pam/pkcs11.conf
- Model: claude-sonnet-5
- Effort: xhigh
- Notes: depends on T-022; must run before T-023. The lock screen runs as the user and cannot open the root-owned token (the `sudo` path works only because it is root). Decision (owner, 2026-10-21): the wrapper in the user's process becomes a thin proxy; keyd (root) owns the real PKCS#11 session and signs, as in Windows Hello where the key never leaves the service. The Protector secret K stops crossing the socket: the world-accessible unlock socket no longer returns K. AC-019, AC-025 and AC-027 must keep passing through the proxy.

## T-023 — KDE lock screen verification [in-progress]
- Refs: AC-028
- Files: packaging/pam/openhello-lockscreen, packaging/pam/openhello-common-auth, .spec/features/credential-login-v1b/lockscreen.md, scripts/install.sh, scripts/pam-survey.sh, crates/openhello-pam/src/lib.rs, crates/openhello-pkcs11/src/config.rs, crates/openhello-cli/tests/pam_sudo.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: delivered 2026-10-21 (generic lock-screen PAM service, survey script, guide); stays in-progress until the manual check proves AC-028. Depends on T-025. Manual check on the Plasma session (ASM-011), recorded as evidence; an unprivileged PAM test through the `kde` service file covers the same path in CI.

## T-026 — Embed the default FAR calibration as a readable config file [pending]

- Refs: AC-036, AC-037, AC-038
- Files: crates/engine-adapter-face/config/default_calibration.toml, crates/engine-adapter-face/src/far_calibration.rs, crates/engine-adapter-face/src/calibrate.rs, crates/engine-adapter-face/src/bin/openhello-calibrate.rs, crates/engine-adapter-face/src/ffi.rs, crates/engine-adapter-face/tests/default_calibration.rs, crates/engine-adapter-face/Cargo.toml, Cargo.lock, crates/engine-adapter-face/src/matching.rs, crates/engine-adapter-face/tests/frame_fixtures.rs, .spec/features/credential-login-v1b/calibration-results.md
- Model: claude-sonnet-5
- Effort: medium
- Notes: blocked until a calibration run exists (installer on the VM with LFW through the real models, `/var/lib/openhello/calibration.bin`). Owner decision (2026-10-21): record the results in a versioned, human-readable file instead of a binary blob. The calibration becomes a TOML file: the 64-point body table and tail parameters plus provenance (dataset name and license note, date, sha256 of the detector and embedding models, impostor pair count, tool version) and a list of the thresholds it yields at FAR 1e-3 to 1e-8. `openhello-calibrate` writes this TOML; the default file is embedded with `include_str!`; the optional runtime override (`calibration_path`) uses the same format. The old `OHC2` binary is still read so existing files keep working. `calibration-results.md` records the run: sample counts, thresholds per FAR, and the caveat that LFW is visible light (ASM-013). Keep the golden test; add a test that the embedded file parses and its thresholds are monotonic over FAR 1e-1 to 1e-8.

## T-027 — Installer no longer calibrates; docs [pending]

- Refs: AC-036
- Files: scripts/install.sh, evaluation/README.md, crates/openhellod/src/config.rs
- Model: claude-sonnet-5
- Effort: low
- Notes: depends on T-026. `install.sh` stops requiring calibration images (`--calibration-*` options stay as an optional override that writes `/var/lib/openhello/calibration.bin`); the daemon starts right after install. `openhellod` config makes the calibration path optional. The evaluation README explains how to regenerate the default calibration file from LFW or from infrared captures and where to record the results (`calibration-results.md`, the TOML provenance block).

## T-028 — CLI: provision the key after enrollment, set a PIN, show the recovery code [done]
- Refs: AC-016, AC-025, AC-031
- Files: crates/openhello-cli/src/lib.rs, crates/openhello-cli/src/dbus_client.rs, crates/openhello-cli/src/keyd_client.rs, crates/openhello-cli/src/main.rs, crates/openhello-cli/tests/provisioning_flow.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: found while testing on the VM (2026-10-21): nothing calls keyd `Provision` after `EnrollCommit`, so no user has a key and `sudo` face login cannot work. `openhello-cli enroll` calls keyd `Provision` for the same uid right after a successful commit and prints the recovery code once (never again, never logged); new `openhello-cli set-pin` reads the PIN from the terminal without echo and calls keyd `SetPin`; `purge` already reaches keyd through openhellod (T-021). If Provision fails after a committed enrollment the CLI says so plainly and does not discard the template. The polkit actions allow only an active local session (`allow_active`), so these commands are run from the desktop session, not over SSH.

## T-029 — pam_openhello stays silent for users without an open-hello credential [done]
- Refs: AC-030
- Files: crates/openhello-pam/src/lib.rs, crates/openhello-cli/tests/pam_sudo.rs
- Model: claude-sonnet-5
- Effort: low
- Notes: found on the VM: for a user with no token the stack printed "Looking for your face..." and then pam_pkcs11 errors ("no suitable token available", "Error 2308") before the password prompt. `pam_openhello` checks the root-owned subject map (T-024) for the calling user and returns `PAM_IGNORE` silently when the user is absent, before any message or camera use. The check must not need the user's home or environment.

## T-030 — keyd finds the tpm2-pkcs11 module on any distribution; CLI can retry provisioning [done]
- Refs: AC-016
- Files: crates/openhello-keyd/src/tpm.rs, crates/openhello-keyd/src/config.rs, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/tests/module_discovery.rs, crates/openhello-cli/src/lib.rs, crates/openhello-cli/src/keyd_client.rs, crates/openhello-cli/src/main.rs, crates/openhello-cli/tests/provisioning_flow.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: found on the KDE neon VM (2026-10-21): keyd looked for `/usr/lib64/pkcs11/libtpm2_pkcs11.so` (openSUSE layout) and the module lives in `/usr/lib/x86_64-linux-gnu/pkcs11/` on Debian and Ubuntu. keyd resolves the module from an explicit `OPENHELLO_TPM2_PKCS11_MODULE`, else the test prefix, else the first existing of the common locations (`/usr/lib64/pkcs11`, `/usr/lib/<multiarch>/pkcs11`, `/usr/lib/pkcs11`, `/usr/lib/aarch64-linux-gnu/pkcs11`), and fails with a message naming the paths it tried. New `openhello-cli provision` retries the key creation for an already enrolled face without re-enrolling.

## T-031 — Installer restarts services and never overwrites loaded libraries [done]
- Refs: AC-016
- Files: scripts/install.sh
- Model: claude-sonnet-5
- Effort: low
- Notes: found on the VM: `cp -a` over the ONNX Runtime libraries mapped by the running `openhellod` crashed it with SEGV on the next call, and `enable --now` left the old `openhello-keyd` running the previous binary. The installer stops both services before replacing files, copies libraries without writing into mapped files (`cp --remove-destination`), then restarts both. Debian and Ubuntu use `libtpm2-pkcs11-tools`.

## T-032 — Token proxy accepts the search templates of the OpenSSL build of pam_pkcs11 [done]
- Refs: AC-027
- Files: crates/openhello-keyd/src/token_socket.rs, crates/openhello-keyd/tests/token_proxy.rs, crates/openhello-cli/tests/pam_sudo.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: found on the KDE neon VM (2026-10-21), see `pam-pkcs11-0612-diagnosis.md`: Debian and Ubuntu build pam_pkcs11 with OpenSSL (openSUSE with NSS), and the OpenSSL build searches with `{CKA_CLASS=certificate, CKA_CERTIFICATE_TYPE=X509}` and `{CKA_CLASS=private key, CKA_SIGN=true[, CKA_ID]}`. `parse_template` in `token_socket.rs` rejected `CKA_CERTIFICATE_TYPE` (0x80) and `CKA_SIGN` (0x108), the proxy answered `CKR_ARGUMENTS_BAD`, and pam_pkcs11 ignores that error and reports "no valid certificate". Accept both attributes and keep refusing unknown ones. The tests so far ran only against the NSS build, so add template-level tests that mirror the OpenSSL build; the real proof is `sudo true` on the VM.

## T-033 — Subject map covers the subject format of both pam_pkcs11 builds [done]
- Refs: AC-027
- Files: crates/openhello-keyd/src/certificate.rs, crates/openhello-keyd/src/provision.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/tests/certificate.rs, crates/openhello-pam/src/lib.rs, crates/openhello-cli/tests/pam_sudo.rs
- Model: claude-sonnet-5
- Effort: low
- Notes: found on the KDE neon VM (2026-10-21) with pam_pkcs11 debug on: `certificate is valid but does not match the user`, `Mapper module subject match() returns 0`. The NSS build presents the subject as `CN=openhello-uid-1000`; the OpenSSL build (Debian, Ubuntu) as `/CN=openhello-uid-1000` (one-line form). Provision writes both lines to the root-owned map for the user, Purge removes both, and the check in `pam_openhello` that a user has a credential keeps working. AC-016's test, which asserts the exact map content, is updated to assert both exact lines (not weakened).



## T-034 — keyd: root-owned public key and a challenge-signing operation [pending]

- Refs: AC-027
- Files: crates/openhello-keyd/src/auth_keys.rs, crates/openhello-keyd/src/token_socket.rs, crates/openhello-keyd/src/provision.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/tests/auth_challenge.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: first step of owner decision ASM-014. Provision writes the user's P-256 public key (SEC1 or SPKI PEM) to `/etc/openhello/auth/<uid>.pub` (root-owned, 0644, atomic, idempotent; directory configurable by `OPENHELLO_KEYD_AUTH_DIR` for tests); Purge removes it. New keyd operation: given a 32-byte challenge from the caller, keyd takes the grant that the ticket created for that uid, logs in to the token internally, signs a domain-separated hash (`"openhello-pam-v1" || uid || challenge`) with the TPM key and returns the 64-byte signature; no grant, no signature; one use per grant; private key and K never leave keyd. The challenge always comes from the verifier (the PAM module) and keyd signs only for the uid of the grant (the Windows counterpart is the registered key credential, `msDS-KeyCredentialLink` or the Entra registration). Include the PAM service name in the signed bytes.

## T-035 — pam_openhello verifies the signature itself; stacks drop pam_pkcs11 [pending]

- Refs: AC-027, AC-029, AC-030
- Files: crates/openhello-pam/Cargo.toml, crates/openhello-pam/src/lib.rs, crates/openhello-pam/src/challenge.rs, packaging/pam/sudo-openhello, packaging/pam/openhello-lockscreen, packaging/pam/openhello-common-auth, crates/openhello-cli/tests/pam_sudo.rs
- Model: claude-sonnet-5
- Effort: xhigh
- Notes: depends on T-034. `pam_openhello` generates the challenge (getrandom), asks openhellod `Verify` (4 s ceiling as in T-022), asks keyd to sign, verifies with the root-owned public key (pure Rust P-256, no OpenSSL or NSS), and returns SUCCESS only on a valid signature; every other outcome falls through as today (IGNORE/AUTH_ERR to the password). Same silence for users without a credential and for ssh/allowlist rules. The packaged stacks lose their `pam_pkcs11` lines. The tests no longer need `pam_pkcs11`, so they run the same on every distribution. Keep the `// @spec` proofs of AC-027, AC-029 and AC-030 passing. The verification runs inside the PAM process (accepted trade-off, ASM-014); a missing public key, or one not owned by root, makes the module return `PAM_IGNORE`.

## T-036 — keyd discovers the tpm2-pkcs11 module through p11-kit, then by name [pending]

- Refs: AC-016
- Files: crates/openhello-keyd/src/tpm.rs, crates/openhello-keyd/tests/module_discovery.rs
- Model: claude-sonnet-5
- Effort: low
- Notes: replaces the fixed list of directories from T-030 (portability-paths.md): order is `OPENHELLO_TPM2_PKCS11_MODULE`, the test prefix, `p11-kit list-modules` (entry whose `path:` ends in `libtpm2_pkcs11.so`), then `dlopen("libtpm2_pkcs11.so")` by name through the loader cache. Resolution stays pure and testable with injected lookups.

## T-037 — Installer uses neutral locations and discovers third-party paths [pending]

- Refs: AC-016
- Files: scripts/install.sh, packaging/openhellod.service, packaging/openhello-keyd.service
- Model: claude-sonnet-5
- Effort: medium
- Notes: units to `/usr/lib/systemd/system`, D-Bus policy to `/usr/share/dbus-1/system.d`, polkit actions to `/usr/share/polkit-1/actions`, daemon directory written into the units by template, PAM directory from `dirname $(ldconfig -p | awk '/libpam\.so\.0/{print $NF; exit}')/security`; no `/etc/systemd/system` or `/etc/dbus-1` branches; dependency lists drop `libpam-pkcs11`, `libnss3-tools` and the NSS paths (ASM-014); the sudo edit by `sed` is replaced by T-038.

## T-038 — PAM manager profiles instead of editing /etc/pam.d by hand [pending]

- Refs: AC-027
- Files: packaging/pam/pam-auth-update/openhello, packaging/pam/authselect/openhello, packaging/pam/manual-snippet.md, scripts/install.sh
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-035 and T-037. A `pam-auth-update` profile for the Debian family, an `authselect` custom feature for Fedora and RHEL, and a manual snippet with backup for openSUSE, Arch and the rest (portability.md). The profile applies the gated block with the service allowlist starting at `sudo` only. Nothing here may remove the password path; document how to remove the profile.

## T-039 — Native deb and rpm packages from one definition [pending]

- Refs: AC-016
- Files: packaging/nfpm.yaml, packaging/scripts/postinstall.sh, packaging/scripts/preremove.sh, scripts/build-packages.sh
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-037. One definition with nfpm (portability-packaging.md), per-family dependency names through overrides, idempotent post-install scripts, models and ONNX Runtime fetched and verified after install, `install.sh` kept for development only. CI matrix (Ubuntu LTS, Fedora, openSUSE Tumbleweed) in containers with systemd, pam_wrapper and swtpm is a follow-up once the packages build.

## T-040 — KDE lock screen adapter (kde-face) [pending]

- Refs: AC-028
- Files: scripts/install.sh, .spec/features/credential-login-v1b/lockscreen.md
- Model: claude-sonnet-5
- Effort: low
- Notes: lowest priority, KDE only (kscreenlocker-face-diagnosis.md). The greeter starts `kde-face` only with `[Authenticators] Face=true` in `kscreenlockerrc` (`/etc/xdg/kscreenlockerrc` or per user), and the lock begins on Face only if `[Greeter] Authenticator=Face` in `~/.local/state/kscreenlockerrc`. The installer offers this as an explicit opt-in step, never silently, and the guide records the side effects.
\n