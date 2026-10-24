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
- Files: Cargo.toml, packaging/pam/sudo-openhello, packaging/openhello-keyd.service, scripts/install.sh, crates/openhello-pam/Cargo.toml, crates/openhello-pam/src/lib.rs, crates/openhello-cli/Cargo.toml, crates/openhello-cli/tests/pam_sudo.rs, crates/openhello-keyd/src/certificate.rs, crates/openhello-keyd/src/config.rs, crates/openhello-keyd/src/provision.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/src/tpm.rs, crates/openhello-keyd/tests/certificate.rs, crates/openhello-pkcs11/src/lib.rs, crates/openhello-pkcs11/src/config.rs, crates/openhello-pkcs11/tests/privileged_config.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-019, T-020, T-024. Tested with a `pam_wrapper` client (pamtester is not packaged) against a private service file. Fixes the wrapper and module paths in root-owned config instead of the caller's environment, supplies the `C_Login` placeholder to `pam_pkcs11`, and uses the root-owned certificate mapping from T-024. `pam_pkcs11` only accepts the self-signed certificate if it is imported as a trusted CA in a root-owned NSS database (`certutil -A -t "CT,C,C"`; the certificate must carry no extensions): Provision imports it there and Purge removes it.
  `pam_openhello` (new crate) shows "Looking for your face..." and sets the `C_Login` placeholder as the first password; `pam_pkcs11` crashes without a first password, so the stack maps its answer with `[success=ignore ignore=2 default=ignore]` (ignore skips `pam_pkcs11`) and a trailing `pam_openhello.so clear` drops the placeholder before the password module. The PIN is an opt-in second `pam_pkcs11` line (no `use_first_pass`) because a password typed by habit would count against the TPM-wide lockout. The wrapper also exposes only the caller's own token to `pam_pkcs11`, pins the token store from the root-owned config when privileged, and caps `Verify` at 4 s so a silent camera falls through within 5 s.

## T-025 — Token proxy: the wrapper forwards PKCS#11 calls to keyd [done]
- Refs: AC-019, AC-025, AC-027
- Files: crates/openhello-keyd/src/token_socket.rs, crates/openhello-keyd/src/unlock_socket.rs, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/src/main.rs, crates/openhello-keyd/tests/token_proxy.rs, crates/openhello-pkcs11/src/proxy.rs, crates/openhello-pkcs11/src/lib.rs, crates/openhello-pkcs11/src/config.rs, crates/openhello-pkcs11/tests/login.rs, crates/openhello-pkcs11/tests/privileged_config.rs, crates/openhello-pkcs11/Cargo.toml, crates/openhello-keyd/Cargo.toml, crates/openhello-keyd/src/config.rs, crates/openhello-keyd/src/provision.rs, crates/openhello-keyd/tests/support/mod.rs, crates/openhello-keyd/tests/certificate.rs, crates/openhello-keyd/tests/purge_and_logs.rs, crates/openhello-cli/tests/pam_sudo.rs, crates/openhello-pam/src/lib.rs, packaging/openhello-keyd.service
- Model: claude-sonnet-5
- Effort: xhigh
- Notes: depends on T-022; must run before T-023. The lock screen runs as the user and cannot open the root-owned token (the `sudo` path works only because it is root). Decision (owner, 2026-10-21): the wrapper in the user's process becomes a thin proxy; keyd (root) owns the real PKCS#11 session and signs, as in Windows Hello where the key never leaves the service. The Protector secret K stops crossing the socket: the world-accessible unlock socket no longer returns K. AC-019, AC-025 and AC-027 must keep passing through the proxy.

## T-023 — Lock screen verification [in-progress]
- Refs: AC-028
- Files: .spec/features/credential-login-v1b/lockscreen.md, scripts/install.sh, scripts/pam-survey.sh, crates/openhello-pam/src/lib.rs, crates/openhello-pkcs11/src/config.rs, crates/openhello-cli/tests/pam_sudo.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: delivered 2026-10-21 (generic lock-screen PAM service, survey script, guide); stays in-progress until the manual check proves AC-028. Depends on T-025. Manual check on the Plasma session (ASM-011), recorded as evidence; an unprivileged PAM test through the `kde` service file covers the same path in CI.

## T-026 — Embed the default FAR calibration as a readable config file [done]
- Refs: AC-036, AC-037, AC-038
- Files: crates/engine-adapter-face/config/default_calibration.toml, crates/engine-adapter-face/src/far_calibration.rs, crates/engine-adapter-face/src/calibrate.rs, crates/engine-adapter-face/src/bin/openhello-calibrate.rs, crates/engine-adapter-face/src/ffi.rs, crates/engine-adapter-face/tests/default_calibration.rs, crates/engine-adapter-face/Cargo.toml, Cargo.lock, crates/engine-adapter-face/src/matching.rs, crates/engine-adapter-face/tests/frame_fixtures.rs, .spec/features/credential-login-v1b/calibration-results.md
- Model: claude-sonnet-5
- Effort: medium
- Notes: blocked until a calibration run exists (installer on the VM with LFW through the real models, `/var/lib/openhello/calibration.bin`). Owner decision (2026-10-21): record the results in a versioned, human-readable file instead of a binary blob. The calibration becomes a TOML file: the 64-point body table and tail parameters plus provenance (dataset name and license note, date, sha256 of the detector and embedding models, impostor pair count, tool version) and a list of the thresholds it yields at FAR 1e-3 to 1e-8. `openhello-calibrate` writes this TOML; the default file is embedded with `include_str!`; the optional runtime override (`calibration_path`) uses the same format. The old `OHC2` binary is still read so existing files keep working. `calibration-results.md` records the run: sample counts, thresholds per FAR, and the caveat that LFW is visible light (ASM-013). Keep the golden test; add a test that the embedded file parses and its thresholds are monotonic over FAR 1e-1 to 1e-8.

## T-027 — Installer no longer calibrates; docs [done]
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
- Notes: found while testing on the VM (2026-10-21): nothing calls keyd `Provision` after `EnrollCommit`, so no user has a key and `sudo` face login cannot work. `openhello-cli enroll` calls keyd `Provision` for the same uid right after a successful commit and prints the recovery code once (never again, never logged); new `openhello-cli set-pin` reads the PIN from the terminal without echo and calls keyd `SetPin`; `purge` already reaches keyd through openhellod (T-021). If Provision fails after a committed enrollment the CLI says so plainly and does not discard the template. The polkit actions allow only an active local session (`allow_active`), so these commands are run from the desktop session, not over SSH. Superseded in part on 2026-10-23 (enrollment-ui T-073): the CLI no longer prints the recovery code and has no `set-pin`; the key service API is unchanged.

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



## T-034 — keyd: root-owned public key and a challenge-signing operation [done]
- Refs: AC-027
- Files: crates/openhello-keyd/src/auth_keys.rs, crates/openhello-keyd/src/token_socket.rs, crates/openhello-keyd/src/provision.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/src/tpm.rs, crates/openhello-keyd/src/config.rs, crates/openhello-keyd/tests/auth_challenge.rs, crates/openhello-keyd/tests/support/mod.rs, crates/openhello-auth-proto/Cargo.toml, crates/openhello-auth-proto/src/lib.rs, Cargo.toml
- Model: claude-sonnet-5
- Effort: high
- Notes: first step of owner decision ASM-014. Provision writes the user's P-256 public key (SEC1 or SPKI PEM) to `/etc/openhello/auth/<uid>.pub` (root-owned, 0644, atomic, idempotent; directory configurable by `OPENHELLO_KEYD_AUTH_DIR` for tests); Purge removes it. New keyd operation: given a 32-byte challenge from the caller, keyd takes the grant that the ticket created for that uid, logs in to the token internally, signs a domain-separated hash (`"openhello-pam-v1" || uid || challenge`) with the TPM key and returns the 64-byte signature; no grant, no signature; one use per grant; private key and K never leave keyd. The challenge always comes from the verifier (the PAM module) and keyd signs only for the uid of the grant (the Windows counterpart is the registered key credential, `msDS-KeyCredentialLink` or the Entra registration). Include the PAM service name in the signed bytes.

## T-035 — pam_openhello verifies the signature itself; stacks drop pam_pkcs11 [done]
- Refs: AC-027, AC-029, AC-030
- Files: crates/openhello-pam/Cargo.toml, crates/openhello-pam/src/lib.rs, crates/openhello-pam/src/challenge.rs, packaging/pam/sudo-openhello, crates/openhello-cli/tests/pam_sudo.rs, crates/openhello-cli/Cargo.toml, Cargo.lock
- Model: claude-sonnet-5
- Effort: xhigh
- Notes: depends on T-034. `pam_openhello` generates the challenge (getrandom), asks openhellod `Verify` (4 s ceiling as in T-022), asks keyd to sign, verifies with the root-owned public key (pure Rust P-256, no OpenSSL or NSS), and returns SUCCESS only on a valid signature; every other outcome falls through as today (IGNORE/AUTH_ERR to the password). Same silence for users without a credential and for ssh/allowlist rules. The packaged stacks lose their `pam_pkcs11` lines. The tests no longer need `pam_pkcs11`, so they run the same on every distribution. Keep the `// @spec` proofs of AC-027, AC-029 and AC-030 passing. The verification runs inside the PAM process (accepted trade-off, ASM-014); a missing public key, or one not owned by root, makes the module return `PAM_IGNORE`.

## T-036 — keyd discovers the tpm2-pkcs11 module through p11-kit, then by name [done]
- Refs: AC-016
- Files: crates/openhello-keyd/src/tpm.rs, crates/openhello-keyd/tests/module_discovery.rs
- Model: claude-sonnet-5
- Effort: low
- Notes: replaces the fixed list of directories from T-030 (portability-paths.md): order is `OPENHELLO_TPM2_PKCS11_MODULE`, the test prefix, `p11-kit list-modules` (entry whose `path:` ends in `libtpm2_pkcs11.so`), then `dlopen("libtpm2_pkcs11.so")` by name through the loader cache. Resolution stays pure and testable with injected lookups.

## T-037 — Installer uses neutral locations, discovers third-party paths and checks capabilities [done]
- Refs: AC-016
- Files: scripts/install.sh, packaging/openhellod.service, packaging/openhello-keyd.service, crates/openhello-cli/tests/pam_sudo.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: owner rule (2026-10-21): no per-distro or per-desktop code unless unavoidable. Units to `/usr/lib/systemd/system`, D-Bus policy to `/usr/share/dbus-1/system.d`, polkit actions to `/usr/share/polkit-1/actions`, daemon directory written into the units by template, PAM directory from `dirname $(ldconfig -p | awk '/libpam\.so\.0/{print $NF; exit}')/security`; no `/etc/systemd/system` or `/etc/dbus-1` branches. The installer no longer installs packages: every `apt`, `dnf`, `zypper` and `pacman` branch goes, replaced by a capability check (`command -v tpm2_createprimary tpm2_ptool`, `python3 -c "import tpm2_pkcs11"`, a loader-cache probe for the TPM and PKCS#11 libraries, `polkitd` and a system bus) that prints what is missing as capabilities, never package names. The KDE-only `kde-face` code and the common-stack snippet (`openhello-common-auth`) are removed; the dependency lists drop `libpam-pkcs11`, `libnss3-tools` and the NSS paths (ASM-014); the `sed` edit of `/etc/pam.d/sudo` is replaced by T-038.


## T-038 — One universal rule to enable the PAM module per service [done]
- Refs: AC-027
- Files: crates/openhello-cli/src/pam_enable.rs, crates/openhello-cli/src/lib.rs, crates/openhello-cli/src/main.rs, crates/openhello-cli/tests/pam_enable.rs, scripts/install.sh
- Model: claude-sonnet-5
- Effort: medium
- Notes: replaces the per-manager profiles (`pam-auth-update`, `authselect`, `pam-config`) that the portability research proposed, because they are one adapter per distribution (owner rule, 2026-10-21). New `openhello-cli pam enable <service>... | disable <service>... | status`: for each service name, insert `auth sufficient pam_openhello.so` before the first `auth` line of `/etc/pam.d/<service>` (the `auth` control syntax is valid in every Linux-PAM system, unlike `@include`), copying the vendor file first when the service only exists in `/usr/lib/pam.d`; keep one `.openhello.bak` backup, be idempotent, refuse and say why when the file is a symlink into a manager-owned tree, and `disable` removes exactly that line. `enable` also migrates a machine installed with the earlier installer: when `/etc/pam.d/<service>` still has `auth include sudo-openhello` or `auth include openhello-lockscreen`, or `/etc/pam.d/` still holds our old stack files (`sudo-openhello`, `openhello-lockscreen`, `kde-face`, recognised by their content), remove exactly those lines and files and say so, because the old stacks relied on the `pam_pkcs11` placeholder flow and a new `pam_openhello` success would be ignored by them (a `pam_pkcs11` call without an authentication token crashes). The default service list is `sudo`; lockers and greeters are added by name as data (`kde`, `gdm-password`, `swaylock`, ...), with no code per desktop. The shared common stacks (`common-auth`, `system-auth`) are never edited. Tests run on temporary directories.


## T-039 — Release artifacts: one tarball and thin package metadata [pending]

- Refs: AC-016
- Files: packaging/nfpm.yaml, packaging/scripts/postinstall.sh, packaging/scripts/preremove.sh, scripts/build-release.sh
- Model: claude-sonnet-5
- Effort: medium
- Notes: lowest priority and optional. One distribution-neutral tarball plus a single nfpm definition that emits deb and rpm; the only per-family content is the dependency names, kept as data in the metadata, never as code. Post-install scripts call the same neutral steps as the installer and `openhello-cli pam enable`; models and ONNX Runtime stay outside the package, fetched and verified. CI in containers (Ubuntu LTS, Fedora, openSUSE Tumbleweed) with systemd, pam_wrapper and swtpm is a follow-up.


## T-040 — Lock screens use the same rule; no desktop adapter [done]
- Refs: AC-028
- Files: .spec/features/credential-login-v1b/lockscreen.md
- Model: claude-sonnet-5
- Effort: low
- Notes: replaces the KDE-only `kde-face` plan (owner rule, 2026-10-21). Observed on the VM: at lock the KDE greeter starts the `kde` password worker; with `pam_openhello` first in that service the face is tried before the password prompt and needs no `[Authenticators] Face=true`. Verify with `openhello-cli pam enable kde` on the VM and record: unlock without typing, what the greeter shows while the module waits, and what happens to a password typed during the wait. Other lockers use the identical command with their service name; anything the guide cannot confirm stays marked unverified.

## T-041 — keyd backfills the public key file for tokens provisioned before T-034 [done]
- Refs: AC-027
- Files: crates/openhello-keyd/src/auth_keys.rs, crates/openhello-keyd/src/main.rs, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/tests/auth_backfill.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: found on the KDE neon VM (2026-10-21) after upgrading: `/etc/openhello/auth` did not exist, because the user was provisioned before T-034, so `pam_openhello` found no credential and stayed silent (sudo and the KDE lock screen asked for the password). A repeated Provision cannot repair it (the key already exists). At start, and after each Provision, keyd reads the public key of every token `openhello-<uid>` (a public object, no login) and writes `<uid>.pub` when it is missing or differs, with the same format, owner, mode and atomic write as T-034; a token whose key cannot be read is skipped with a generic log line and never blocks startup. Purge still removes the file. The token's public key is authoritative.

## T-042 — pam_openhello: logs the reason it stays silent, detects local sessions robustly, links libpam [done]
- Refs: AC-028, AC-030
- Files: crates/openhello-pam/src/lib.rs, crates/openhello-pam/src/session.rs, crates/openhello-pam/build.rs, crates/openhello-pam/Cargo.toml, crates/openhello-cli/tests/pam_sudo.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: delivered 2026-10-21 (commit f69049d, tests green); stays in-progress until the lock-screen test on the VM proves AC-028. Found on the KDE neon VM (2026-10-21). In the real KDE lock screen the module reached no `Verify` at all, while the same module, run as the same user against the `kde` service from a test client, authenticated in 1.36 s. Likely cause, unconfirmed: the greeter is started by kwin with the compositor connection passed as a file descriptor (`WAYLAND_SOCKET`) and without `DISPLAY` or `WAYLAND_DISPLAY`, so the "local session" gate says no. Three changes. (1) A `debug` module argument makes every early exit (remote, not local, service not allowed, no credential file, files untrusted, openhellod or keyd unavailable, face refused, bad signature, success) write one syslog line (`LOG_AUTHPRIV`) with a reason code and the service name only, never a challenge, signature, key or user secret; it stays off by default. (2) Locality becomes: remote if `PAM_RHOST` or `SSH_CONNECTION`; local if `PAM_TTY`, `DISPLAY`, `WAYLAND_DISPLAY`, `WAYLAND_SOCKET` or `XDG_SESSION_TYPE` in {wayland, x11, mir}, or if the process's logind session (from `/proc/self/cgroup`, `session-<id>.scope`, then `/run/systemd/sessions/<id>`) reports `REMOTE=0`; no libsystemd dependency, and every probe is skipped quietly when its source does not exist. (3) The module declares `libpam.so.0` as a dependency (`cargo:rustc-cdylib-link-arg=-l:libpam.so.0`, no development package needed) because it failed with `undefined symbol: pam_get_item` when the host loaded libpam privately; a test asserts the built module lists `libpam.so.0` as needed.

## T-043 — Enable the module once in the common auth stack; the installer does it by default [done]
- Refs: AC-027, AC-028
- Files: crates/openhello-cli/src/pam_enable.rs, crates/openhello-cli/src/main.rs, crates/openhello-cli/tests/pam_enable.rs, scripts/install.sh
- Model: claude-sonnet-5
- Effort: high
- Notes: owner principle (2026-10-21, `camera-on-at-auth-moments-common-stack`): no per-interface change or command; the camera may turn on for a few seconds at sudo, polkit, the lock screen and the SDDM greeter once the user has enrolled a face. Windows Hello (tier 1) offers the credential in every sign-in context; `pam_fprintd` (tier 2) is wired through the common stack. `openhello-cli pam enable` with no service arguments becomes the whole integration: (1) find the common auth stack by reading what `sudo` includes (`@include X` or `auth include X` in `/etc/pam.d/sudo`, or the vendor copy), never from a list of distribution names; (2) when that file is a regular file, insert `auth sufficient pam_openhello.so allowlist=/etc/openhello/pam-services` before its first `auth` line, with the existing backup, atomic write and idempotence; when it is a symlink or otherwise manager-owned, refuse, say so, and print the per-service fallback (`pam enable <service>...`); (3) write the root-owned data file `/etc/openhello/pam-services` (0644) from `packaging/pam/pam-services`: `sudo`, `polkit-1`, `kde`, `gdm-password`, `sddm`, `lightdm`, `swaylock`, `hyprlock`, `i3lock`, `xscreensaver`, `xsecurelock`, `cinnamon-screensaver`, `mate-screensaver`, `xfce4-screensaver`, with a header saying which entries have been verified on a real system (`sudo` and `kde` only) and that `login`, `su`, `sshd`, `cron` are deliberately absent; (4) remove the per-service lines this tool added earlier (`sudo`, `kde`) so the module never runs twice; (5) `pam disable` with no arguments removes every line the tool added and leaves the allowlist file for the user to delete, `pam status` reports the common stack, the allowlist and any per-service line. The installer runs `openhello-cli pam enable` by default after installing the module, because the module is inert for users without a credential file, unless `--no-pam` is given, and prints how to undo it. A face-enrolled user whose greeter supplies the login name (SDDM and GDM select the user first) is covered by the same line; typing a name is covered the same way once it reaches PAM; greeters are unverified and must be marked as such. Tests run on temporary roots with the Debian layout (`sudo` includes `common-auth`), the SUSE/Arch layout (`auth include system-auth`) and a managed symlink that is refused.

## T-044 — Remove desktop-specific code and data; a denylist replaces the allowlist [done]
- Refs: AC-027, AC-028
- Files: crates/openhello-pam/src/lib.rs, crates/openhello-pam/src/debug.rs, crates/openhello-cli/src/pam_enable.rs, crates/openhello-cli/tests/pam_enable.rs, crates/openhello-cli/tests/pam_sudo.rs, scripts/install.sh, scripts/pam-survey.sh, scripts/spike-pkcs11.sh, .spec/features/credential-login-v1b/spec.md
- Model: claude-sonnet-5
- Effort: high
- Notes: owner directive (2026-10-21): open-hello contains no desktop-environment-specific code, data, messages or commands. The module decides alone: ignore (silent) when remote, not local, uid 0, no root-owned `<uid>.pub`, or the service is in a compiled denylist (`login`, `su`, `su-l`, `sshd`, `cron`, `crond`, `atd`, `passwd`, `chsh`, `chfn`, `runuser`, `runuser-l`, `other`); otherwise act. The `allowlist=` argument, `packaging/pam/pam-services` and `packaging/pam/openhello-lockscreen` are removed; the reason code `service-not-allowed` becomes `service-denied`. `pam enable` writes `auth sufficient pam_openhello.so` once in the common stack, removes earlier per-service lines, rewrites a previous line carrying `allowlist=` (backup kept once) and deletes `/etc/openhello/pam-services` when it still has the tool's header; the `kde-face` legacy cleanup is gone. Allowlist tests were replaced by tests of the new rule.

## T-045 — Ensure the IR emitter mode before every capture and fail closed without illumination [done]
- Refs: AC-039, AC-011
- Files: crates/sensor-adapter-ir/src/lib.rs, crates/sensor-adapter-ir/src/msxu.rs, crates/sensor-adapter-ir/src/emitter_xu.rs, crates/sensor-adapter-ir/src/illumination.rs, crates/openhello-plugin-abi/src/lib.rs, crates/openhellod/src/plugin_loader.rs, scripts/install.sh, .spec/features/face-recognition-proof/spec.md, .spec/features/face-recognition-proof/design.md
- Model: claude-sonnet-5
- Effort: high
- Notes: owner rule (2026-10-21): a controllable IR emitter is on whenever the camera is in use. On `2b7e:c757` the face-auth control (unit 7, selector 6) comes up in mode 1 (emitter off) after every power-up; mode 2 (byte 2) is alternating. `MsxuEmitter::ensure` runs before the stream starts: reads length, current and maximum, does nothing when the mode is 2, otherwise requires capability and maximum support, writes mode 2 and confirms by read-back. A controllable emitter admits frames only after the probe sees lit/unlit swings (flat warm-up and ambient frames fail with `NoAlternation`). `OPENHELLO_IR_EMITTER_ALLOW_WRITE` is obsolete and ignored. Error reasons reach the daemon log through the optional `openhello_sensor_last_error` export; ABI numbers are unchanged.

## T-046 — Cancelable capture and one coherent time budget [done]
- Refs: AC-040, AC-041
- Files: crates/openhellod/src/core.rs, crates/openhellod/src/dbus_service.rs, crates/openhellod/src/backends.rs, crates/openhellod/Cargo.toml, crates/openhellod/tests/dbus_service.rs, crates/openhello-auth-proto/src/lib.rs, crates/openhello-pam/src/lib.rs, crates/openhello-cli/tests/pam_sudo.rs, Cargo.lock, .spec/features/credential-login-v1b/spec.md, .spec/features/credential-login-v1b/design.md, .spec/features/credential-login-v1b/windows-hello-alignment.md
- Model: claude-sonnet-5
- Effort: high
- Notes: found on the VM (2026-10-21): the module gave up after 4 s while `openhellod` kept capturing 8-12 s, and calls abandoned by it still waited for the core mutex and ran later, so the camera and the emitter blinked after the unlock. `Verify` and `Identify` now watch the caller's unique name on the bus (`NameOwnerChanged` plus `NameHasOwner`), check it before every frame and before a queued call starts, always end the engine session and deliver no ticket to a caller that left. The attempt budget (10 s, `FACE_ATTEMPT_BUDGET`) is shared by daemon and module; the module waits budget + 2 s for the verdict and has a 15 s total that includes the keyd signature (design.md). No interface-specific code and no message.

## T-047 — Up to three recognition attempts per authentication request [done]
- Refs: AC-042, AC-043, AC-041
- Files: crates/openhellod/src/core.rs, .spec/features/credential-login-v1b/spec.md, .spec/features/credential-login-v1b/design.md
- Model: claude-sonnet-5
- Effort: high
- Notes: owner decision (2026-10-21), replacing the first design of this task (persistent per-user counter, state file, `pam_sm_setcred` notification and a reset method, all discarded and recorded in design.md as deferred, ASM-016). One request makes up to three attempts, each with a new engine session that is always ended; the first acceptance stops it, three rejections refuse at once so the module falls to the password; engine and camera errors and cancellation are not attempts; the three attempts share the 10 s budget of T-046 on an injectable clock (ASM-015). `pam_sm_setcred` stays `PAM_IGNORE`.

## T-048 — Release the camera as soon as the request is decided [done]
- Refs: AC-044, AC-011
- Files: crates/openhellod/src/core.rs, crates/openhellod/src/backends.rs, crates/openhellod/src/plugin_loader.rs, crates/sensor-adapter-ir/src/lib.rs, crates/sensor-adapter-ir/src/lazy.rs, crates/openhello-plugin-abi/src/lib.rs, .spec/features/credential-login-v1b/spec.md
- Model: claude-sonnet-5
- Effort: medium
- Notes: owner policy (2026-10-21): the camera stays on for the minimum time. The camera used to stay open for the 3 s idle period after the last frame (released by a thread polling every 500 ms). `SensorInterface` gains `release` (plugin ABI 3); `authenticate` calls it on every exit path, and enroll commit/discard call it too. The idle release stays as a safety net for enrollment captures.

## T-049 — A user service resolves its locality through the user's logind display session [done]
- Refs: AC-028
- Files: crates/openhello-pam/src/session.rs, crates/openhello-pam/src/lib.rs
- Model: claude-sonnet-5
- Effort: low
- Notes: found on the VM (2026-10-21): the polkit dialog runs `polkit-agent-helper-1` inside the agent's user service (cgroup `user@UID.service/...`, no `session-N.scope`), with a cleared environment and no TTY, so the module returned `not-local` and polkit never tried the face. When the cgroup has no session scope but names `user-UID.slice`, the module reads the user's `DISPLAY=` session from logind and applies the same `REMOTE=` rule. No desktop-specific data; a missing or empty `DISPLAY=` stays unknown (silent ignore).

## T-050 — Remove the orphaned NSS provisioning and pam_pkcs11 configuration [done]
- Refs: AC-027
- Files: crates/openhello-keyd/src/certificate.rs, crates/openhello-keyd/src/provision.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/src/config.rs, crates/openhello-keyd/src/tpm.rs, crates/openhello-keyd/tests/certificate.rs, scripts/pam-survey.sh
- Model: claude-sonnet-5
- Effort: low
- Notes: `pam_openhello` verifies in pure Rust, so nothing reads the NSS trust database any more. Removed: `nss_dir` and `certutil` from `KeydConfig` and from the `OPENHELLO_KEYD_NSS_DIR` and `OPENHELLO_KEYD_CERTUTIL` variables, `import_trusted`, `remove_trusted`, the certutil runner, the NSS provisioning test, the two `pam_pkcs11` packaging files and the `pam_pkcs11.so` and `certutil` lines of the survey script. Kept: the PKCS#11 proxy crate, the token socket and the certificate and subject map, which keep their own tests.

## T-051 — Default token socket when the PAM config file is absent [done]
- Refs: AC-045
- Files: crates/openhello-pam/src/lib.rs, .spec/features/credential-login-v1b/spec.md
- Model: claude-sonnet-5
- Effort: low
- Notes: found on a freshly reset VM (2026-10-21): `sudo` never asked for the face and logged `reason=keyd-unavailable`, because the setuid path reads the keyd socket only from root-owned `/etc/openhello/pkcs11.conf`, which `install.sh` never created (earlier VMs had it by hand). The module now falls back to the compiled default `/run/openhello/keyd-token.sock` when the file is absent. The shared `config.rs` of the PKCS#11 crate is unchanged. T-050 removed the unused template `packaging/pam/pkcs11.conf`; it was never installed.

## T-052 — The login screen's helper counts as a local session [done]
- Refs: AC-028
- Files: crates/openhello-pam/src/session.rs, crates/openhello-pam/src/lib.rs, .spec/features/credential-login-v1b/lockscreen.md
- Model: claude-sonnet-5
- Effort: low
- Notes: the greeter's helper runs as root in the display manager's service cgroup with no session scope or display variables, so the module ignored it (`not-local`). When no other signal decides, a logind session with `CLASS=greeter` and `REMOTE=0` makes the process local. Proven on the plasmalogin VM (2026-10-22): the face logs in after Enter with an empty password. An automatic Enter through `/dev/uinput` worked but was removed by owner decision (fragile, extra attack surface); the manual Enter stays.

## T-053 — At the login screen the face is tried only when the password is empty [done]
- Refs: AC-028
- Files: crates/openhello-pam/src/lib.rs, crates/openhello-pam/src/session.rs, crates/openhello-pam/src/debug.rs, .spec/features/credential-login-v1b/lockscreen.md
- Model: claude-sonnet-5
- Effort: low
- Notes: found on the VM (2026-10-22): the module is `sufficient` and runs before the password, so at the login screen it opened the camera and accepted the face whatever was typed (a wrong password logged in; a correct one still lit the camera). For the login manager's helper (no user session, a local `CLASS=greeter` session in logind) the module now reads the submitted password with `pam_get_authtok` and acts only when it is empty; otherwise it returns `password-typed` (ignore) and `pam_unix` decides. Unreadable password: ignore. Proven on the plasmalogin VM. Greeters that start PAM on user selection (GDM, LightDM, greetd) get the same rule, not verified.

## T-055 — Ten seconds only wait for a face; the three attempts have their own window [done]
- Refs: AC-041
- Files: crates/openhellod/src/core.rs, crates/openhello-auth-proto/src/lib.rs, crates/openhello-pam/src/lib.rs, crates/openhello-cli/tests/pam_sudo.rs
- Model: claude-sonnet-5
- Effort: low
- Notes: owner decision (2026-10-22). One clock for the whole request cut the third attempt of a stranger short (48 frames take about 9 s). The 10 s `FACE_ATTEMPT_BUDGET` now ends at the first scored frame; from there `FACE_DECISION_BUDGET` (10 s) bounds the three attempts, so a request lasts at most 20 s. The module's verdict wait grew to 22 s.

## T-056 — Ctrl+C stops the camera in `sudo` and in enrollment [done]
- Refs: AC-046, AC-047
- Files: crates/openhello-pam/src/lib.rs, crates/openhello-pam/src/debug.rs, crates/openhellod/src/dbus_service.rs, crates/openhellod/tests/dbus_service.rs, crates/openhello-cli/tests/pam_sudo.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: owner report (2026-10-22): Ctrl+C could not stop the camera. In `sudo` the module blocked inside `pam_authenticate` until the daemon answered (the program's handler only set a flag): it now handles SIGINT and SIGTERM for the duration of the wait, closes its bus connection (also on timeout) and re-raises the signal. In enrollment the daemon never learned that the CLI had gone and the camera stayed on until the 3 s idle release: it now watches the owner of each enrollment session. Verified on the KDE neon VM with real `sudo`, `openhello-cli verify` and `openhello-cli enroll` (2026-10-22): the camera stops within about a second of Ctrl+C. The module also lifts a SIGINT block the caller sets while it authenticates and restores the mask afterwards.
