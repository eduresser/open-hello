# Portability research: path discovery across distros

Research only; no code changed. Marks: **C** = confirmed by the cited source or measured on this machine (openSUSE Tumbleweed); **I** = inferred, needs a VM check. Fetched 2026-10-21.

## 1. Conclusion

- Two kinds of paths exist. **Our own files** (daemon binaries, units, D-Bus policy, polkit action) have one stable, distro-neutral location each; fix them. **Third-party files** (PAM module dir, PKCS#11 module, tpm2 tools, python modules) differ per distro; discover them on the target, never list them in code.
- Upstream projects never keep per-distro path lists. They use pkg-config variables (systemd, dbus, polkit, p11-kit), a single configure option with a `$libdir`-derived default (linux-pam, sssd), or a registry (p11-kit).
- PKCS#11 has a registry: `p11-kit`. A module is registered by a one-line file and found by name; no path in the consumer.

## 2. Mechanisms and who uses them

| Mechanism | Used by | Evidence | Mark |
|---|---|---|---|
| pkg-config variable | systemd `systemdsystemunitdir` = `${prefix}/lib/systemd/system` | [systemd.pc.in](https://raw.githubusercontent.com/systemd/systemd/main/src/core/systemd.pc.in); [daemon(7)](https://www.freedesktop.org/software/systemd/man/latest/daemon.html) says "install units in the directory returned by pkg-config" | C |
| pkg-config variable | polkit `actiondir`/`policydir` = `@datarootdir@/polkit-1/actions/` | [polkit-gobject-1.pc.in](https://raw.githubusercontent.com/polkit-org/polkit/main/data/polkit-gobject-1.pc.in) | C |
| pkg-config variable | dbus-1 `datadir`, `sysconfdir`, `system_bus_services_dir` | `pkg-config --print-variables dbus-1` on this machine; fprintd derives `dbus_data_dir / 'dbus-1/system.d'` from `dbus_dep.get_variable('datadir')` ([fprintd meson.build](https://sources.debian.org/data/main/f/fprintd/1.94.5-2/meson.build)) | C |
| pkg-config variable | p11-kit `p11_module_path`, `p11_module_configs` | [p11-kit-1.pc.in](https://raw.githubusercontent.com/p11-glue/p11-kit/master/p11-kit/p11-kit-1.pc.in); measured here: `/usr/lib64/pkcs11` and `/usr/share/p11-kit/modules` | C |
| pkg-config consumer | tpm2-pkcs11 `PKG_CHECK_VAR([P11_MODULE_PATH], [p11-kit-1], [p11_module_path])`, installs `.so` there and the `.module` file in `P11_CONFIGS_PATH` | [configure.ac](https://raw.githubusercontent.com/tpm2-software/tpm2-pkcs11/master/configure.ac), [Makefile.am](https://raw.githubusercontent.com/tpm2-software/tpm2-pkcs11/master/Makefile.am) | C |
| pkg-config consumer | OpenSC reads `p11_system_config_modules` from p11-kit-1 | [configure.ac](https://raw.githubusercontent.com/OpenSC/OpenSC/master/configure.ac) | C |
| Registry file | p11-kit: `/usr/share/p11-kit/modules/*.module` (packages) and `/etc/pkcs11/modules` (admin); `module:` value may be relative and then resolves against the default module dir | [pkcs11-conf](https://p11-glue.github.io/p11-glue/p11-kit/manual/pkcs11-conf.html) (page suppresses the literal paths; defaults confirmed in [meson.build](https://raw.githubusercontent.com/p11-glue/p11-kit/master/meson.build): `pkgdatadir/'modules'`, `sysconfdir/'pkcs11'/'modules'`, `libdir/'pkcs11'`) | C |
| Registry file, tpm2 | tpm2-pkcs11 ships `misc/p11-kit/tpm2_pkcs11.module` containing `module: libtpm2_pkcs11.so`, `critical: no` (relative: no path at all) | [tpm2_pkcs11.module](https://raw.githubusercontent.com/tpm2-software/tpm2-pkcs11/master/misc/p11-kit/tpm2_pkcs11.module) | C |
| Registry query | `p11-kit list-modules` prints `path:` per module | measured here (`path: /usr/lib64/pkcs11/p11-kit-trust.so`) | C |
| Configure option, default from `$libdir` | linux-pam `securedir = libdir / 'security'`; sssd `pammoddir=$libdir/security` | [linux-pam meson.build](https://raw.githubusercontent.com/linux-pam/linux-pam/master/meson.build), [sssd configure.ac](https://raw.githubusercontent.com/SSSD/sssd/master/configure.ac) | C |
| Hardcoded per-OS default | pam_u2f: `*linux*) PAMDIR="/lib/x86_64-linux-gnu/security"`, override `--with-pam-dir` | [configure.ac](https://raw.githubusercontent.com/Yubico/pam-u2f/master/configure.ac) | C |
| Meson options only | fprintd libexec: `get_option('prefix') / get_option('libexecdir')` | fprintd meson.build (link above) | C |
| Config dir from options | Howdy: `prefix/sysconfdir/howdy`; PAM module install dir not visible in the root file | [meson.build](https://raw.githubusercontent.com/boltgolt/howdy/master/meson.build); subdir build files returned 404 | C (config), unknown (PAM dir) |
| dlopen by soname | systemd TPM2 code: `"libtss2-esys.so.0"`, `"libtss2-tcti-<driver>.so.0"` with no directory | [tpm2-util.c](https://raw.githubusercontent.com/systemd/systemd/main/src/shared/tpm2-util.c) (systemd-cryptenroll builds on it) | C (library), I (cryptenroll) |
| dlopen search order | no slash: `LD_LIBRARY_PATH`, RUNPATH, `/etc/ld.so.cache`, `/lib`, `/usr/lib` | [dlopen(3)](https://man7.org/linux/man-pages/man3/dlopen.3.html) | C |
| PAM absolute path | `module-path` beginning with `/` is a full filename; otherwise relative to the default module dir | [pam.conf(5)](https://man7.org/linux/man-pages/man5/pam.conf.5.html) | C |

Not available as a mechanism:

- `pam.pc` has **no** module-dir variable. linux-pam's `pkgconfig.generate(... filebase: 'pam')` passes no `variables:`; `securedir` only goes into a compile define ([libpam/meson.build](https://raw.githubusercontent.com/linux-pam/linux-pam/master/libpam/meson.build)). On this machine `pkg-config pam` does not even exist (C). So no `pkg-config --variable=moduledir pam`.
- `systemd-path` lists runtime/search paths, not install dirs ([systemd-path(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-path.html), page gives no names) (C, limited).

## 3. Layout facts

| Fact | Source | Mark |
|---|---|---|
| systemd dropped split-usr; units install under `${prefix}/lib/systemd/system` | systemd.pc.in comment (link above) | C |
| Packages put units in `/usr/lib/systemd/system`; `/etc/systemd/system` is admin-only and masks package updates | [systemd.unit(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) | C |
| D-Bus: third-party policy goes to `/usr/share/dbus-1/system.d` (since dbus 1.10); `/etc/dbus-1/system.d` is the admin override and package installs there are deprecated | [dbus-daemon(1)](https://dbus.freedesktop.org/doc/dbus-daemon.1.html) | C |
| Debian multiarch moves arch-specific libs from `{/,/usr/}{lib,lib32,lib64}` to `{/,/usr/}lib/<multiarch-name>/`; `$(DEB_HOST_MULTIARCH)` in `debian/rules` | [Multiarch/Implementation](https://wiki.debian.org/Multiarch/Implementation) | C |
| NixOS references PAM modules by absolute store path (`modulePath = "${pkgs.pam_u2f}/lib/security/pam_u2f.so"`) | [nixpkgs pam.nix](https://git.alioth.systems/alioth/nixpkgs/commits/commit/6c610e01f1dc8382b4072885668c71b1ad709201/nixos/modules/security/pam.nix) (search snippet) | C |
| Guix, Alpine path conventions | not fetched | I |

## 4. Rust specifics

| Question | Answer | Source | Mark |
|---|---|---|---|
| Detect PAM dir in `build.rs` | Not possible via pkg-config (see section 2). Do not try; the cdylib name `libpam_openhello.so` -> `pam_openhello.so` is fixed, destination is an install-time decision | linux-pam sources above | C |
| `pkg-config` crate and variables | `Library` exposes libs/link paths/include paths/version only; no arbitrary-variable API. For a variable use `Command::new("pkg-config").args(["--variable=p11_module_path","p11-kit-1"])` in `build.rs` | [docs.rs Library](https://docs.rs/pkg-config/latest/pkg_config/struct.Library.html) (page covers `Library` only) | C (Library), I (rest of crate) |
| Build-time vs target | A value baked in `build.rs` reflects the build machine, not the install machine; useless for a prebuilt binary shipped to many distros | reasoning | I |
| cargo-deb | `--multiarch=same`: asset `dest` starting with `usr/lib` becomes `usr/lib/$tuple`; units via `[package.metadata.deb.systemd-units]`; `depends = "$auto"` | [cargo-deb README](https://raw.githubusercontent.com/kornelski/cargo-deb/main/README.md) | C |
| cargo-generate-rpm | `dest` is literal (examples `/usr/bin/XXX`); no libdir placeholder documented, so lib64 must be written explicitly; no systemd option, units are plain assets plus scriptlets; auto-req via `find-requires` or `ldd` | [README](https://raw.githubusercontent.com/cat-in-136/cargo-generate-rpm/master/README.md) | C |
| Crate pattern for libs | `-sys` crates use pkg-config for link flags only; install paths are the packager's job | pkg-config crate docs | I |

## 5. Recommendation for open-hello

Rule: one fixed location for what we own, query-on-target for what we do not, and zero path lists in Rust.

| Item | Strategy | Source | Mark |
|---|---|---|---|
| systemd units | Install to `/usr/lib/systemd/system`; never `/etc/systemd/system`. Optionally `pkg-config --variable=systemdsystemunitdir systemd` if present, else the fixed default | daemon(7), systemd.unit(5) | C |
| D-Bus system policy | `/usr/share/dbus-1/system.d`; drop the `/etc/dbus-1/system.d` branch | dbus-daemon(1) | C |
| polkit action | `/usr/share/polkit-1/actions` (the `.pc` value is `@datarootdir@/polkit-1/actions/`, i.e. prefix/share) | polkit-gobject-1.pc.in | C |
| Daemon binaries (libexec) | Own distro-neutral private dir, e.g. `/usr/lib/openhello/` (or keep `/usr/libexec/openhello`); nothing reads it but our units. Write the absolute path into the unit by template substitution at install time (`@LIBEXECDIR@`) | fprintd uses a meson option only (no discovery) | C (fprintd), I (choice) |
| PAM module dir | Install-time, one rule: `$(dirname "$(ldconfig -p \| awk '/libpam\.so\.0/{print $NF; exit}')")/security`. Matches linux-pam default `$libdir/security` on openSUSE (`/usr/lib64`), Debian/Ubuntu (multiarch), Arch (`/usr/lib`). Keep the probe list only as a fallback | linux-pam meson.build, sssd configure.ac, Debian multiarch | C (default rule), I (ldconfig one-liner) |
| PAM line in `/etc/pam.d` | Optional: reference `pam_openhello.so` by absolute path, so the module can live anywhere; SELinux labelling of a non-standard dir is untested | pam.conf(5) | C (syntax), I (SELinux) |
| PKCS#11 module (keyd) | Runtime order: (1) config/env `OPENHELLO_PKCS11_MODULE`; (2) `p11-kit list-modules`, take the entry whose `path:` ends in `libtpm2_pkcs11.so`; (3) `dlopen("libtpm2_pkcs11.so")` by name via ld cache; (4) installer fallback `$(pkg-config --variable=p11_module_path p11-kit-1)/libtpm2_pkcs11.so`. The installer writes the resolved path to `/etc/openhello/keyd.toml`, so the daemon reads one value | p11-kit pc and docs, tpm2-pkcs11 `.module`, dlopen(3) | C (each step), I (ordering) |
| PKCS#11 alternative | Load `p11-kit-proxy.so` (`proxy_module=@libdir@/p11-kit-proxy@p11_shlext@`) and pick the tpm2 token by label; zero tpm2 paths, but adds a slot-selection step and needs the tpm2 package's `.module` registered | p11-kit-1.pc.in | C (proxy), I (slot logic) |
| `pam_pkcs11` module path (`pam_pkcs11.so` and its `config_file`) | Same PAM dir rule as above; it lives in the PAM dir (or `pam_pkcs11/` sibling) of the target | pam_pkcs11 not fetched | I |
| tpm2-pkcs11 python modules | Capability probe: `python3 -c "import tpm2_pkcs11"`; the interpreter path is whatever `command -v python3` returns. Package names only appear in the error hint | tpm2_ptool.py imports `tpm2_pkcs11` only | C |
| `tpm2_ptool` binary / tools package name | `command -v tpm2_ptool` (the name differs: `tpm2-pkcs11-tools` vs `libtpm2-pkcs11-tools`); map name -> package only inside the hint message or inside deb/rpm metadata | user report; no upstream source needed | I |
| certutil / nss-tools | `command -v certutil`; same hint-only mapping | reasoning | I |
| Debian/RPM packaging | Same binaries, two asset tables: `.deb` with `--multiarch=same` for the PAM module (`usr/lib/security` becomes `usr/lib/<tuple>/security`; verify, since cargo-deb only rewrites `usr/lib*` prefixes), `.rpm` with explicit `/usr/lib64/security`. Units/D-Bus/polkit identical in both | cargo-deb and cargo-generate-rpm READMEs | C (rewrite rule), I (security subdir) |
| NixOS / Guix | Out of scope for the script; declarative module referencing store paths (`modulePath`) | nixpkgs pam.nix | C |

Plan with minimum delta: (1) replace `MODULE_DIRS` in `crates/openhello-keyd/src/tpm.rs` with config value then `p11-kit list-modules` then soname; (2) in `scripts/install.sh` drop `/etc` unit/D-Bus variants and compute PAM dir with the ldconfig rule; (3) template the unit `ExecStart` with the chosen libexec dir; (4) keep a short fallback list only in the installer, never in Rust.

## 6. Blocked or incomplete pages

- gitlab.freedesktop.org (fprintd `meson.build`, `meson_options.txt`): Anubis "Access Denied". Used the Debian copy at sources.debian.org; it shows `pam_modules_dir` only in a print statement, so fprintd's PAM-dir default is unconfirmed.
- Howdy: `howdy/src/pam/meson.build`, `main.cc`, `meson_options.txt` returned 404; only the root `meson.build` was read.
- FHS 3.0 (refspecs.linuxfoundation.org): Anubis block. `systemd file-hierarchy(7)` gave no library guidance in the fetched text.
- `dbus-1.pc.in`, `pam.pc.in`: 404 on GitHub raw; replaced by local `pkg-config --print-variables dbus-1` and by linux-pam `libpam/meson.build`.
- Not researched in depth: Alpine, Guix, usrmerge page itself, systemd-cryptenroll source (inferred from `tpm2-util.c`), pam-sys crate.
