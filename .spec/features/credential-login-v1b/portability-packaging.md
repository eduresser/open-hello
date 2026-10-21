# Portability research: distribution and packaging strategy

Research only; no code or spec changed. Marks: **C** = confirmed by the cited source (or measured/read in this repo, or on this machine: openSUSE Tumbleweed); **I** = inferred, needs a check. Fetched 2026-10-21. Complements `portability.md` (PAM managers and lockers).

Blocked pages (Anubis bot wall): gitlab.freedesktop.org (fprintd upstream), docs.fedoraproject.org, wiki.archlinux.org, salsa.debian.org. Replaced by Fedora/Debian/openSUSE package sources and GitHub mirrors; Arch Rust guideline claims are therefore **I**.

## 1. Summary

- Every comparable project ships **one upstream source with build-time path options, and each distro writes its own native package** (rpm spec, debian/, PKGBUILD, nix expression). Nobody ships a per-distro install script as the main path (C, section 2).
- The differences that bit open-hello are the same ones those projects solve with **build-time variables**, not runtime detection: PAM module dir, PKCS#11 dir, unit dir, libexec (C, 3).
- Flatpak and Snap do not fit a daemon + PAM module + system D-Bus policy (C for Flatpak sandbox, C for Snap classic semantics; the conclusion is I).
- For a solo owner: build **one tarball with a neutral layout**, plus thin deb/rpm/pkg wrappers from **one definition** (nfpm or cargo-deb + cargo-generate-rpm), published via **OBS** (or COPR + AUR); distro-quality inclusion is a later, optional step.

## 2. How comparable projects are distributed

| Project | Upstream build | Native packages | Who packages | PAM integration | Marks |
|---|---|---|---|---|---|
| Howdy | meson (`pam_dir`, `install_pam_config`, `with_polkit` options) | Ubuntu PPA `ppa:boltgolt/howdy`; Debian: `.deb` attached to GitHub Releases (built by `debian/rules` + Python `postinst`); Fedora COPR `principis/howdy`; Arch AUR; openSUSE wiki; nixpkgs | Mixed: upstream (.deb), community (COPR @luyatshimbalanga, openSUSE @dmafanasyev, AUR "Maintainer wanted"), nixpkgs contributors | Debian: `pam-auth-update` profile `howdy.in` (Primary, priority 512, `@pamdir@` substituted at build); others: manual edit | C: [README](https://github.com/boltgolt/howdy), [meson_options.txt](https://github.com/boltgolt/howdy/blob/master/meson_options.txt), [pam/meson.build](https://github.com/boltgolt/howdy/blob/master/howdy/src/pam/meson.build), [howdy.in](https://github.com/boltgolt/howdy/blob/master/howdy/src/pam-config/howdy.in), [debian/rules](https://github.com/boltgolt/howdy/blob/master/howdy/debian/rules), [PKGBUILD](https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=howdy), [nixpkgs package.nix](https://github.com/NixOS/nixpkgs/blob/master/pkgs/by-name/ho/howdy/package.nix), [COPR](https://copr.fedorainfracloud.org/coprs/principis/howdy/) |
| fprintd | meson: `-Dpam=true -Dpam_modules_dir=... -Dsystemd_system_unit_dir=... -Ddbus_service_dir=...` | In every distro archive; each distro owns its spec/rules | Distro maintainers (Fedora, openSUSE, Debian, nixpkgs) | Debian: `libpam-fprintd` postinst runs `pam-auth-update --package`; Fedora: `authselect disable-feature with-fingerprint` in `%postun pam`; openSUSE: `pam-config -d --fprintd` in `%postun pam`; NixOS: `services.fprintd.enablePam` | C: [Fedora spec](https://src.fedoraproject.org/rpms/fprintd/raw/rawhide/f/fprintd.spec), [openSUSE spec](https://build.opensuse.org/public/source/openSUSE:Factory/fprintd/fprintd.spec), [Debian rules](https://sources.debian.org/data/main/f/fprintd/1.94.5-4/debian/rules), [Debian postinst](https://sources.debian.org/data/main/f/fprintd/1.94.5-4/debian/libpam-fprintd.postinst), [nixpkgs package.nix](https://github.com/NixOS/nixpkgs/blob/master/pkgs/by-name/fp/fprintd/package.nix), [fprintd.nix](https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/security/fprintd.nix) |
| pam_u2f (Yubico) | autotools (`--with-pam-dir`) and CMake (>= 1.4.0) | Distro archives (Ubuntu `libpam-u2f`, Fedora `pam-u2f`); Yubico PPA `ppa:yubico/stable` for newer versions | Distros + Yubico PPA | None shipped: README tells the admin to add `auth sufficient pam_u2f.so` to `/etc/pam.d/` | C: [README](https://raw.githubusercontent.com/Yubico/pam-u2f/master/README), [Fedora spec](https://src.fedoraproject.org/rpms/pam-u2f/raw/rawhide/f/pam-u2f.spec) |
| tpm2-pkcs11 | autotools (`--with-p11kitmoduledir`, `--with-storedir`) | Distro archives (Fedora spec, Debian, Arch, openSUSE) | Distro maintainers | n/a (PKCS#11 module) | C: [configure.ac](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/configure.ac), [Fedora spec](https://src.fedoraproject.org/rpms/tpm2-pkcs11/raw/rawhide/f/tpm2-pkcs11.spec) |
| sssd | autotools (`--with-*`) | Upstream carries a spec for Fedora/RHEL (`contrib/sssd.spec.in`); Debian has its own source package (2.10.1 in trixie) | Red Hat (spec), Debian maintainers | authselect profile `sssd` (Fedora/RHEL); pam-auth-update elsewhere | C: [sssd.spec.in](https://raw.githubusercontent.com/SSSD/sssd/master/contrib/sssd.spec.in), [Fedora spec](https://src.fedoraproject.org/rpms/sssd/raw/rawhide/f/sssd.spec), [Debian sources](https://sources.debian.org/api/src/sssd/) |
| linux-enable-ir-emitter | C++ (meson), static release | Release tarball extracted into `/usr/local/bin`; no PAM module of its own; documents a `grep -rl howdy /etc/pam.d` edit | Upstream | Manual | C: [README](https://github.com/EmixamPP/linux-enable-ir-emitter#installation) |
| authselect / pam-auth-update / pam-config | The manager is the integration point | Each distro ships its own manager; packages drop a profile and call it from scripts | Distros | See `portability.md` section 2 | C ([portability.md](portability.md)) |

Pattern (C): one source, `pam_modules_dir` and unit dir passed by each packager (Fedora `%{_libdir}/security`; Debian `/usr/lib/$(DEB_HOST_MULTIARCH)/security`; openSUSE `%{_pam_moduledir}`; nixpkgs `$out/lib/security`). This is why a single hardcoded PAM path cannot work.

### 2.1 Delivery channels for a daemon + PAM module

| Channel | Viable? | Why | Marks |
|---|---|---|---|
| Native package in distro archive | Yes, long term | How fprintd, sssd, pam_u2f, tpm2-pkcs11 ship; needs a distro maintainer, vendored/packaged Rust deps and no network at build | C (projects above); effort I |
| OBS (openSUSE Build Service), one project | Yes | Builds RPM, DEB, Arch and APK repos from the same account; deb uses separate `debian.*` files, not the spec | C: [OBS formats](https://openbuildservice.org/help/manuals/obs-user-guide/cha-obs-package-formats); Rust offline builds via [obs-service-cargo_vendor](https://github.com/openSUSE/obs-service-cargo_vendor) and [Packaging Rust Software](https://en.opensuse.org/Packaging_Rust_Software) |
| COPR (Fedora) | Yes | Howdy uses it; rpkg/SCM build from a spec | C: [COPR howdy](https://copr.fedorainfracloud.org/coprs/principis/howdy/) |
| PPA (Ubuntu) | Yes, needs a source package | Howdy and Yubico use PPAs; Launchpad builds from a Debian source package (I) | C: Howdy README, pam-u2f README; source-package rule I |
| AUR (Arch) | Yes | Howdy and pam_pkcs11 are AUR-only; PKGBUILD is a source recipe; pam_pkcs11 is not in the official repos (search empty) | C: [AUR rpc](https://aur.archlinux.org/rpc/v5/search/pam_pkcs11?by=name), [archlinux.org search](https://archlinux.org/packages/search/json/?q=pam_pkcs11) |
| nixpkgs + NixOS module | Yes, in a distinct model | nixpkgs packages Howdy and fprintd; NixOS wires PAM through `security.pam.services` options, not files | C: [pam.nix](https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/security/pam.nix) |
| Flatpak | No | Sandbox has no system D-Bus, no host services; owning a system bus name or loading into host PAM is outside the model | C: [Flatpak sandbox docs](https://docs.flatpak.org/en/latest/sandbox-permissions.html) for bus/services; "no PAM" conclusion I |
| Snap | No (strict); classic is possible but weak | Classic behaves like a host package and needs Canonical vetting for the store; PAM modules load from the host, with known library-conflict pitfalls | C: [classic confinement](https://snapcraft.io/docs/explanation/security/classic-confinement/index.html), [forum thread](https://forum.snapcraft.io/t/pam-account-management-error/14026); conclusion I |
| Bash installer | Dev only | Distro-specific dependency names and paths inside one script (today `install_deps` has four branches); no upgrade/removal tracking (I) | C: `scripts/install.sh` |

## 3. Tools that generate several formats from one definition

| Tool | Outputs | Dir variables | Per-distro dependency names | Scripts / systemd | Limits | Marks |
|---|---|---|---|---|---|---|
| [cargo-deb](https://raw.githubusercontent.com/kornelski/cargo-deb/main/README.md) | deb | Explicit asset paths; `usr/lib` becomes `usr/lib/<triplet>` when multiarch is enabled | `depends = "$auto"` plus manual; `[package.metadata.deb.variants.NAME]` for alternatives | `maintainer-scripts`, `triggers-file`; [systemd-units](https://raw.githubusercontent.com/kornelski/cargo-deb/main/systemd.md) generates enable/start/restart fragments (needs `#DEBHELPER#`) | Debian family only; Rust 1.76+; cannot target older Debian by cross-compiling | C |
| [cargo-generate-rpm](https://raw.githubusercontent.com/cat-in-136/cargo-generate-rpm/master/README.md) | rpm | Explicit asset paths (`/usr/lib64/...` is hand-written) | `requires` list with version operators and rich deps; auto-req via `find-requires` or `ldd` | `pre_install_script`, `post_install_script`, `pre_uninstall`, `post_uninstall`, `*_trans`; no systemd macro handling documented | RPM only; no `%systemd_post` macros; no CentOS 7 | C |
| [nfpm](https://nfpm.goreleaser.com/docs/configuration/) | deb, rpm, apk, archlinux, ipk | `${VAR}` expansion in `depends`, `version`, and in `contents` with `expand: true` | `overrides.deb/rpm/apk/archlinux.depends`; `contents[].packager` filter for per-format files | `preinstall`, `postinstall`, `preremove`, `postremove`; deb triggers; rpm `pretrans`/`posttrans`; no systemd section (only `Requires(post): systemd`) | One YAML, not distro-policy packages (no dbgsym, no source package, no `%systemd_*` macros) (I) | C |
| [fpm](https://fpm.readthedocs.io/en/latest/) | deb, rpm, pacman, apk, tar, ... | Command-line flags | Per-run flags | Per-format script flags | "a tool to help you make packages for existing systems with less effort": quick wrapper, not policy packages; last release 1.17.0 (2025-10-02) | C (quote); policy limit I |
| OBS with specs | rpm, deb (`debian.*`), Arch (PKGBUILD), apk | `%{_libdir}`, `%{_pam_moduledir}` on RPM side | Spec `BuildRequires`/`Requires` with `%if` per distro | Full RPM macros (`%service_add_post` on SUSE, `%systemd_post` on Fedora); deb separate | One definition per format family (spec + debian dir + PKGBUILD); builds and hosts repos | C: [OBS formats](https://openbuildservice.org/help/manuals/obs-user-guide/cha-obs-package-formats) |
| PKGBUILD / [cargo-aur](https://docs.rs/cargo-aur/latest/cargo_aur/) | Arch package / PKGBUILD | `/usr/lib` | `depends` in PKGBUILD | `.install` file | cargo-aur only generates the PKGBUILD from `Cargo.toml` | C (cargo-aur); Arch rules I (wiki blocked) |
| Nix flake (e.g. crane) | Nix store paths, NixOS module | `$out` | `buildInputs` | NixOS module generates units/PAM | Not deb/rpm; needs a module to integrate PAM | I (crane README not fetched) |

Dependency names that already differ in `scripts/install.sh` (C, repo):

| Need | Debian/Ubuntu | Fedora | openSUSE | Arch |
|---|---|---|---|---|
| TPM tools | `tpm2-tools` | `tpm2-tools` | `tpm2.0-tools` | `tpm2-tools` |
| PKCS#11 module | `libtpm2-pkcs11-1`, `libtpm2-pkcs11-tools` | `tpm2-pkcs11`, `tpm2-pkcs11-tools` | `tpm2-pkcs11` | `tpm2-pkcs11` |
| `pam_pkcs11` | `libpam-pkcs11` | `pam_pkcs11` | `pam_pkcs11` | AUR only |
| NSS tools (certutil) | `libnss3-tools` | `nss-tools` | `mozilla-nss-tools` | `nss` |
| Polkit | `polkitd` | `polkit` | `polkit` | `polkit` |
| swtpm TCTI | `libtss2-tcti-swtpm0` | `tpm2-tss` | `libtss2-tcti-swtpm0` | `tpm2-tss` |

Directory differences (C unless marked):

| Item | Debian/Ubuntu | Fedora | openSUSE | Arch | NixOS |
|---|---|---|---|---|---|
| PAM module dir | `/usr/lib/<triplet>/security` ([rules](https://sources.debian.org/data/main/f/fprintd/1.94.5-4/debian/rules)) | `%{_libdir}/security` | `%{_pam_moduledir}` (older SLE: `/%{_lib}/security`) | `/usr/lib/security` (I) | `$out/lib/security` |
| PKCS#11 dir | `/usr/lib/<triplet>/pkcs11` (I) | `/usr/lib64/pkcs11` (this machine reports that path for Tumbleweed too) | `/usr/lib64/pkcs11` (measured) | `/usr/lib/pkcs11` (I) | store path |
| Unit dir | `/usr/lib/systemd/system` | `%{_unitdir}` = `/usr/lib/systemd/system` (measured `rpm -E`) | same | same | `$out/lib/systemd/system` |
| D-Bus policy / polkit | `/usr/share/dbus-1/system.d`, `/usr/share/polkit-1/actions` (all four, via `pkg-config dbus-1`/`polkit-gobject-1`; measured `datadir=/usr/share`) | same | same | same | `$out/share/...` |
| libexec | `/usr/lib/<pkg>` by convention (I; [dh-exec rules](https://sources.debian.org/src/dh-exec/0.30/debian/rules) pass `--libexecdir=/usr/lib`) | `/usr/libexec` | `/usr/libexec` | `/usr/lib/<pkg>` (I) | `$out/libexec` |

Neutral options (derived from C facts, so I as a design choice):
- PKCS#11: read it at build time with `pkg-config --variable=p11_module_path p11-kit-1` (variable exists in [p11-kit-1.pc.in](https://raw.githubusercontent.com/p11-glue/p11-kit/master/p11-kit/p11-kit-1.pc.in); measured `/usr/lib64/pkcs11` here) or let the packager pass it.
- Units: [systemd.pc](https://raw.githubusercontent.com/systemd/systemd/main/src/core/systemd.pc.in) defines `systemd_system_unit_dir=${prefix}/lib/systemd/system`; `/usr/lib/systemd/system` works on all four.
- Private helper binaries: UAPI.9 says `/usr/libexec` "its use is not encouraged" and recommends a subdirectory of `/usr/lib/` ([spec](https://uapi-group.org/specifications/specs/linux_file_system_hierarchy/)). Using `/usr/lib/openhello/` for helpers removes the libexec difference.
- PAM dir is the one path that truly differs; keep it a **build-time parameter** (like fprintd, Howdy `pam_dir`).

## 4. Matrix and CI

Minimal matrix (priority order; I as recommendation):

| # | Target | Why | Package type | PAM manager |
|---|---|---|---|---|
| 1 | Ubuntu LTS (24.04) | Largest user base; Howdy/pam_u2f PPAs exist | deb | pam-auth-update |
| 2 | Fedora (current) | Second family; COPR; authselect | rpm | authselect |
| 3 | openSUSE Tumbleweed (+ Leap later) | Owner's machine; OBS home | rpm (SUSE macros) | pam-config / manual |
| 4 | Debian stable | Same deb as Ubuntu; check dependency names | deb | pam-auth-update |
| 5 | Arch | AUR, no native `pam_pkcs11` | PKGBUILD | manual |
| 6 | NixOS | Declarative; separate module | flake | `security.pam.services` |

Desktops: none gets code or data; every PAM-based locker or greeter is reached through the common stack (see `portability.md`).

CI without hardware (all I unless a source is cited):

| Layer | Tool | Notes |
|---|---|---|
| Package build | Containers per distro (`ubuntu`, `fedora`, `opensuse/tumbleweed`, `archlinux`) running nfpm or the native build; or OBS itself | `cargo build --release --locked` once, reused |
| Install and file layout | Container: install the package, assert file paths, `pam-auth-update`/`authselect` result, `systemd-analyze verify` on the unit | No systemd needed for layout checks |
| PAM behaviour | [pam_wrapper](https://cwrap.org/pam_wrapper.html) (`PAM_WRAPPER=1`, `PAM_WRAPPER_SERVICE_DIR`, works as a normal user) with `pam_matrix`/pamtest; fprintd tests use `python3-libpamtest` and `pam_wrapper` | C for pam_wrapper; fprintd uses them per the openSUSE and nixpkgs sources above |
| TPM | `swtpm` socket + `tcti=swtpm:...` (this repo already needs `libtss2-tcti-swtpm0`, memory note) | Cryptsetup and ima-evm-utils CI start swtpm; [tpm2-software-container](https://github.com/tpm2-software/tpm2-software-container) has ready images (from search results) |
| Full boot (systemd + D-Bus + polkit) | systemd container via Podman on the runner, or a VM (QEMU/libvirt) | GitHub Actions `container:` does not run systemd as PID 1; the YaST team ran Podman on the runner instead ([post](https://yast.opensuse.org/blog/2023-02-28/systemd-podman-github-ci)) |
| Camera | Replay frames through the `sensor-adapter-ir` test path; real camera only in manual VM tests | Existing project workflow |

## 5. Recommendation

Do not keep "one version per distro". Keep **one binary set, one neutral file layout, thin packages**:

1. **One build**: `cargo build --release --locked` for the 8 crates, producing a single tarball with a staging tree (`usr/bin`, `usr/lib/openhello/*` including helpers and the PKCS#11 library, `usr/share/dbus-1/system.d`, `usr/share/polkit-1/actions`, `usr/lib/systemd/system`, `usr/share/openhello/pam/*`). Units are templated (`@libexecdir@`) so `ExecStart` is not hardcoded (today `openhello-keyd.service` has `/usr/libexec/openhello/...` hardcoded; C, repo).
2. **Only two build-time parameters**: PAM module dir and PKCS#11 module dir (and unit dir default `/usr/lib/systemd/system`). Pass them as environment variables at packaging, like fprintd's `pam_modules_dir`.
3. **Thin per-family packages from one definition**: nfpm YAML with `overrides` for dependency names and `contents[].packager` for family-specific files (pam-auth-update profile for deb; authselect profile for rpm-Fedora; none for SUSE/Arch). Alternative if nfpm is too loose: cargo-deb (deb, with systemd-units) + cargo-generate-rpm (rpm). Native specs only when entering OBS/COPR/distro archives.
4. **Standard maintainer scripts** (same shell logic everywhere, small): create dirs/modes, `systemctl daemon-reload`, enable keyd, reload D-Bus, run the PAM manager, never overwrite mapped libraries, never edit `/etc/pam.d/sudo` by sed (use the manager profile or the include file). Opt-in for wiring PAM, as fprintd does (`Default: no` profile in Debian).
5. **Models and ONNX Runtime are not in the package**: `install.sh` downloads them with SHA-256 at install time. Distro builds and OBS are offline (C for OBS vendoring; I for the rest). Ship a `openhello-fetch-models` step (post-install or CLI command) and keep checksums in the package.
6. **`scripts/install.sh` becomes development-only** (build + stage + install from a checkout), calling the same staging step as the packages.
7. **Channel**: one OBS project (rpm for Fedora/openSUSE, deb for Debian/Ubuntu, Arch) as the primary repo; AUR PKGBUILD by hand; nixpkgs/NixOS module later. No Flatpak/Snap.

Risks:

| Risk | Mitigation |
|---|---|
| PAM dir and pam manager differ per distro; a wrong profile locks logins | Build-time PAM dir; opt-in profile; denylist already in `pam_openhello`; test removal in CI (see `portability.md` check 16) |
| `pam_pkcs11` is not in Arch's official repos (C) and the stack depends on it | Document as AUR dependency; evaluate moving the certificate logic into `pam_openhello` to drop the dependency (I) |
| Debian multiarch path differences for PAM and PKCS#11 | Query `DEB_HOST_MULTIARCH` or `dpkg-architecture` at package time (C source above) |
| Distro archives require vendored/packaged Rust crates and offline builds | Use `cargo vendor` or OBS `cargo_vendor` from day one (C for OBS service) |
| Third-party model licences and download at install | Keep out of the package; separate optional package or step (I) |
| One definition (nfpm) hides distro-policy defects (no dbgsym, no `%systemd_*` macros) | Accept for third-party repos; move to native specs only for archive submission (I) |
| Maintenance load for a solo owner | Matrix of 3 first (Ubuntu LTS, Fedora, Tumbleweed); everything else best effort |
| Matrix drift on dependency names | One table in the nfpm file; a CI job that installs the package in each container |

Plan in small steps:

| Step | Deliverable | Done when |
|---|---|---|
| 1 | Inventory of installed paths from `install.sh` into a staging layout (`make stage DESTDIR=...` style script) | Tree identical on any distro except the two parameters |
| 2 | Template the units and PAM files (`@libexecdir@`, `@pamdir@`, `@p11dir@`); move helpers to `/usr/lib/openhello` | No literal `/usr/libexec` or `/usr/lib64` left in `packaging/` |
| 3 | `nfpm.yaml` for deb and rpm; build both in two containers | Packages install and `openhello-keyd` unit passes `systemd-analyze verify` |
| 4 | Post-install scripts (idempotent) and removal test | Install, upgrade, remove, purge in each container leave PAM stack intact |
| 5 | pam-auth-update profile (deb) and authselect feature (Fedora); SUSE/Arch snippet doc | `pam-auth-update --enable` / `authselect select ... with-openhello` produce the three lines in order |
| 6 | CI: pam_wrapper tests for `pam_openhello` + swtpm test for keyd in containers | Green without camera or TPM hardware |
| 7 | OBS project with vendored crates, one spec and one `debian.*` set; AUR PKGBUILD | Repos install on Ubuntu, Fedora, Tumbleweed VMs |
| 8 | Demote `install.sh` to a development tool; keep it calling the staging step | README points to packages |
| 9 | Later: nixpkgs/NixOS module, Debian/Fedora archive submission | Only with an interested maintainer |
