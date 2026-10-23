# open-hello

Face login for Linux, modeled on Windows Hello: your face authorizes the use of a key held in the TPM, instead of being treated like a password.

It works with `sudo`, the lock screen and any service that authenticates through PAM. If the face is not recognized, the system asks for the password as usual.

## Requirements

- An infrared (IR) camera exposed as a V4L2 node, the "Windows Hello certified" kind.
- TPM 2.0.
- Linux with systemd, D-Bus and PAM. No dependency on a specific distribution or desktop environment.
- `tpm2-tools`, `tpm2-pkcs11` (PKCS#11 module and `tpm2_ptool`), `polkit` and a C compiler. The installer checks each item and lists what is missing; it does not install packages.

## Installation

```bash
sudo scripts/install.sh
```

The script builds the project, downloads the models and ONNX Runtime with checksum verification, installs the services and enables the PAM module in the common authentication stack.

Options:

| Option | Effect |
|---|---|
| `--dry-run` | Shows what would be done without changing the system |
| `--skip-checks` | Skips the requirements check |
| `--no-pam` | Installs without enabling PAM |

## Usage

```bash
openhello-cli enroll        # enroll your face
openhello-cli set-pin       # set the fallback PIN
openhello-cli verify        # test recognition
openhello-cli identify      # identify who is in front of the camera
openhello-cli purge         # erase biometric data and the key

sudo openhello-cli pam status    # show where the module is enabled
sudo openhello-cli pam enable    # enable in the common authentication stack
sudo openhello-cli pam disable   # undo
```

Enroll from an active graphical session: polkit requires a local session to authorize the operation.

## Attempt policy

Each authentication request gets up to 3 recognition attempts within 10 seconds. After that, the system asks for the password. There is no persistent lockout.

## How it works

```
 sudo / lock screen / login
            │  PAM
            ▼
      pam_openhello
            │  D-Bus
   ┌────────┴─────────┐
   ▼                  ▼
openhellod        openhello-keyd
capture and       TPM key,
recognition       PKCS#11 tokens
   │   short-lived ticket
   └─────────────────►
```

- **`openhellod`**: captures frames from the IR camera, extracts the face embedding and compares it with the enrolled templates. It never touches the key.
- **`openhello-keyd`**: holds one ECDSA P-256 key per user, created inside the TPM and non-exportable. It never sees biometric data.
- **Ticket**: after a successful recognition, `openhellod` issues a signed, single-use ticket valid for 5 seconds. Only with it does `openhello-keyd` let the key sign the PAM challenge.
- **Enrolled templates**: encrypted with AEAD, using a key sealed in the TPM. Destroying the key makes the data unusable.
- **Recognition**: YuNet detects the face and AuraFace (`glintr100`) produces the embedding, through ONNX Runtime on CPU.
- **Decision**: the threshold is calibrated against a target false accept rate (FAR), not an arbitrary distance cutoff. The IR emitter is switched on before every capture; if it does not turn on, authentication fails.

## Known limitations

- Protection against a printed photo is weak. The risk was accepted for this version.
- Without the hardware isolation of Windows ("Enhanced Sign-in Security"), the anti-spoofing is weaker than Windows Hello's.
- Fingerprint stays with the system's native `fprintd`; open-hello handles face only.
- Graphical login through a display-manager greeter is not yet in scope.

## Repository layout

| Path | Contents |
|---|---|
| `crates/openhellod` | Biometrics daemon |
| `crates/openhello-keyd` | Key and token daemon |
| `crates/openhello-pam` | PAM module |
| `crates/openhello-pkcs11` | Intermediate PKCS#11 module |
| `crates/openhello-cli` | Command line |
| `crates/sensor-adapter-ir` | V4L2 capture and IR emitter |
| `crates/engine-adapter-face` | Detection, embedding and calibration |
| `crates/storage-adapter-templates` | Encrypted template storage |
| `evaluation/` | Python accuracy evaluation (see `evaluation/README.md`) |
| `packaging/` | systemd services, D-Bus policies and PAM snippets |
| `.spec/` | Specifications, architecture and requirement traceability |

## Development

```bash
cargo build --workspace
cargo test --workspace
```

Some tests use a simulated TPM (`swtpm`) and need the `libtss2-tcti-swtpm` library. If it is not installed on the system, point `OPENHELLO_SWTPM_TCTI_LIB` to the `libtss2-tcti-swtpm.so.0` file.

The detailed architecture is in `.spec/docs/arquitetura-linux.md`.

## License

Apache-2.0.
