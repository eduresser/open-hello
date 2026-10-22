# openhello-keyd tests

These tests run against a software TPM (`swtpm`) behind `tpm2-abrmd`, never `/dev/tpm0`. A test that cannot
find a prerequisite fails with the variable to export; none is skipped.

| Variable | Value |
|---|---|
| `OPENHELLO_SWTPM_TCTI_LIB` | path of `libtss2-tcti-swtpm.so.0` |
| `OPENHELLO_TPM2_PKCS11_PREFIX` | install root holding `tpm2-pkcs11`, `tpm2_ptool`, `tpm2-abrmd` and their libraries |

`scripts/spike-pkcs11.sh` builds both in `~/.cache/openhello-spike/root` (no root needed):

```
export OPENHELLO_SWTPM_TCTI_LIB=$HOME/.cache/openhello-spike/root/usr/lib64/libtss2-tcti-swtpm.so.0
export OPENHELLO_TPM2_PKCS11_PREFIX=$HOME/.cache/openhello-spike/root
cargo test -p openhello-keyd
```

Also needed on `PATH`: `swtpm`, `tpm2-tools`, `dbus-daemon`, `python3` with `sqlite3` and `yaml`.
