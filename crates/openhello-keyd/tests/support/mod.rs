#![allow(dead_code)]

#[path = "../../../../tests/support/swtpm_harness.rs"]
mod swtpm_harness;

use std::io::{BufRead, BufReader};
use std::ops::Deref;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use openhello_keyd::KeydConfig;
use swtpm_harness::SwTpm;

fn required(name: &str, meaning: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        _ => panic!(
            "{name} is not set ({meaning}). openhello-keyd tests are never skipped: export it and rerun. \
             scripts/spike-pkcs11.sh prepares ~/.cache/openhello-spike/root (see crates/openhello-keyd/tests/README.md)"
        ),
    }
}

/// tpm2-pkcs11 keeps process-wide state (store, D-Bus connection), so every test in a binary shares one
/// TPM rig and runs one at a time. Each test uses its own uid, hence its own token.
static RIG: Mutex<Option<Rig>> = Mutex::new(None);

pub struct Shared(MutexGuard<'static, Option<Rig>>);

impl Deref for Shared {
    type Target = Rig;

    fn deref(&self) -> &Rig {
        self.0.as_ref().expect("rig started")
    }
}

pub fn rig() -> Shared {
    let mut guard = RIG.lock().unwrap_or_else(PoisonError::into_inner);
    if guard.is_none() {
        *guard = Some(Rig::start());
        unsafe { libc::atexit(teardown) };
    }
    Shared(guard)
}

extern "C" fn teardown() {
    RIG.lock().unwrap_or_else(PoisonError::into_inner).take();
}

/// A private swtpm, D-Bus session and `tpm2-abrmd`, plus a keyd config wired to them. The TPM-wide lockout
/// allows 50 wrong auth values.
pub struct Rig {
    pub config: KeydConfig,
    pub prefix: PathBuf,
    _store: tempfile::TempDir,
    _swtpm: SwTpm,
    dbus: Child,
    abrmd: Child,
}

impl Rig {
    fn start() -> Self {
        required(
            "OPENHELLO_SWTPM_TCTI_LIB",
            "path of libtss2-tcti-swtpm.so.0",
        );
        let prefix = PathBuf::from(required(
            "OPENHELLO_TPM2_PKCS11_PREFIX",
            "install root of tpm2-pkcs11, tpm2_ptool and tpm2-abrmd",
        ));
        let abrmd_binary = prefix.join("usr/sbin/tpm2-abrmd");
        assert!(abrmd_binary.exists(), "{} not found: OPENHELLO_TPM2_PKCS11_PREFIX must point at the prefix built by scripts/spike-pkcs11.sh", abrmd_binary.display());

        let swtpm = SwTpm::start();
        let mut dbus = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("dbus-daemon must be installed to run keyd tests");
        let mut address = String::new();
        BufReader::new(dbus.stdout.take().unwrap())
            .read_line(&mut address)
            .expect("dbus address");
        let address = address.trim().to_string();

        let lib64 = prefix.join("usr/lib64");
        let abrmd = Command::new(&abrmd_binary)
            // abrmd's default of 27 connections ran out during a full run of this suite; cause not isolated.
            .args([
                "--session",
                "--max-connections=100",
                &format!("--tcti={}", swtpm.tcti),
            ])
            .env("DBUS_SESSION_BUS_ADDRESS", &address)
            .env("LD_LIBRARY_PATH", &lib64)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("tpm2-abrmd must start");

        let store = tempfile::tempdir().expect("store dir");
        let mut config = KeydConfig::new(store.path().join("store"));
        config.tcti = Some(format!(
            "{}:bus_type=session",
            lib64.join("libtss2-tcti-tabrmd.so.0").display()
        ));
        config.prefix = Some(prefix.clone());
        config.env = vec![("DBUS_SESSION_BUS_ADDRESS".into(), address)];
        let rig = Self {
            config,
            prefix,
            _store: store,
            _swtpm: swtpm,
            dbus,
            abrmd,
        };

        let deadline = Instant::now() + Duration::from_secs(15);
        while !rig
            .tpm2("tpm2_getcap", &["properties-fixed"])
            .status
            .success()
        {
            assert!(
                Instant::now() < deadline,
                "tpm2-abrmd never answered over swtpm"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        let lockout = [
            "--setup-parameters",
            "--max-tries=50",
            "--recovery-time=3600",
            "--lockout-recovery-time=3600",
        ];
        assert!(
            rig.tpm2("tpm2_dictionarylockout", &lockout)
                .status
                .success(),
            "cannot set the dictionary-attack parameters"
        );
        rig
    }

    pub fn tpm2(&self, tool: &str, args: &[&str]) -> std::process::Output {
        Command::new(tool)
            .args(args)
            .env("TPM2TOOLS_TCTI", self.config.tcti.as_ref().unwrap())
            .env("DBUS_SESSION_BUS_ADDRESS", &self.config.env[0].1)
            .env("LD_LIBRARY_PATH", self.prefix.join("usr/lib64"))
            .output()
            .expect("tpm2-tools must be installed")
    }

    /// The TPM's own dictionary-attack failure counter (`TPM2_PT_LOCKOUT_COUNTER`).
    pub fn lockout_counter(&self) -> u32 {
        let out = self.tpm2("tpm2_getcap", &["properties-variable"]);
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.trim().strip_prefix("TPM2_PT_LOCKOUT_COUNTER:"))
            .and_then(|v| u32::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok())
            .expect("TPM2_PT_LOCKOUT_COUNTER in tpm2_getcap output")
    }

    pub fn clear_lockout(&self) {
        assert!(
            self.tpm2("tpm2_dictionarylockout", &["--clear-lockout"])
                .status
                .success(),
            "cannot clear the dictionary-attack lockout"
        );
    }

    /// Objects `tpm2_ptool` lists for a token, one `CKO_*` class name per object.
    pub fn listed_classes(&self, label: &str) -> Vec<String> {
        let site: Vec<String> = ["usr/lib", "usr/lib64"]
            .iter()
            .map(|d| format!("{}/{d}/python3.13/site-packages", self.prefix.display()))
            .collect();
        let output = Command::new("python3")
            .arg(self.prefix.join("usr/bin/tpm2_ptool"))
            .args(["listobjects", "--label", label])
            .env("PYTHONPATH", site.join(":"))
            .env("PYTHONWARNINGS", "ignore")
            .env("LD_LIBRARY_PATH", self.prefix.join("usr/lib64"))
            .env("TPM2_PKCS11_STORE", &self.config.store_dir)
            .env("TPM2TOOLS_TCTI", self.config.tcti.as_ref().unwrap())
            .env("DBUS_SESSION_BUS_ADDRESS", &self.config.env[0].1)
            .output()
            .expect("python3 must be installed");
        assert!(
            output.status.success(),
            "tpm2_ptool listobjects failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|l| {
                l.trim()
                    .trim_start_matches("- ")
                    .strip_prefix("CKA_CLASS: ")
                    .map(str::to_string)
            })
            .collect()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        for child in [&mut self.abrmd, &mut self.dbus] {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
