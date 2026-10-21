#![allow(dead_code)]

#[path = "../../../../tests/support/swtpm_harness.rs"]
mod swtpm_harness;

use std::io::{BufRead, BufReader, Read, Write};
use std::ops::Deref;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use openhello_keyd::{KeydConfig, OP_TOKEN_FIND, OP_TOKEN_HELLO, OP_TOKEN_SIGN, TOKEN_OK};
use swtpm_harness::SwTpm;

pub const CKO_CERTIFICATE: u64 = 1;
pub const CKO_PUBLIC_KEY: u64 = 2;
pub const CKO_PRIVATE_KEY: u64 = 3;
pub const CKM_ECDSA: u64 = 0x1041;

fn required(name: &str, meaning: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        _ => panic!(
            "{name} is not set ({meaning}). openhello-keyd tests are never skipped: export it and rerun. \
             scripts/spike-pkcs11.sh prepares ~/.cache/openhello-spike/root (see crates/openhello-keyd/tests/README.md)"
        ),
    }
}

// tpm2-pkcs11 keeps process-wide state, so tests share one rig and run serially.
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
        config.mapfile = store.path().join("pkcs11-subject-map");
        config.auth_dir = store.path().join("auth");
        config.user_name = Some(|uid| Some(format!("user{uid}")));
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

#[derive(Default)]
pub struct Recorded {
    pub to_keyd: Vec<u8>,
    pub from_keyd: Vec<u8>,
}

pub fn relay(listen: PathBuf, upstream: PathBuf) -> Arc<Mutex<Recorded>> {
    let recorded = Arc::new(Mutex::new(Recorded::default()));
    let listener = UnixListener::bind(&listen).unwrap();
    let seen = recorded.clone();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let Ok(server) = UnixStream::connect(&upstream) else {
                continue;
            };
            for (mut from, mut to, forward) in [
                (
                    client.try_clone().unwrap(),
                    server.try_clone().unwrap(),
                    true,
                ),
                (server, client, false),
            ] {
                let seen = seen.clone();
                std::thread::spawn(move || {
                    let mut buf = [0u8; 512];
                    while let Ok(n) = from.read(&mut buf) {
                        if n == 0 || to.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let mut log = seen.lock().unwrap();
                        let side = if forward {
                            &mut log.to_keyd
                        } else {
                            &mut log.from_keyd
                        };
                        side.extend_from_slice(&buf[..n]);
                    }
                });
            }
        }
    });
    recorded
}

pub struct TokenClient {
    stream: UnixStream,
    pub received: Vec<u8>,
}

impl TokenClient {
    pub fn connect_unnamed(path: &Path) -> Self {
        let stream = UnixStream::connect(path).expect("the token socket must accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        Self {
            stream,
            received: Vec::new(),
        }
    }

    pub fn connect(path: &Path, uid: u32) -> Self {
        let mut client = Self::connect_unnamed(path);
        let (status, _) = client
            .send(OP_TOKEN_HELLO, &uid.to_be_bytes())
            .expect("hello must be answered");
        assert_eq!(status, TOKEN_OK, "hello for uid {uid} was refused");
        client
    }

    pub fn send(&mut self, op: u8, payload: &[u8]) -> Option<(u8, Vec<u8>)> {
        let mut frame = vec![op];
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        self.stream.write_all(&frame).ok()?;
        let mut header = [0u8; 3];
        self.stream.read_exact(&mut header).ok()?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes([header[1], header[2]]))];
        self.stream.read_exact(&mut body).ok()?;
        self.received.extend_from_slice(&header);
        self.received.extend_from_slice(&body);
        Some((header[0], body))
    }

    pub fn find_class(&mut self, class: u64) -> Vec<u64> {
        let mut template = vec![1u8];
        template.extend_from_slice(&0u64.to_be_bytes());
        template.extend_from_slice(&8u16.to_be_bytes());
        template.extend_from_slice(&class.to_ne_bytes());
        let reply = self.ok(OP_TOKEN_FIND, &template);
        reply
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_be_bytes(*c))
            .collect()
    }

    pub fn sign(&mut self, handle: u64, digest: &[u8]) -> Option<(u8, Vec<u8>)> {
        let mut payload = CKM_ECDSA.to_be_bytes().to_vec();
        payload.extend_from_slice(&handle.to_be_bytes());
        payload.extend_from_slice(digest);
        self.send(OP_TOKEN_SIGN, &payload)
    }

    pub fn ok(&mut self, op: u8, payload: &[u8]) -> Vec<u8> {
        let (status, body) = self.send(op, payload).expect("the keyd must answer");
        assert_eq!(status, TOKEN_OK, "operation {op} returned status {status}");
        body
    }
}

pub fn looks_like_secret(bytes: &[u8]) -> bool {
    bytes
        .windows(24)
        .any(|window| window.iter().all(u8::is_ascii_alphanumeric))
}
