use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{DirBuilder, File};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use openhello_ticket::{Ticket, TicketKey, Verifier, DEFAULT_TTL_MS, KEY_LEN};
use zeroize::{Zeroize, Zeroizing};

use crate::tpm::failure;
use crate::{validate_uid, Keyd, KeydConfig, KeydError, Secret};

const PROTECTORS_DIR: &str = "protectors";
const SECRET_BYTES: usize = 20;
const RECOVERY_BYTES: usize = 16;
const PIN_MIN: usize = 6;
const PIN_MAX: usize = 32;
// noda keeps loading a Protector working in lockout, so refusals come from the Protector itself.
const PRIMARY_ATTRIBUTES: &str =
    "restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda";
const SEAL_ATTRIBUTES: &str = "fixedtpm|fixedparent|userwithauth";
const GRANT_TTL: Duration = Duration::from_millis(DEFAULT_TTL_MS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutPolicy {
    pub max_tries: u32,
    pub recovery_time_s: u32,
    pub lockout_recovery_time_s: u32,
}

impl LockoutPolicy {
    // Production suggestion; the TPM counter is global, so it also throttles disk unlock and every other TPM user.
    pub const RECOMMENDED: Self = Self {
        max_tries: 10,
        recovery_time_s: 600,
        lockout_recovery_time_s: 86_400,
    };
}

pub struct RecoveryCode(Zeroizing<String>);

impl RecoveryCode {
    pub fn reveal(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Biometric,
    Pin,
    Recovery,
}

impl Kind {
    fn file(self) -> &'static str {
        match self {
            Kind::Biometric => "biometric.blob",
            Kind::Pin => "pin.blob",
            Kind::Recovery => "recovery.blob",
        }
    }
}

struct Grant {
    secret: Secret,
    created: Instant,
}

// Weakest point (ASM-008): the biometric Protector has no authValue, so root in keyd can unseal K without a face match; only the 5 s single-use ticket and the match FAR bound it.
pub struct Protectors {
    config: KeydConfig,
    keyd: Keyd,
    ticket_key: Zeroizing<[u8; KEY_LEN]>,
    verifier: Mutex<Verifier>,
    grants: Mutex<HashMap<u32, Grant>>,
    store: Mutex<()>,
}

impl Protectors {
    pub fn new(config: KeydConfig) -> Result<Self, KeydError> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::getrandom(&mut *bytes)
            .map_err(|e| failure("gathering randomness", &e.to_string(), &[]))?;
        Ok(Self {
            keyd: Keyd::new(config.clone()),
            config,
            verifier: Mutex::new(Verifier::new(TicketKey::from_bytes(*bytes))),
            ticket_key: bytes,
            grants: Mutex::new(HashMap::new()),
            store: Mutex::new(()),
        })
    }

    pub fn keyd(&self) -> &Keyd {
        &self.keyd
    }

    pub fn ticket_key(&self) -> TicketKey {
        TicketKey::from_bytes(*self.ticket_key)
    }

    pub(crate) fn ticket_key_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        self.ticket_key.clone()
    }

    pub fn provision_protectors(&self, uid: u32) -> Result<RecoveryCode, KeydError> {
        let uid = validate_uid(uid)?;
        let _store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        let dir = self.user_dir(uid);
        if [Kind::Biometric, Kind::Pin, Kind::Recovery]
            .iter()
            .any(|k| dir.join(k.file()).exists())
        {
            return Err(KeydError::AlreadyProvisioned);
        }
        let secret = random_hex(SECRET_BYTES)?;
        let code = random_hex(RECOVERY_BYTES)?;
        let outcome = (|| {
            self.write_blob(
                uid,
                Kind::Biometric,
                &self.seal(secret.as_bytes(), None, true)?,
            )?;
            self.write_blob(
                uid,
                Kind::Recovery,
                &self.seal(secret.as_bytes(), Some(&code), false)?,
            )?;
            match self.keyd.provision(uid, &Secret::new(secret.as_str())?) {
                Ok(p) if p.created => Ok(()),
                Ok(_) => Err(KeydError::AlreadyProvisioned),
                Err(e) => Err(e),
            }
        })();
        if let Err(error) = outcome {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(error);
        }
        Ok(RecoveryCode(code))
    }

    // Unseals K through the biometric Protector, so authorizing the caller is T-020's job.
    pub fn set_pin(&self, uid: u32, pin: &str) -> Result<(), KeydError> {
        let uid = validate_uid(uid)?;
        validate_pin(pin)?;
        let _store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        let secret = self.unseal_kind(uid, Kind::Biometric, None)?;
        let blob = self.seal(secret.expose().as_bytes(), Some(pin), false)?;
        self.write_blob(uid, Kind::Pin, &blob)
    }

    pub fn unlock_with_pin(&self, uid: u32, pin: &str) -> Result<Secret, KeydError> {
        let uid = validate_uid(uid)?;
        if !self.user_dir(uid).join(Kind::Pin.file()).exists() {
            return Err(if self.is_provisioned(uid) {
                KeydError::PinNotSet
            } else {
                KeydError::NotProvisioned
            });
        }
        if validate_pin(pin).is_err() {
            return Err(KeydError::AuthenticationFailed);
        }
        self.unseal_kind(uid, Kind::Pin, Some(pin))
    }

    pub fn unlock_with_ticket(&self, uid: u32, ticket: &[u8]) -> Result<Secret, KeydError> {
        let uid = validate_uid(uid)?;
        if !self.is_provisioned(uid) {
            return Err(KeydError::NotProvisioned);
        }
        self.verifier
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .verify(ticket, uid)
            .map_err(KeydError::Ticket)?;
        self.unseal_kind(uid, Kind::Biometric, None)
    }

    pub fn unlock_with_recovery(
        &self,
        uid: u32,
        code: &str,
    ) -> Result<(Secret, RecoveryCode), KeydError> {
        let uid = validate_uid(uid)?;
        let _store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.is_provisioned(uid) {
            return Err(KeydError::NotProvisioned);
        }
        if !is_recovery_code(code) {
            return Err(KeydError::AuthenticationFailed);
        }
        let secret = self.unseal_kind(uid, Kind::Recovery, Some(code))?;
        let fresh = random_hex(RECOVERY_BYTES)?;
        let blob = self.seal(secret.expose().as_bytes(), Some(&fresh), false)?;
        self.write_blob(uid, Kind::Recovery, &blob)?;
        Ok((secret, RecoveryCode(fresh)))
    }

    // P-003/AC-024: no code path in keyd accepts a template or embedding as a credential.
    pub fn refuse_biometric_material(
        &self,
        _uid: u32,
        _material: &[u8],
    ) -> Result<Secret, KeydError> {
        Err(KeydError::Refused)
    }

    pub fn apply_lockout_policy(&self, policy: &LockoutPolicy) -> Result<(), KeydError> {
        let run = run_tool(
            &self.config,
            "tpm2_dictionarylockout",
            &[
                "--setup-parameters".into(),
                format!("--max-tries={}", policy.max_tries).into(),
                format!("--recovery-time={}", policy.recovery_time_s).into(),
                format!("--lockout-recovery-time={}", policy.lockout_recovery_time_s).into(),
            ],
            &[],
            None,
        )?;
        if !run.success {
            return Err(failure(
                "setting the lockout policy",
                &run.last_error(),
                &[],
            ));
        }
        Ok(())
    }

    pub(crate) fn store_grant(&self, uid: u32, secret: Secret) {
        self.grants
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                uid,
                Grant {
                    secret,
                    created: Instant::now(),
                },
            );
    }

    pub fn take_grant(&self, uid: u32) -> Option<Secret> {
        let grant = self
            .grants
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&uid)?;
        (grant.created.elapsed() < GRANT_TTL).then_some(grant.secret)
    }

    pub(crate) fn unlock_for_socket(&self, ticket: &[u8]) -> Result<(), KeydError> {
        let uid = Ticket::decode(ticket).map_err(KeydError::Ticket)?.uid();
        let secret = self.unlock_with_ticket(uid, ticket)?;
        self.store_grant(uid, secret);
        Ok(())
    }

    fn user_dir(&self, uid: u32) -> PathBuf {
        self.config
            .store_dir
            .join(PROTECTORS_DIR)
            .join(uid.to_string())
    }

    fn is_provisioned(&self, uid: u32) -> bool {
        self.user_dir(uid).join(Kind::Biometric.file()).exists()
    }

    fn write_blob(&self, uid: u32, kind: Kind, blob: &[u8]) -> Result<(), KeydError> {
        let dir = self.user_dir(uid);
        let io = |what: &str, e: std::io::Error| failure(what, &e.to_string(), &[]);
        self.config.ensure_store_dir()?;
        for path in [dir.parent().unwrap_or(&dir), &dir] {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(|e| io("preparing the protector directory", e))?;
        }
        let target = dir.join(kind.file());
        let staging = dir.join(format!("{}.new", kind.file()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&staging)
            .map_err(|e| io("writing a protector", e))?;
        file.write_all(blob)
            .and_then(|_| file.sync_all())
            .map_err(|e| io("writing a protector", e))?;
        std::fs::rename(&staging, &target).map_err(|e| io("replacing a protector", e))
    }

    fn read_blob(&self, uid: u32, kind: Kind) -> Result<Vec<u8>, KeydError> {
        match std::fs::read(self.user_dir(uid).join(kind.file())) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(KeydError::NotProvisioned),
            Err(e) => Err(failure("reading a protector", &e.to_string(), &[])),
        }
    }

    fn seal(&self, data: &[u8], auth: Option<&str>, no_da: bool) -> Result<Vec<u8>, KeydError> {
        let work = WorkDir::new(&self.config)?;
        let secrets: Vec<&str> = auth.into_iter().collect();
        self.create_primary(&work)?;
        let attributes = if no_da {
            format!("{SEAL_ATTRIBUTES}|noda")
        } else {
            SEAL_ATTRIBUTES.to_string()
        };
        let mut args: Vec<OsString> = vec![
            "-C".into(),
            work.path("primary.ctx").into(),
            "-i".into(),
            "-".into(),
            "-u".into(),
            work.path("seal.pub").into(),
            "-r".into(),
            work.path("seal.priv").into(),
            "-a".into(),
            attributes.into(),
        ];
        let auth_fd = auth.map(memory_file).transpose()?;
        if let Some(fd) = &auth_fd {
            args.push("-p".into());
            args.push(format!("file:/proc/self/fd/{}", fd.fd()).into());
        }
        let run = run_tool(&self.config, "tpm2_create", &args, &secrets, Some(data))?;
        drop(auth_fd);
        if !run.success {
            return Err(failure("sealing a protector", &run.last_error(), &secrets));
        }
        let read = |name: &str| {
            std::fs::read(work.path(name))
                .map_err(|e| failure("reading the sealed object", &e.to_string(), &[]))
        };
        Ok(encode_blob(&read("seal.pub")?, &read("seal.priv")?))
    }

    fn unseal_kind(&self, uid: u32, kind: Kind, auth: Option<&str>) -> Result<Secret, KeydError> {
        let blob = self.read_blob(uid, kind)?;
        let (public, private) = decode_blob(&blob)
            .ok_or_else(|| failure("reading a protector", "corrupt protector file", &[]))?;
        let work = WorkDir::new(&self.config)?;
        let secrets: Vec<&str> = auth.into_iter().collect();
        std::fs::write(work.path("seal.pub"), public)
            .and_then(|_| std::fs::write(work.path("seal.priv"), private))
            .map_err(|e| failure("staging a protector", &e.to_string(), &[]))?;
        self.create_primary(&work)?;
        let loaded = run_tool(
            &self.config,
            "tpm2_load",
            &[
                "-C".into(),
                work.path("primary.ctx").into(),
                "-u".into(),
                work.path("seal.pub").into(),
                "-r".into(),
                work.path("seal.priv").into(),
                "-c".into(),
                work.path("seal.ctx").into(),
            ],
            &[],
            None,
        )?;
        if !loaded.success {
            return Err(failure("loading a protector", &loaded.last_error(), &[]));
        }
        let mut args: Vec<OsString> = vec!["-c".into(), work.path("seal.ctx").into()];
        if auth.is_some() {
            args.push("-p".into());
            args.push("file:-".into());
        }
        let run = run_tool(
            &self.config,
            "tpm2_unseal",
            &args,
            &secrets,
            auth.map(str::as_bytes),
        )?;
        if !run.success {
            return Err(classify_unseal(&run, &secrets));
        }
        let text = Zeroizing::new(
            String::from_utf8(run.stdout.to_vec())
                .map_err(|_| failure("unsealing a protector", "output is not text", &[]))?,
        );
        Secret::new(text.as_str())
    }

    fn create_primary(&self, work: &WorkDir) -> Result<(), KeydError> {
        let run = run_tool(
            &self.config,
            "tpm2_createprimary",
            &[
                "-C".into(),
                "o".into(),
                "-G".into(),
                "ecc256".into(),
                "-a".into(),
                PRIMARY_ATTRIBUTES.into(),
                "-c".into(),
                work.path("primary.ctx").into(),
            ],
            &[],
            None,
        )?;
        if run.success {
            Ok(())
        } else {
            Err(failure("creating the primary key", &run.last_error(), &[]))
        }
    }
}

fn validate_pin(pin: &str) -> Result<(), KeydError> {
    if (PIN_MIN..=PIN_MAX).contains(&pin.len()) && pin.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        Ok(())
    } else {
        Err(KeydError::InvalidPin)
    }
}

fn is_recovery_code(code: &str) -> bool {
    code.len() == RECOVERY_BYTES * 2 && code.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn random_hex(bytes: usize) -> Result<Zeroizing<String>, KeydError> {
    let mut raw = Zeroizing::new(vec![0u8; bytes]);
    getrandom::getrandom(&mut raw)
        .map_err(|e| failure("gathering randomness", &e.to_string(), &[]))?;
    Ok(Zeroizing::new(
        raw.iter().map(|b| format!("{b:02x}")).collect(),
    ))
}

fn encode_blob(public: &[u8], private: &[u8]) -> Vec<u8> {
    let mut out = (public.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(public);
    out.extend_from_slice(private);
    out
}

fn decode_blob(blob: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    let public = blob.get(4..4usize.checked_add(len)?)?;
    let private = blob.get(4 + len..).filter(|p| !p.is_empty())?;
    Some((public, private))
}

struct ToolRun {
    success: bool,
    stdout: Zeroizing<Vec<u8>>,
    stderr: String,
}

impl ToolRun {
    fn last_error(&self) -> String {
        self.stderr
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("no diagnostic output")
            .to_string()
    }
}

fn classify_unseal(run: &ToolRun, secrets: &[&str]) -> KeydError {
    let text = run.stderr.to_ascii_uppercase();
    if text.contains("0X921") || text.contains("LOCKOUT") {
        KeydError::LockedOut
    } else if text.contains("0X98E") || text.contains("0X9A2") {
        KeydError::AuthenticationFailed
    } else {
        failure("unsealing a protector", &run.stderr, secrets)
    }
}

fn run_tool(
    config: &KeydConfig,
    tool: &str,
    args: &[OsString],
    secrets: &[&str],
    stdin: Option<&[u8]>,
) -> Result<ToolRun, KeydError> {
    let mut command = Command::new(tool);
    command
        .args(args)
        .current_dir("/")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(tcti) = &config.tcti {
        command.env("TPM2TOOLS_TCTI", tcti);
    }
    if let Some(prefix) = &config.prefix {
        let mut library_path = prefix.join("usr/lib64").into_os_string();
        if let Some(existing) = std::env::var_os("LD_LIBRARY_PATH") {
            library_path.push(":");
            library_path.push(existing);
        }
        command.env("LD_LIBRARY_PATH", library_path);
    }
    command.envs(config.env.iter().map(|(k, v)| (k, v)));
    let mut child = command
        .spawn()
        .map_err(|e| failure(&format!("starting {tool}"), &e.to_string(), secrets))?;
    if let (Some(mut pipe), Some(data)) = (child.stdin.take(), stdin) {
        pipe.write_all(data)
            .map_err(|e| failure(&format!("writing to {tool}"), &e.to_string(), secrets))?;
    }
    let mut output = child
        .wait_with_output()
        .map_err(|e| failure(&format!("waiting for {tool}"), &e.to_string(), secrets))?;
    let stdout = Zeroizing::new(std::mem::take(&mut output.stdout));
    let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        stderr = stderr.replace(secret, "[redacted]");
    }
    output.stderr.zeroize();
    Ok(ToolRun {
        success: output.status.success(),
        stdout,
        stderr,
    })
}

struct MemoryFile(File);

impl MemoryFile {
    fn fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

// Keeps authValues off command lines (visible in /proc) and off disk.
fn memory_file(content: &str) -> Result<MemoryFile, KeydError> {
    let fd = unsafe { libc::memfd_create(c"openhello-auth".as_ptr(), 0) };
    if fd < 0 {
        return Err(failure(
            "creating an in-memory file",
            &std::io::Error::last_os_error().to_string(),
            &[],
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(content.as_bytes())
        .map_err(|e| failure("writing an in-memory file", &e.to_string(), &[content]))?;
    Ok(MemoryFile(file))
}

struct WorkDir(PathBuf);

impl WorkDir {
    fn new(config: &KeydConfig) -> Result<Self, KeydError> {
        config.ensure_store_dir()?;
        let mut tag = [0u8; 8];
        getrandom::getrandom(&mut tag)
            .map_err(|e| failure("gathering randomness", &e.to_string(), &[]))?;
        let name: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        let path = config.store_dir.join(format!(".work-{name}"));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| failure("preparing a work directory", &e.to_string(), &[]))?;
        Ok(Self(path))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_and_recovery_code_formats_are_enforced() {
        assert!(validate_pin("123456").is_ok());
        assert!(validate_pin("12345").is_err());
        assert!(validate_pin(&"x".repeat(33)).is_err());
        assert!(validate_pin("pin\nline").is_err());
        assert!(validate_pin("sênha123").is_err());
        assert!(is_recovery_code(&"ab".repeat(16)));
        assert!(!is_recovery_code(&"AB".repeat(16)));
        assert!(!is_recovery_code("abc"));
    }

    #[test]
    fn blob_round_trips_and_rejects_truncation() {
        let blob = encode_blob(b"public", b"private");
        assert_eq!(decode_blob(&blob), Some((&b"public"[..], &b"private"[..])));
        assert_eq!(decode_blob(&blob[..8]), None);
        assert_eq!(decode_blob(&[0, 0]), None);
    }

    #[test]
    fn recovery_code_is_redacted() {
        let code = RecoveryCode(Zeroizing::new("ab".repeat(16)));
        assert_eq!(format!("{code:?}"), "RecoveryCode(<redacted>)");
    }
}
