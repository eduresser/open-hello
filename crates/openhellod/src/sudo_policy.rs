use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::Command;

const SYSTEM_DROP_IN_DIR: &str = "/etc/sudoers.d";
const TARGET_PASSWORD_OPTIONS: [&str; 3] = ["targetpw", "rootpw", "runaspw"];
const DEFAULTS_HEADER: &str = "Matching Defaults entries for ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudoPolicy {
    OwnPassword,
    RootPassword,
    Unavailable,
}

impl SudoPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            SudoPolicy::OwnPassword => "own-password",
            SudoPolicy::RootPassword => "root-password",
            SudoPolicy::Unavailable => "unavailable",
        }
    }
}

pub fn policy_from_listing(listing: &str) -> SudoPolicy {
    let mut lines = listing.lines().skip_while(|l| !l.starts_with(DEFAULTS_HEADER));
    if lines.next().is_none() {
        return SudoPolicy::Unavailable;
    }
    let entries: String = lines.take_while(|l| l.starts_with(char::is_whitespace)).collect::<Vec<_>>().join(",");
    let mut asks_target = [false; 3];
    for entry in split_entries(&entries) {
        let (value, name) = match entry.strip_prefix('!') {
            Some(name) => (false, name),
            None => (true, entry),
        };
        if let Some(index) = TARGET_PASSWORD_OPTIONS.iter().position(|option| *option == name) {
            asks_target[index] = value;
        }
    }
    if asks_target.contains(&true) {
        SudoPolicy::RootPassword
    } else {
        SudoPolicy::OwnPassword
    }
}

fn split_entries(text: &str) -> Vec<&str> {
    let mut entries = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (index, byte) in text.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                entries.push(text[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    entries.push(text[start..].trim());
    entries
}

pub struct SudoPolicyStore {
    drop_in_dir: PathBuf,
    sudo: PathBuf,
    visudo: PathBuf,
}

impl SudoPolicyStore {
    pub fn system() -> Self {
        Self::new(SYSTEM_DROP_IN_DIR, "sudo", "visudo")
    }

    pub fn new(drop_in_dir: impl Into<PathBuf>, sudo: impl Into<PathBuf>, visudo: impl Into<PathBuf>) -> Self {
        Self { drop_in_dir: drop_in_dir.into(), sudo: sudo.into(), visudo: visudo.into() }
    }

    fn drop_in(&self, uid: u32) -> PathBuf {
        self.drop_in_dir.join(format!("openhello-uid{uid}"))
    }

    pub fn detect(&self, uid: u32) -> SudoPolicy {
        let Some(user) = user_name(uid) else { return SudoPolicy::Unavailable };
        match Command::new(&self.sudo).args(["-n", "-l", "-U", &user]).env("LC_ALL", "C").output() {
            Ok(output) => policy_from_listing(&String::from_utf8_lossy(&output.stdout)),
            Err(_) => SudoPolicy::Unavailable,
        }
    }

    pub fn use_own_password(&self, uid: u32) -> Result<SudoPolicy, String> {
        match self.detect(uid) {
            SudoPolicy::RootPassword => {}
            other => return Ok(other),
        }
        self.write_drop_in(uid)?;
        match self.detect(uid) {
            SudoPolicy::OwnPassword => Ok(SudoPolicy::OwnPassword),
            other => {
                let _ = fs::remove_file(self.drop_in(uid));
                Err(format!(
                    "sudo still reports {} after writing {}; its configuration does not read that directory",
                    other.as_str(),
                    self.drop_in(uid).display()
                ))
            }
        }
    }

    pub fn is_switched(&self, uid: u32) -> bool {
        self.drop_in(uid).is_file()
    }

    pub fn restore(&self, uid: u32) -> Result<bool, String> {
        match fs::remove_file(self.drop_in(uid)) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("cannot remove {}: {error}", self.drop_in(uid).display())),
        }
    }

    fn write_drop_in(&self, uid: u32) -> Result<(), String> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o750)
            .create(&self.drop_in_dir)
            .map_err(|e| format!("cannot create {}: {e}", self.drop_in_dir.display()))?;
        // A dot-prefixed name keeps sudo from reading the file before visudo accepts it.
        let staged = self.drop_in_dir.join(format!(".openhello-uid{uid}.tmp"));
        let _ = fs::remove_file(&staged);
        let content = format!("Defaults:#{uid} !targetpw, !rootpw, !runaspw\n");
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o440)
            .open(&staged)
            .and_then(|mut file| file.write_all(content.as_bytes()).and_then(|()| file.sync_all()));
        let checked = written.map_err(|e| format!("cannot write {}: {e}", staged.display())).and_then(|()| self.validate(&staged));
        let moved = checked.and_then(|()| {
            fs::rename(&staged, self.drop_in(uid)).map_err(|e| format!("cannot install {}: {e}", self.drop_in(uid).display()))
        });
        if moved.is_err() {
            let _ = fs::remove_file(&staged);
        }
        moved
    }

    fn validate(&self, staged: &std::path::Path) -> Result<(), String> {
        let output = Command::new(&self.visudo)
            .arg("-c")
            .arg("-q")
            .arg("-f")
            .arg(staged)
            .output()
            .map_err(|e| format!("cannot run {}: {e}", self.visudo.display()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!("visudo rejected the drop-in: {}", String::from_utf8_lossy(&output.stderr).trim()))
        }
    }
}

pub(crate) fn user_name(uid: u32) -> Option<String> {
    let mut buffer = vec![0u8; 4096];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut entry, buffer.as_mut_ptr().cast(), buffer.len(), &mut found) };
    if rc != 0 || found.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(entry.pw_name) }.to_str().ok().map(str::to_string)
}
