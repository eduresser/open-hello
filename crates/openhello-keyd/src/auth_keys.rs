use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use openhello_auth_proto::{encode_public_key, public_key_file_name};

use crate::logging::{log, Level, Value};
use crate::provision::{token_uid, Keyd};
use crate::tpm::{failure, lock};
use crate::KeydError;

pub(crate) const DEFAULT_AUTH_DIR: &str = "/etc/openhello/auth";
const FILE_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o755;

pub(crate) fn write_public_key(dir: &Path, uid: u32, point: &[u8]) -> Result<(), KeydError> {
    let io = |e: std::io::Error| failure("registering the public key", &e.to_string(), &[]);
    let text = encode_public_key(point).ok_or_else(|| {
        failure(
            "registering the public key",
            "not an uncompressed P-256 point",
            &[],
        )
    })?;
    let path = dir.join(public_key_file_name(uid));
    if is_current(&path, &text) {
        return Ok(());
    }
    std::fs::create_dir_all(dir).map_err(io)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(DIR_MODE)).map_err(io)?;
    let temp = dir.join(format!(
        ".{}.tmp{}",
        public_key_file_name(uid),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&temp);
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&temp)?;
        file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temp, &path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(io(e));
    }
    let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    Ok(())
}

pub(crate) fn sync_public_key(keyd: &Keyd, uid: u32) -> Result<(), KeydError> {
    let key = keyd.key(uid)?;
    write_public_key(&keyd.config.auth_dir, uid, &key.public_key)
}

impl Keyd {
    pub fn backfill_auth_keys(&self) {
        let labels = {
            let guard = lock();
            self.config.token_labels(&guard)
        };
        let Ok(labels) = labels else {
            log(Level::Warn, "auth-key-backfill-skipped", &[]);
            return;
        };
        for uid in labels.iter().filter_map(|label| token_uid(label)) {
            if sync_public_key(self, uid).is_err() {
                log(
                    Level::Warn,
                    "auth-key-backfill-skipped",
                    &[("uid", Value::Uid(uid))],
                );
            }
        }
    }
}

pub(crate) fn remove_public_key(dir: &Path, uid: u32) -> Result<(), KeydError> {
    match std::fs::remove_file(dir.join(public_key_file_name(uid))) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(failure("removing the public key", &e.to_string(), &[])),
    }
}

fn is_current(path: &Path, text: &str) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.permissions().mode() & 0o7777 == FILE_MODE
        && meta.uid() == unsafe { libc::geteuid() }
        && std::fs::read_to_string(path).is_ok_and(|current| current == text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(fill: u8) -> Vec<u8> {
        let mut p = vec![fill; 65];
        p[0] = 0x04;
        p
    }

    #[test]
    fn write_is_atomic_idempotent_and_replaces_a_stale_key() {
        let dir = tempfile::tempdir().unwrap();
        let auth = dir.path().join("auth");
        write_public_key(&auth, 1000, &point(1)).unwrap();
        let file = auth.join("1000.pub");
        let first = std::fs::metadata(&file).unwrap().ino();
        write_public_key(&auth, 1000, &point(1)).unwrap();
        assert_eq!(std::fs::metadata(&file).unwrap().ino(), first);
        assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o7777, 0o644);
        assert_eq!(std::fs::metadata(&auth).unwrap().mode() & 0o7777, 0o755);
        write_public_key(&auth, 1000, &point(2)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            encode_public_key(&point(2)).unwrap()
        );
        assert_eq!(std::fs::read_dir(&auth).unwrap().count(), 1);
    }

    #[test]
    fn write_fails_loudly_and_remove_tolerates_absence() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, b"x").unwrap();
        assert!(write_public_key(&blocker.join("auth"), 1, &point(1)).is_err());
        assert!(write_public_key(dir.path(), 1, &[4; 10]).is_err());
        remove_public_key(dir.path(), 1).unwrap();
        write_public_key(dir.path(), 1, &point(1)).unwrap();
        remove_public_key(dir.path(), 1).unwrap();
        assert!(!dir.path().join("1.pub").exists());
    }
}
