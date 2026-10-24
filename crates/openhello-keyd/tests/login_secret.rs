mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use openhello_keyd::logging::{self, Level, LogSink};
use openhello_keyd::{KeydError, LoginSecrets, Protectors};
use support::{rig, Rig};

const SHADOW: &str = "user4100:$6$rounds=5000$saltsalt$Q2hhbmdlZEhhc2hWYWx1ZQ:20000:0:99999:7:::";
const CHANGED_SHADOW: &str =
    "user4100:$6$rounds=5000$othersalt$TmV3SGFzaEFmdGVyUGFzc3dk:20384:0:99999:7:::";

fn user_dir(rig: &Rig, uid: u32) -> PathBuf {
    rig.config
        .store_dir
        .join("login-secrets")
        .join(uid.to_string())
}

fn persistent_handles(rig: &Rig) -> Vec<String> {
    let out = rig.tpm2("tpm2_getcap", &["handles-persistent"]);
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().trim_start_matches("- ").to_ascii_lowercase())
        .filter(|l| !l.is_empty())
        .collect()
}

fn key_handle(uid: u32) -> String {
    format!("0x{:x}", 0x8109_0000u32 | uid)
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

struct Evict<'a>(&'a Rig, Vec<String>);

impl Drop for Evict<'_> {
    fn drop(&mut self) {
        for handle in &self.1 {
            let _ = self.0.tpm2("tpm2_evictcontrol", &["-C", "o", "-c", handle]);
        }
    }
}

fn files_contain(dir: &Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            let path = entry.path();
            if path.is_dir() {
                files_contain(&path, needle)
            } else {
                let bytes = std::fs::read(&path).unwrap_or_default();
                bytes.windows(needle.len()).any(|w| w == needle)
            }
        })
}

#[derive(Default)]
struct Lines(Mutex<Vec<String>>);

impl LogSink for Lines {
    fn write_line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }
}

// @spec:AC-083
#[test]
fn a_new_password_replaces_the_sealed_one() {
    let rig = rig();
    let secrets = LoginSecrets::new(rig.config.clone());
    let uid = 4101;

    secrets.seal(uid, "first password", SHADOW).unwrap();
    assert_eq!(
        secrets
            .release(uid, SHADOW)
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("first password")
    );
    secrets
        .seal(uid, "second password", CHANGED_SHADOW)
        .unwrap();

    assert_eq!(
        secrets
            .release(uid, CHANGED_SHADOW)
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("second password")
    );
    let mode = std::fs::metadata(user_dir(&rig, uid).join("secret.bin"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert!(!user_dir(&rig, uid).join("key.blob").exists());
    let leftovers: Vec<_> = std::fs::read_dir(user_dir(&rig, uid))
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .filter(|n| n.to_string_lossy().ends_with(".new"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    secrets.purge(uid).unwrap();
}

// @spec:AC-080
#[test]
fn a_changed_shadow_entry_discards_the_secret() {
    let rig = rig();
    let secrets = LoginSecrets::new(rig.config.clone());
    let uid = 4102;
    secrets.seal(uid, "before the change", SHADOW).unwrap();

    assert!(secrets.release(uid, CHANGED_SHADOW).unwrap().is_none());

    assert!(!user_dir(&rig, uid).join("secret.bin").exists());
    assert!(!user_dir(&rig, uid).join("key.blob").exists());
    assert!(secrets.release(uid, SHADOW).unwrap().is_none());
}

// @spec:AC-088
#[test]
fn the_password_and_shadow_entry_never_reach_files_errors_or_logs() {
    let rig = rig();
    let lines = Arc::new(Lines::default());
    logging::configure(Level::Trace, lines.clone());
    let secrets = LoginSecrets::new(rig.config.clone());
    let uid = 4103;
    let password = "Corr3ct-Horse-Battery-Staple";
    let mut errors = Vec::new();

    secrets.seal(uid, password, SHADOW).unwrap();
    assert_eq!(
        secrets
            .release(uid, SHADOW)
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some(password)
    );
    assert!(!files_contain(&rig.config.store_dir, password.as_bytes()));
    assert!(!files_contain(&rig.config.store_dir, SHADOW.as_bytes()));
    assert!(!files_contain(
        &rig.config.store_dir,
        b"$6$rounds=5000$saltsalt"
    ));

    errors.push(secrets.seal(0x1_0000, password, SHADOW).unwrap_err());
    errors.push(
        secrets
            .seal(uid, &format!("{password}\0"), SHADOW)
            .unwrap_err(),
    );
    errors.push(secrets.seal(uid, password, "").unwrap_err());
    let file = user_dir(&rig, uid).join("secret.bin");
    let mut stored = std::fs::read(&file).unwrap();
    let last = stored.len() - 1;
    stored[last] ^= 0x01;
    std::fs::write(&file, &stored).unwrap();
    errors.push(secrets.release(uid, SHADOW).unwrap_err());
    let broken = LoginSecrets::new({
        let mut config = rig.config.clone();
        config.tcti = Some("device:/dev/openhello-no-tpm".into());
        config
    });
    errors.push(broken.release(uid, SHADOW).unwrap_err());
    secrets.purge(uid).unwrap();
    errors.push(broken.seal(uid, password, SHADOW).unwrap_err());

    let store = rig.config.store_dir.to_string_lossy().into_owned();
    for error in &errors {
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains(password), "{text}");
            assert!(!text.contains(SHADOW), "{text}");
            assert!(!text.contains(&store), "{text}");
        }
    }
    let log = lines.0.lock().unwrap().join("\n");
    assert!(log.contains("tpm-failure"), "{log}");
    assert!(!log.contains(password), "{log}");
    assert!(!log.contains("saltsalt"), "{log}");
    assert!(!files_contain(&rig.config.store_dir, password.as_bytes()));
}

// @spec:AC-089
#[test]
fn after_purge_a_restored_backup_cannot_be_released() {
    let rig = rig();
    let protectors = Protectors::new(rig.config.clone()).unwrap();
    let uid = 4104;
    protectors
        .login_secrets()
        .seal(uid, "purged password", SHADOW)
        .unwrap();
    let secrets_dir = rig.config.store_dir.join("login-secrets");
    let backup = tempfile::tempdir().unwrap();
    copy_tree(&secrets_dir, backup.path());
    assert!(persistent_handles(&rig).contains(&key_handle(uid)));

    protectors.purge(uid).unwrap();

    assert!(!user_dir(&rig, uid).exists());
    assert!(!persistent_handles(&rig).contains(&key_handle(uid)));
    copy_tree(backup.path(), &secrets_dir);
    assert!(user_dir(&rig, uid).join("secret.bin").exists());
    assert!(protectors
        .login_secrets()
        .release(uid, SHADOW)
        .unwrap()
        .is_none());
    assert!(!user_dir(&rig, uid).exists());
}

#[test]
fn a_reseal_reuses_the_same_handle_and_purge_frees_it() {
    let rig = rig();
    let secrets = LoginSecrets::new(rig.config.clone());
    let uid = 4108;
    let before = persistent_handles(&rig);
    assert!(!before.contains(&key_handle(uid)));

    secrets.seal(uid, "first", SHADOW).unwrap();
    let sealed = persistent_handles(&rig);
    assert_eq!(sealed.len(), before.len() + 1);
    assert!(sealed.contains(&key_handle(uid)));
    secrets.seal(uid, "second", CHANGED_SHADOW).unwrap();
    assert_eq!(persistent_handles(&rig), sealed);
    assert_eq!(
        secrets
            .release(uid, CHANGED_SHADOW)
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("second")
    );

    secrets.purge(uid).unwrap();

    assert_eq!(persistent_handles(&rig), before);
    secrets.purge(uid).unwrap();
    assert_eq!(persistent_handles(&rig), before);
}

#[test]
fn an_old_key_blob_is_dropped_and_the_next_password_reseals() {
    let rig = rig();
    let secrets = LoginSecrets::new(rig.config.clone());
    let uid = 4109;
    let dir = user_dir(&rig, uid);
    secrets.seal(uid, "old install", SHADOW).unwrap();
    let handle = key_handle(uid);
    assert!(rig
        .tpm2("tpm2_evictcontrol", &["-C", "o", "-c", &handle])
        .status
        .success());
    std::fs::write(dir.join("key.blob"), b"sealed by an old install").unwrap();

    assert!(secrets.release(uid, SHADOW).unwrap().is_none());
    assert!(!dir.exists());

    secrets.seal(uid, "old install", SHADOW).unwrap();
    std::fs::write(dir.join("key.blob"), b"sealed by an old install").unwrap();
    secrets.seal(uid, "typed again", SHADOW).unwrap();
    assert!(!dir.join("key.blob").exists());
    assert_eq!(
        secrets
            .release(uid, SHADOW)
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("typed again")
    );
    secrets.purge(uid).unwrap();
    assert!(!persistent_handles(&rig).contains(&handle));
}

#[test]
fn a_full_tpm_refuses_to_seal_without_leaving_a_secret() {
    let rig = rig();
    let secrets = LoginSecrets::new(rig.config.clone());
    let uid = 4110;
    let work = tempfile::tempdir().unwrap();
    let path = |name: &str| work.path().join(name).display().to_string();
    let (primary, public, private, loaded) =
        (path("p.ctx"), path("f.pub"), path("f.priv"), path("f.ctx"));
    for (tool, args) in [
        (
            "tpm2_createprimary",
            vec!["-C", "o", "-c", primary.as_str()],
        ),
        (
            "tpm2_create",
            vec![
                "-C",
                &primary,
                "-G",
                "aes128cfb",
                "-u",
                &public,
                "-r",
                &private,
            ],
        ),
        (
            "tpm2_load",
            vec!["-C", &primary, "-u", &public, "-r", &private, "-c", &loaded],
        ),
    ] {
        let out = rig.tpm2(tool, &args);
        assert!(
            out.status.success(),
            "{tool}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let mut fillers = Evict(&rig, Vec::new());
    for slot in 0..256u32 {
        let handle = format!("0x{:x}", 0x810a_0000u32 | slot);
        if !rig
            .tpm2("tpm2_evictcontrol", &["-C", "o", "-c", &loaded, &handle])
            .status
            .success()
        {
            break;
        }
        fillers.1.push(handle);
    }
    assert!(fillers.1.len() < 256, "the TPM never filled up");

    assert!(matches!(
        secrets.seal(uid, "no room", SHADOW),
        Err(KeydError::Tpm)
    ));
    assert!(!user_dir(&rig, uid).join("secret.bin").exists());
    assert!(!persistent_handles(&rig).contains(&key_handle(uid)));
    assert!(secrets.release(uid, SHADOW).unwrap().is_none());

    drop(fillers);
    secrets.seal(uid, "room again", SHADOW).unwrap();
    assert_eq!(
        secrets
            .release(uid, SHADOW)
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("room again")
    );
    secrets.purge(uid).unwrap();
}

#[test]
fn no_sealed_secret_releases_nothing() {
    let rig = rig();
    let secrets = LoginSecrets::new(rig.config.clone());

    assert!(secrets.release(4105, SHADOW).unwrap().is_none());
    secrets.purge(4105).unwrap();
}

#[test]
fn a_tampered_ciphertext_is_refused() {
    let rig = rig();
    let secrets = LoginSecrets::new(rig.config.clone());
    let uid = 4106;
    secrets.seal(uid, "tamper target", SHADOW).unwrap();
    let file = user_dir(&rig, uid).join("secret.bin");
    let original = std::fs::read(&file).unwrap();

    for position in [original.len() - 1, original.len() - 20, 69] {
        let mut stored = original.clone();
        stored[position] ^= 0x80;
        std::fs::write(&file, &stored).unwrap();
        assert!(
            matches!(
                secrets.release(uid, SHADOW),
                Err(KeydError::LoginSecretDamaged)
            ),
            "byte {position}"
        );
    }
    std::fs::write(&file, &original[..40]).unwrap();
    assert!(matches!(
        secrets.release(uid, SHADOW),
        Err(KeydError::LoginSecretDamaged)
    ));
    std::fs::write(&file, &original).unwrap();
    assert_eq!(
        secrets
            .release(uid, SHADOW)
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("tamper target")
    );
    secrets.purge(uid).unwrap();
}

#[test]
fn invalid_passwords_are_refused_before_sealing() {
    let rig = rig();
    let secrets = LoginSecrets::new(rig.config.clone());

    for password in [String::new(), "x".repeat(513), "a\0b".into()] {
        assert!(matches!(
            secrets.seal(4107, &password, SHADOW),
            Err(KeydError::InvalidPassword)
        ));
    }
    assert!(matches!(
        secrets.seal(4107, "fine", ""),
        Err(KeydError::NoShadowEntry)
    ));
    assert!(!user_dir(&rig, 4107).exists());
}
