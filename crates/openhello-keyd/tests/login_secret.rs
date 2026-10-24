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
    for name in ["key.blob", "secret.bin"] {
        let mode = std::fs::metadata(user_dir(&rig, uid).join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
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
fn after_purge_a_restored_ciphertext_cannot_be_released() {
    let rig = rig();
    let protectors = Protectors::new(rig.config.clone()).unwrap();
    let uid = 4104;
    protectors
        .login_secrets()
        .seal(uid, "purged password", SHADOW)
        .unwrap();
    let dir = user_dir(&rig, uid);
    let ciphertext = std::fs::read(dir.join("secret.bin")).unwrap();

    protectors.purge(uid).unwrap();

    assert!(!dir.exists());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("secret.bin"), &ciphertext).unwrap();
    assert!(protectors
        .login_secrets()
        .release(uid, SHADOW)
        .unwrap()
        .is_none());
    assert!(!dir.join("secret.bin").exists());
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
