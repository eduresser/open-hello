mod support;

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use openhello_keyd::{Keyd, Protectors};
use support::rig;

fn uid() -> u32 {
    let uid = unsafe { libc::getuid() };
    assert!(
        uid <= 0xFFFF,
        "run the tests as a regular user (uid {uid} is outside 0..=65535)"
    );
    uid
}

// @covers:AC-027-auth-backfill
#[test]
fn keyd_rewrites_the_public_key_file_of_a_token_provisioned_before_the_file_existed() {
    let rig = rig();
    rig.clear_lockout();
    let protectors = Protectors::new(rig.config.clone()).unwrap();
    protectors.provision_protectors(uid()).unwrap();
    let dir = &rig.config.auth_dir;
    let file = dir.join(format!("{}.pub", uid()));
    let original = std::fs::read_to_string(&file).unwrap();

    std::fs::remove_dir_all(dir).unwrap();
    protectors.keyd().backfill_auth_keys();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
    let meta = std::fs::metadata(&file).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o644);
    assert_eq!(meta.uid(), unsafe { libc::geteuid() });
    assert_eq!(std::fs::metadata(dir).unwrap().mode() & 0o7777, 0o755);

    protectors.keyd().backfill_auth_keys();
    assert_eq!(std::fs::metadata(&file).unwrap().ino(), meta.ino());

    std::fs::write(&file, "tampered").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    protectors.keyd().backfill_auth_keys();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
    assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o7777, 0o644);

    let empty = tempfile::tempdir().unwrap();
    let mut config = rig.config.clone();
    config.store_dir = empty.path().join("store");
    config.auth_dir = empty.path().join("auth");
    Keyd::new(config).backfill_auth_keys();
    assert!(!empty.path().join("auth").exists());

    let broken = tempfile::tempdir().unwrap();
    let mut config = rig.config.clone();
    config.store_dir = broken.path().to_path_buf();
    config.auth_dir = broken.path().join("auth");
    std::fs::write(broken.path().join("tpm2_pkcs11.sqlite3"), b"not a database").unwrap();
    Keyd::new(config).backfill_auth_keys();
    assert!(!broken.path().join("auth").exists());

    let blocked = tempfile::tempdir().unwrap();
    let mut config = rig.config.clone();
    config.auth_dir = blocked.path().join("file").join("auth");
    std::fs::write(blocked.path().join("file"), b"x").unwrap();
    Keyd::new(config).backfill_auth_keys();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
}
