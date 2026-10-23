use std::fs;
use std::os::unix::fs::PermissionsExt;

use openhellod::polkit_admin::{admin_rule, PolkitAdminStore};

fn my_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn my_name() -> String {
    let out = std::process::Command::new("id").arg("-un").output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn the_rule_makes_only_that_user_their_own_administrator() {
    assert_eq!(
        admin_rule("ana"),
        "polkit.addAdminRule(function(action, subject) {\n    if (subject.user == \"ana\") {\n        return [\"unix-user:ana\"];\n    }\n});\n"
    );
}

#[test]
fn the_rule_is_written_before_the_distro_default_readable_by_polkitd_and_removed_on_restore() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("polkit-1/rules.d");
    let store = PolkitAdminStore::new(&rules);
    assert!(!store.is_own(my_uid()));
    store.use_own_identity(my_uid()).unwrap();
    store.use_own_identity(my_uid()).unwrap();
    let path = rules.join(format!("49-openhello-uid{}.rules", my_uid()));
    assert_eq!(fs::read_to_string(&path).unwrap(), admin_rule(&my_name()));
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644);
    assert_eq!(fs::metadata(&rules).unwrap().permissions().mode() & 0o777, 0o755);
    assert_eq!(fs::read_dir(&rules).unwrap().count(), 1, "no staging file is left behind");
    assert!(store.is_own(my_uid()));
    assert_eq!(store.restore(my_uid()), Ok(true));
    assert_eq!(store.restore(my_uid()), Ok(false));
    assert!(!store.is_own(my_uid()));
}

#[test]
fn a_uid_without_an_account_gets_no_rule() {
    let dir = tempfile::tempdir().unwrap();
    let store = PolkitAdminStore::new(dir.path());
    let error = store.use_own_identity(4_000_000_000).unwrap_err();
    assert!(error.contains("no plain user name"), "{error}");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}
