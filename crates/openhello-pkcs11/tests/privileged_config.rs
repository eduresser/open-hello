use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use openhello_pkcs11::config::{is_privileged, resolve};
use openhello_pkcs11::{
    wire_request, CONFIG_ENV, REAL_MODULE_ENV, TEST_BUS_ADDRESS_ENV, UNLOCK_SOCKET_ENV,
};

const CALLER: u32 = 1000;
const ROOT: u32 = 0;
const OP_UNLOCK_FOR_UID: u8 = 4;
const OP_TAKE_GRANT: u8 = 1;
const OP_UNLOCK_PIN: u8 = 2;

fn owner() -> u32 {
    unsafe { libc::getuid() }
}

fn write_config(dir: &Path, mode: u32, text: &str) -> PathBuf {
    let path = dir.join("pkcs11.conf");
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

const SYSTEM: &str = "# root-owned\nmodule = /usr/lib64/pkcs11/libtpm2_pkcs11.so\nunlock_socket = /run/openhello/keyd-unlock.sock\nstore_dir = /var/lib/openhello-keyd\ntcti = device:/dev/tpmrm0\n";

fn hostile_env(name: &str) -> Option<String> {
    match name {
        REAL_MODULE_ENV => Some("/tmp/evil.so".into()),
        UNLOCK_SOCKET_ENV => Some("/tmp/evil.sock".into()),
        TEST_BUS_ADDRESS_ENV => Some("unix:path=/tmp/evil-bus".into()),
        CONFIG_ENV => Some("/tmp/evil.conf".into()),
        _ => None,
    }
}

#[test]
fn a_setuid_caller_gets_its_module_and_sockets_from_the_root_owned_file_never_from_the_environment()
{
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), 0o644, SYSTEM);

    for (ruid, euid) in [(CALLER, ROOT), (CALLER, 1001)] {
        assert!(is_privileged(ruid, euid));
        let settings = resolve(ruid, euid, &hostile_env, &path, owner()).unwrap();
        assert_eq!(
            settings.module,
            Some("/usr/lib64/pkcs11/libtpm2_pkcs11.so".into())
        );
        assert_eq!(
            settings.unlock_socket,
            Some("/run/openhello/keyd-unlock.sock".into())
        );
        assert_eq!(settings.store_dir, Some("/var/lib/openhello-keyd".into()));
        assert_eq!(settings.tcti.as_deref(), Some("device:/dev/tpmrm0"));
        assert_eq!(settings.bus_address, None);
    }
    assert!(is_privileged(ROOT, ROOT));
}

#[test]
fn a_privileged_caller_is_refused_a_config_that_is_not_trustworthy() {
    let dir = tempfile::tempdir().unwrap();
    let writable = write_config(dir.path(), 0o664, SYSTEM);
    let error = resolve(CALLER, ROOT, &hostile_env, &writable, owner()).unwrap_err();
    assert!(error.contains("not writable by group or others"), "{error}");

    let other_owner = write_config(dir.path(), 0o644, SYSTEM);
    let error = resolve(CALLER, ROOT, &hostile_env, &other_owner, owner() + 1).unwrap_err();
    assert!(error.contains("owned by uid"), "{error}");

    let missing = dir.path().join("absent.conf");
    assert!(resolve(CALLER, ROOT, &hostile_env, &missing, owner()).is_err());

    let unknown = write_config(dir.path(), 0o644, "module = /m\nrun_this = /bin/sh\n");
    let error = resolve(CALLER, ROOT, &hostile_env, &unknown, owner()).unwrap_err();
    assert!(error.contains("unknown key `run_this`"), "{error}");

    let malformed = write_config(dir.path(), 0o644, "module\n");
    assert!(resolve(CALLER, ROOT, &hostile_env, &malformed, owner()).is_err());
}

#[test]
fn an_unprivileged_caller_may_override_the_file_with_its_environment() {
    let dir = tempfile::tempdir().unwrap();
    let system = write_config(dir.path(), 0o644, SYSTEM);
    assert!(!is_privileged(CALLER, CALLER));

    let no_env = |_: &str| None;
    let from_file = resolve(CALLER, CALLER, &no_env, &system, owner()).unwrap();
    assert_eq!(
        from_file.unlock_socket,
        Some("/run/openhello/keyd-unlock.sock".into())
    );

    let env = |name: &str| match name {
        REAL_MODULE_ENV => Some("/tmp/real.so".to_string()),
        UNLOCK_SOCKET_ENV => Some("/tmp/unlock.sock".to_string()),
        _ => None,
    };
    let settings = resolve(CALLER, CALLER, &env, &system, owner()).unwrap();
    assert_eq!(settings.module, Some("/tmp/real.so".into()));
    assert_eq!(settings.unlock_socket, Some("/tmp/unlock.sock".into()));

    let missing = dir.path().join("absent.conf");
    let none = resolve(CALLER, CALLER, &no_env, &missing, owner()).unwrap();
    assert_eq!(none.module, None);

    let named = |name: &str| (name == CONFIG_ENV).then(|| missing.display().to_string());
    assert!(resolve(CALLER, CALLER, &named, &system, owner()).is_err());
}

#[test]
fn under_setuid_sudo_the_real_caller_is_named_to_keyd_and_otherwise_the_request_is_untouched() {
    let (op, payload) = wire_request(CALLER, ROOT, OP_TAKE_GRANT, &[]);
    assert_eq!(op, OP_UNLOCK_FOR_UID);
    assert_eq!(&payload[..], [0, 0, 0x03, 0xe8, OP_TAKE_GRANT]);

    let (op, payload) = wire_request(CALLER, ROOT, OP_UNLOCK_PIN, b"482916");
    assert_eq!(op, OP_UNLOCK_FOR_UID);
    assert_eq!(&payload[..5], [0, 0, 0x03, 0xe8, OP_UNLOCK_PIN]);
    assert_eq!(&payload[5..], b"482916");

    for (ruid, euid) in [(CALLER, CALLER), (ROOT, ROOT), (CALLER, 1001)] {
        let (op, payload) = wire_request(ruid, euid, OP_UNLOCK_PIN, b"482916");
        assert_eq!(op, OP_UNLOCK_PIN);
        assert_eq!(&payload[..], b"482916");
    }
}
