use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use openhello_keyd::logging::{self, Level, LogSink};
use openhello_keyd::{resolve_module, KeydError};

const DEBIAN: &str = "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so";
const SUSE: &str = "/usr/lib64/pkcs11/libtpm2_pkcs11.so";

fn existing(paths: &[&str]) -> impl Fn(&Path) -> bool {
    let set: HashSet<PathBuf> = paths.iter().map(PathBuf::from).collect();
    move |path| set.contains(path)
}

#[derive(Default)]
struct Lines(Mutex<Vec<String>>);

impl LogSink for Lines {
    fn write_line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }
}

// @covers:AC-016-module
#[test]
fn an_explicit_module_path_wins_over_everything() {
    let found = resolve_module(
        Some(Path::new("/opt/tpm/module.so")),
        Some(Path::new("/root")),
        existing(&[SUSE, DEBIAN]),
    );
    assert_eq!(found.unwrap(), PathBuf::from("/opt/tpm/module.so"));
}

// @covers:AC-016-module
#[test]
fn the_test_prefix_wins_over_the_system_locations() {
    let found = resolve_module(None, Some(Path::new("/root")), existing(&[SUSE, DEBIAN]));
    assert_eq!(
        found.unwrap(),
        PathBuf::from("/root/usr/lib64/pkcs11/libtpm2_pkcs11.so")
    );
}

// @covers:AC-016-module
#[test]
fn the_system_locations_are_tried_in_order() {
    assert_eq!(
        resolve_module(None, None, existing(&[SUSE, DEBIAN])).unwrap(),
        PathBuf::from(SUSE)
    );
    assert_eq!(
        resolve_module(None, None, existing(&[DEBIAN])).unwrap(),
        PathBuf::from(DEBIAN)
    );
    for path in [
        "/usr/lib/aarch64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
        "/usr/lib/pkcs11/libtpm2_pkcs11.so",
    ] {
        assert_eq!(
            resolve_module(None, None, existing(&[path])).unwrap(),
            PathBuf::from(path)
        );
    }
}

// @covers:AC-016-module
#[test]
fn a_missing_module_logs_every_path_tried_and_tells_the_caller_nothing_specific() {
    let lines = Arc::new(Lines::default());
    logging::configure(Level::Info, lines.clone());

    let error = resolve_module(None, None, existing(&[])).unwrap_err();

    assert!(matches!(error, KeydError::Config(_)));
    assert!(!error.to_string().contains("/usr/lib"));
    let log = lines.0.lock().unwrap().join("\n");
    for path in [
        SUSE,
        DEBIAN,
        "/usr/lib/aarch64-linux-gnu/pkcs11",
        "/usr/lib/pkcs11/",
    ] {
        assert!(log.contains(path), "{log}");
    }
}
