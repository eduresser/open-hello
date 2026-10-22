use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use openhello_keyd::logging::{self, Level, LogSink};
use openhello_keyd::{resolve_module, KeydError};

const REAL_LISTING: &str = "module: p11-kit-trust
    path: /usr/lib64/pkcs11/p11-kit-trust.so
    uri: pkcs11:library-description=PKCS%2311%20Kit%20Trust%20Module;library-manufacturer=PKCS%2311%20Kit
    library-description: PKCS#11 Kit Trust Module
    library-manufacturer: PKCS#11 Kit
    library-version: 0.26
    token: System Trust
        uri: pkcs11:model=p11-kit-trust;manufacturer=PKCS%2311%20Kit;serial=1;token=System%20Trust
        manufacturer: PKCS#11 Kit
        model: p11-kit-trust
        flags:
              write-protected
              token-initialized

module: opensc-pkcs11
    path: /usr/lib64/pkcs11/opensc-pkcs11.so
    uri: pkcs11:library-description=OpenSC%20smartcard%20framework;library-manufacturer=OpenSC%20Project
    library-description: OpenSC smartcard framework
    library-manufacturer: OpenSC Project
    library-version: 0.26

module: tpm2_pkcs11
    path: /opt/tpm/lib/libtpm2_pkcs11.so
    uri: pkcs11:library-description=TPM2.0%20Cryptoki;library-manufacturer=tpm2-software.github.io
    library-description: TPM2.0 Cryptoki
    library-manufacturer: tpm2-software.github.io
    library-version: 1.9
";

const NO_TPM_LISTING: &str = "module: p11-kit-trust
    path: /usr/lib64/pkcs11/p11-kit-trust.so
    library-description: PKCS#11 Kit Trust Module
";

fn listing(text: &'static str) -> impl FnOnce() -> Option<String> {
    move || Some(text.to_string())
}

fn never_loads(_: &str) -> bool {
    false
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
        listing(REAL_LISTING),
        |_| true,
    );
    assert_eq!(found.unwrap(), PathBuf::from("/opt/tpm/module.so"));
}

// @covers:AC-016-module
#[test]
fn the_test_prefix_wins_over_p11_kit_and_the_loader() {
    let found = resolve_module(
        None,
        Some(Path::new("/root")),
        listing(REAL_LISTING),
        |_| true,
    );
    assert_eq!(
        found.unwrap(),
        PathBuf::from("/root/usr/lib64/pkcs11/libtpm2_pkcs11.so")
    );
}

// @covers:AC-016-module
#[test]
fn p11_kit_names_the_module_among_several_and_wins_over_the_loader() {
    let found = resolve_module(None, None, listing(REAL_LISTING), |_| true);
    assert_eq!(
        found.unwrap(),
        PathBuf::from("/opt/tpm/lib/libtpm2_pkcs11.so")
    );
}

// @covers:AC-016-module
#[test]
fn a_p11_kit_listing_without_tpm2_falls_through_to_the_loader_by_name() {
    let asked = Cell::new(None);
    let found = resolve_module(None, None, listing(NO_TPM_LISTING), |name| {
        asked.set(Some(name.to_string()));
        true
    });
    assert_eq!(found.unwrap(), PathBuf::from("libtpm2_pkcs11.so"));
    assert_eq!(asked.take().as_deref(), Some("libtpm2_pkcs11.so"));
}

// @covers:AC-016-module
#[test]
fn a_missing_or_failing_p11_kit_falls_through_to_the_loader_by_name() {
    let found = resolve_module(None, None, || None, |_| true);
    assert_eq!(found.unwrap(), PathBuf::from("libtpm2_pkcs11.so"));
}

// @covers:AC-016-module
#[test]
fn a_path_line_for_another_library_is_not_taken_for_the_module() {
    let text = "module: x\n    path: /usr/lib64/pkcs11/libtpm2_pkcs11.so.bak\n";
    let error = resolve_module(None, None, || Some(text.to_string()), never_loads);
    assert!(error.is_err());
}

// @covers:AC-016-module
#[test]
fn nothing_found_logs_the_origins_tried_and_tells_the_caller_nothing_specific() {
    let lines = Arc::new(Lines::default());
    logging::configure(Level::Info, lines.clone());

    let error = resolve_module(None, None, listing(NO_TPM_LISTING), never_loads).unwrap_err();

    assert!(matches!(error, KeydError::Config(_)));
    assert!(!error.to_string().contains("/usr/lib"));
    let log = lines.0.lock().unwrap().join("\n");
    for origin in [
        "OPENHELLO_TPM2_PKCS11_MODULE",
        "OPENHELLO_TPM2_PKCS11_PREFIX",
        "p11-kit list-modules",
        "loader cache",
    ] {
        assert!(log.contains(origin), "{log}");
    }
}
