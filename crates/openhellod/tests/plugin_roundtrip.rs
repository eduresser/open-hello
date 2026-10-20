#[path = "../../../tests/support/swtpm_harness.rs"]
mod swtpm_harness;

use std::path::{Path, PathBuf};
use std::process::Command;

use openhellod::backends::{DaemonError, StorageBackend};
use openhellod::plugin_loader::{EnginePlugin, SensorPlugin, StoragePlugin};

fn build_plugins() -> PathBuf {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let target = workspace.join("target/plugin-fixtures");
    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["build", "-p", "sensor-adapter-ir", "-p", "engine-adapter-face", "-p", "storage-adapter-templates"])
        .arg("--target-dir")
        .arg(&target)
        .current_dir(&workspace)
        .status()
        .expect("cargo must be runnable to build plugin fixtures");
    assert!(status.success(), "plugin fixtures failed to build");
    target.join("debug")
}

#[test]
fn storage_plugin_round_trips_a_template_through_the_real_cdylib_and_swtpm() {
    let plugins = build_plugins();
    let tpm = swtpm_harness::SwTpm::start();
    std::env::set_var("OPENHELLO_TPM_TCTI", &tpm.tcti);
    let state = tempfile::tempdir().unwrap();

    let mut storage = StoragePlugin::load(&plugins.join("libstorage_adapter_templates.so"), state.path().to_str().unwrap()).unwrap();
    assert!(matches!(storage.get(1000), Err(DaemonError::NotFound)));
    storage.put(1000, b"template-one").unwrap();
    storage.put(1001, b"template-two").unwrap();
    assert_eq!(storage.get(1000).unwrap(), b"template-one");
    assert_eq!(storage.list_uids().unwrap(), vec![1000, 1001]);

    let file = state.path().join("1000.tpl");
    let mut bytes = std::fs::read(&file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&file, bytes).unwrap();
    assert!(matches!(storage.get(1000), Err(DaemonError::Tampered)));

    storage.purge(1001).unwrap();
    assert!(matches!(storage.get(1001), Err(DaemonError::NotFound)));
    assert_eq!(storage.list_uids().unwrap(), vec![1000]);
}

#[test]
fn engine_and_sensor_cdylibs_load_and_report_configuration_problems() {
    let plugins = build_plugins();
    let engine_error = EnginePlugin::load(&plugins.join("libengine_adapter_face.so"), r#"{"models_dir":"/nonexistent","calibration_path":"/nonexistent"}"#)
        .err()
        .unwrap();
    assert!(matches!(engine_error, DaemonError::InvalidRequest(_)), "{engine_error}");

    let sensor_error = SensorPlugin::load(&plugins.join("libsensor_adapter_ir.so"), "/dev/video2").err().unwrap();
    assert!(matches!(sensor_error, DaemonError::Backend(_)), "{sensor_error}");
}
