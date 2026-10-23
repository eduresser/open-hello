use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn desktop_entry() -> Vec<(String, String)> {
    let text = fs::read_to_string(repo().join("packaging/openhello.desktop")).unwrap();
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn value(entry: &[(String, String)], key: &str) -> String {
    entry
        .iter()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("missing key {key}"))
        .1
        .clone()
}

fn installed_window_binary() -> String {
    let script = fs::read_to_string(repo().join("scripts/install.sh")).unwrap();
    let line = script
        .lines()
        .find(|l| l.contains("install -m 0755") && l.contains("$T/openhello-gui"))
        .expect("install.sh installs the window binary");
    let target = line.split_whitespace().last().unwrap();
    Path::new(target)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

// @spec:AC-067
#[test]
fn desktop_entry_has_the_required_keys_and_launches_the_installed_binary() {
    let entry = desktop_entry();
    assert_eq!(value(&entry, "Type"), "Application");
    assert_eq!(value(&entry, "Name"), "Open Hello");
    assert_eq!(value(&entry, "GenericName"), "Face recognition");
    assert_eq!(value(&entry, "Terminal"), "false");
    assert!(!value(&entry, "Comment").is_empty());
    assert_eq!(value(&entry, "Icon"), "openhello");
    let categories = value(&entry, "Categories");
    assert!(categories.split(';').any(|c| c == "Settings"), "{categories}");
    let exec = value(&entry, "Exec");
    assert_eq!(exec.split_whitespace().next().unwrap(), installed_window_binary());
    assert_eq!(installed_window_binary(), "openhello-gui");
}

struct Run {
    status: i32,
    output: String,
}

fn fake_pkg_config(dir: &Path, exit: i32) {
    let path = dir.join("pkg-config");
    fs::write(&path, format!("#!/bin/sh\nexit {exit}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn dry_run(pkg_config_exit: i32, os_release: &str, extra: &[&str]) -> Run {
    let dir = tempfile::tempdir().unwrap();
    fake_pkg_config(dir.path(), pkg_config_exit);
    let release = dir.path().join("os-release");
    fs::write(&release, os_release).unwrap();
    let path = format!("{}:{}", dir.path().display(), std::env::var("PATH").unwrap());
    let out = Command::new("bash")
        .arg(repo().join("scripts/install.sh"))
        .args(["--dry-run", "--skip-checks"])
        .args(extra)
        .env("PATH", path)
        .env("OPENHELLO_OS_RELEASE", &release)
        .output()
        .unwrap();
    Run {
        status: out.status.code().unwrap(),
        output: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

// @spec:AC-068
#[test]
fn missing_headers_skip_the_window_name_the_packages_and_keep_going() {
    let cases = [
        ("ID=opensuse-tumbleweed\nID_LIKE=\"opensuse suse\"\n", "fontconfig-devel freetype2-devel"),
        ("ID=fedora\n", "fontconfig-devel freetype-devel"),
        ("ID=ubuntu\nID_LIKE=debian\n", "libfontconfig-dev libfreetype-dev"),
        ("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n", "libfontconfig-dev libfreetype-dev"),
        ("ID=manjaro\nID_LIKE=arch\n", "fontconfig freetype2"),
        ("ID=nixos\n", "the fontconfig and FreeType development packages"),
    ];
    for (release, packages) in cases {
        let run = dry_run(1, release, &[]);
        assert_eq!(run.status, 0, "{}", run.output);
        assert!(run.output.contains("window (openhello-gui) was skipped"), "{}", run.output);
        assert!(run.output.contains(&format!("Install {packages} and")), "{release}: {}", run.output);
        assert!(run.output.contains("openhello-cli keeps working"), "{}", run.output);
        assert!(!run.output.contains("-p openhello-gui"), "{}", run.output);
        assert!(run.output.contains("openhello-keyd.service"), "{}", run.output);
        assert!(run.output.contains("systemctl restart openhellod"), "{}", run.output);
    }
}

// @spec:AC-068
#[test]
fn present_headers_list_building_and_installing_the_window_and_the_entry() {
    let run = dry_run(0, "ID=fedora\n", &[]);
    assert_eq!(run.status, 0, "{}", run.output);
    assert!(run.output.contains("cargo build --release") && run.output.contains("-p openhello-gui"), "{}", run.output);
    assert!(run.output.contains("/usr/local/bin/openhello-gui"), "{}", run.output);
    assert!(run.output.contains("/usr/local/share/applications/openhello.desktop"), "{}", run.output);
    assert!(run.output.contains("/usr/local/share/icons/hicolor/scalable/apps/openhello.svg"), "{}", run.output);
    assert!(!run.output.contains("was skipped"), "{}", run.output);
}

// @spec:AC-068
#[test]
fn no_gui_leaves_the_window_out_entirely() {
    let run = dry_run(0, "ID=fedora\n", &["--no-gui"]);
    assert_eq!(run.status, 0, "{}", run.output);
    assert!(!run.output.contains("openhello-gui"), "{}", run.output);
    assert!(!run.output.contains("openhello.desktop"), "{}", run.output);
    assert!(!run.output.contains("openhello.svg"), "{}", run.output);
    assert!(!run.output.contains("was skipped"), "{}", run.output);
}
