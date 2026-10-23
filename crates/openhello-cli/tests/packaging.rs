use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new(pam_enable_exit: i32) -> Sandbox {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("bin")).unwrap();
        fs::create_dir(dir.path().join("systemd")).unwrap();
        let log = dir.path().join("calls");
        for (tool, exit) in [("openhello-cli", pam_enable_exit), ("systemctl", 0)] {
            let script = format!(
                "#!/bin/sh\necho \"{tool} $*\" >> {log}\n[ \"$1 $2\" = \"pam enable\" ] && exit {exit}\nexit 0\n",
                log = log.display()
            );
            let path = dir.path().join("bin").join(tool);
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Sandbox { dir }
    }

    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    fn run(&self, script: &str, args: &[&str]) -> (i32, String) {
        let path = format!("{}:{}", self.dir.path().join("bin").display(), std::env::var("PATH").unwrap());
        let out = Command::new("sh")
            .arg(repo().join("packaging/package").join(script))
            .args(args)
            .env("PATH", path)
            .env("OPENHELLO_PKG_STATE_DIR", self.state())
            .env("OPENHELLO_PKG_SYSTEMD_RUN_DIR", self.dir.path().join("systemd"))
            .output()
            .unwrap();
        (out.status.code().unwrap(), String::from_utf8_lossy(&out.stderr).into_owned())
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.dir.path().join("calls")).unwrap_or_default()
    }
}

#[test]
fn first_install_enables_pam_once_and_starts_both_daemons() {
    let sandbox = Sandbox::new(0);
    let (status, _) = sandbox.run("postinstall.sh", &["configure"]);
    assert_eq!(status, 0);
    let calls = sandbox.calls();
    assert!(calls.contains("openhello-cli pam migrate"), "{calls}");
    assert!(calls.contains("openhello-cli pam enable\n"), "{calls}");
    assert!(calls.contains("systemctl enable openhello-keyd.service openhellod.service"), "{calls}");
    assert!(calls.contains("systemctl restart openhellod.service"), "{calls}");
    assert!(sandbox.state().join("pam-enabled-by-package").exists());
}

#[test]
fn upgrade_keeps_the_owner_pam_choice_and_restarts_daemons() {
    let sandbox = Sandbox::new(0);
    sandbox.run("postinstall.sh", &["configure"]);
    fs::remove_file(sandbox.dir.path().join("calls")).unwrap();
    let (status, _) = sandbox.run("postinstall.sh", &["2"]);
    assert_eq!(status, 0);
    let calls = sandbox.calls();
    assert!(!calls.contains("pam enable"), "{calls}");
    assert!(calls.contains("systemctl restart openhello-keyd.service"), "{calls}");
}

#[test]
fn failed_pam_enable_still_installs_and_retries_next_time() {
    let sandbox = Sandbox::new(3);
    let (status, stderr) = sandbox.run("postinstall.sh", &["1"]);
    assert_eq!(status, 0);
    assert!(stderr.contains("passwords are untouched"), "{stderr}");
    assert!(!sandbox.state().join("pam-enabled-by-package").exists());
    assert!(sandbox.calls().contains("systemctl restart openhellod.service"));
}

#[test]
fn without_running_systemd_no_service_is_touched() {
    let sandbox = Sandbox::new(0);
    fs::remove_dir(sandbox.dir.path().join("systemd")).unwrap();
    let (status, _) = sandbox.run("postinstall.sh", &["configure"]);
    assert_eq!(status, 0);
    assert!(!sandbox.calls().contains("systemctl"), "{}", sandbox.calls());
}

#[test]
fn upgrades_never_disable_pam_or_stop_daemons() {
    for argument in ["upgrade", "failed-upgrade", "1"] {
        let sandbox = Sandbox::new(0);
        let (status, _) = sandbox.run("preremove.sh", &[argument]);
        assert_eq!(status, 0);
        assert_eq!(sandbox.calls(), "", "{argument}");
    }
}

#[test]
fn removal_disables_pam_forgets_the_choice_and_stops_daemons() {
    for argument in ["remove", "0", "0.2.0-1"] {
        let sandbox = Sandbox::new(0);
        sandbox.run("postinstall.sh", &["configure"]);
        let (status, _) = sandbox.run("preremove.sh", &[argument]);
        assert_eq!(status, 0);
        let calls = sandbox.calls();
        assert!(calls.contains("openhello-cli pam disable"), "{argument}: {calls}");
        assert!(calls.contains("systemctl disable --now openhellod.service openhello-keyd.service"), "{argument}: {calls}");
        assert!(!sandbox.state().join("pam-enabled-by-package").exists(), "{argument}");
    }
}

fn packaged_destinations() -> Vec<String> {
    fs::read_to_string(repo().join("packaging/nfpm.yaml"))
        .unwrap()
        .lines()
        .filter_map(|line| line.trim().strip_prefix("dst: "))
        .map(str::to_string)
        .collect()
}

#[test]
fn every_path_the_units_and_config_use_is_in_the_package() {
    let destinations = packaged_destinations();
    let mut referenced = Vec::new();
    for unit in ["openhellod.service", "openhello-keyd.service"] {
        let text = fs::read_to_string(repo().join("packaging").join(unit)).unwrap();
        for word in text.replace("@LIBEXECDIR@", "/usr/libexec/openhello").split_whitespace() {
            let word = word.rsplit('=').next().unwrap().trim_start_matches('-');
            if word.starts_with("/usr/") {
                referenced.push(word.to_string());
            }
        }
    }
    referenced.push("/usr/share/openhello/models/yunet.onnx".into());
    referenced.push("/usr/share/openhello/models/glintr100.onnx".into());
    assert!(referenced.len() > 5, "{referenced:?}");
    for path in referenced {
        assert!(destinations.contains(&path), "{path} is used but not packaged");
    }
}

#[test]
fn pam_module_lands_in_each_family_module_directory() {
    let destinations = packaged_destinations();
    for dir in ["/usr/lib/x86_64-linux-gnu/security", "/usr/lib64/security", "/usr/lib/security"] {
        assert!(destinations.contains(&format!("{dir}/pam_openhello.so")), "{dir}");
    }
}

#[test]
fn packaged_config_matches_the_paths_the_daemon_reads() {
    let env = fs::read_to_string(repo().join("packaging/package/openhello.env")).unwrap();
    assert!(env.lines().any(|l| l == "ORT_DYLIB_PATH=/usr/lib/openhello/libonnxruntime.so"), "{env}");
    let engine = fs::read_to_string(repo().join("packaging/package/engine.json")).unwrap();
    assert_eq!(engine.trim(), r#"{"models_dir": "/usr/share/openhello/models"}"#);
}
