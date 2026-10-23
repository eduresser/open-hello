#[path = "../../openhellod/tests/support/fake_sudo.rs"]
mod fake_sudo;

use std::fs;
use std::process::Command;

use fake_sudo::{my_uid, FakeSudo, Reads, Visudo, TUMBLEWEED_DEFAULTS};

fn cli(fake: &FakeSudo, args: &[&str]) -> (i32, String, String) {
    let path = format!("{}:{}", fake.dir.path().display(), std::env::var("PATH").unwrap());
    let out = Command::new(env!("CARGO_BIN_EXE_openhello-cli"))
        .arg("sudo")
        .args(args)
        .env("PATH", path)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn status_own_password_and_restore_round_trip_through_the_drop_in() {
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Accepts, Reads::DropIns);
    let (uid, root) = (my_uid().to_string(), fake.dir.path().to_str().unwrap().to_string());
    assert_eq!(cli(&fake, &["status", &uid, "--root", &root]), (0, "root-password".into(), String::new()));
    assert_eq!(cli(&fake, &["own-password", &uid, "--root", &root]).1, "own-password");
    assert!(fake.drop_in(my_uid()).exists());
    assert_eq!(cli(&fake, &["status", &uid, "--root", &root]).1, "own-password");
    assert_eq!(cli(&fake, &["restore", &uid, "--root", &root]).1, "restored");
    assert_eq!(cli(&fake, &["restore", &uid, "--root", &root]).1, "nothing to restore");
    assert_eq!(cli(&fake, &["status", &uid, "--root", &root]).1, "root-password");
}

#[test]
fn a_rejected_drop_in_exits_three_and_leaves_no_file() {
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Rejects, Reads::DropIns);
    let (code, _, stderr) = cli(&fake, &["own-password", &my_uid().to_string(), "--root", fake.dir.path().to_str().unwrap()]);
    assert_eq!(code, 3);
    assert!(stderr.contains("visudo rejected"), "{stderr}");
    assert!(fake.entries().is_empty());
}

#[test]
fn writing_the_real_directory_requires_root_and_bad_arguments_exit_two() {
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Accepts, Reads::DropIns);
    if my_uid() != 0 {
        let (code, _, stderr) = cli(&fake, &["own-password", &my_uid().to_string()]);
        assert_eq!(code, 3);
        assert!(stderr.contains("requires root"), "{stderr}");
    }
    for args in [vec![], vec!["grant", "1000"], vec!["status"], vec!["status", "ana"], vec!["status", "1000", "--force"]] {
        assert_eq!(cli(&fake, &args).0, 2, "{args:?}");
    }
    assert!(!fs::exists(fake.drop_in_dir()).unwrap());
}
