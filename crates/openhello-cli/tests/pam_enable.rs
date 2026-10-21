use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use openhello_cli::pam_enable::run;

const DEBIAN_SUDO: &str = "#%PAM-1.0\n\nsession    required   pam_env.so readenv=1 user_readenv=0\nsession    required   pam_limits.so\n\n@include common-auth\n@include common-account\n@include common-session-noninteractive\n";
const SUSE_SUDO: &str = "#%PAM-1.0\nauth      include       system-auth\naccount   include       system-auth\nsession   include       system-auth\n";
const FEDORA_SUDO: &str = "#%PAM-1.0\nauth       include      system-auth\naccount    include      system-auth\npassword   include      system-auth\nsession    include      system-auth\n";
const OUR_LINE: &str = "auth sufficient pam_openhello.so";
const OLD_STACK: &str =
    "#%PAM-1.0\nauth    sufficient  pam_openhello.so\nauth    required    pam_pkcs11.so\n";

struct Tree {
    dir: tempfile::TempDir,
}

impl Tree {
    fn new() -> Tree {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("etc/pam.d")).unwrap();
        fs::create_dir_all(dir.path().join("usr/lib/pam.d")).unwrap();
        Tree { dir }
    }
    fn etc(&self, name: &str) -> PathBuf {
        self.dir.path().join("etc/pam.d").join(name)
    }
    fn vendor(&self, name: &str) -> PathBuf {
        self.dir.path().join("usr/lib/pam.d").join(name)
    }
    fn put(&self, name: &str, content: &str) {
        fs::write(self.etc(name), content).unwrap();
    }
    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.etc(name)).unwrap()
    }
    fn pam(&self, args: &[&str]) -> (Result<(), String>, String) {
        let mut all: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        all.push("--root".into());
        all.push(self.dir.path().to_str().unwrap().into());
        let mut out = Vec::new();
        let result = run(&all, &mut out).map_err(|f| f.message);
        (result, String::from_utf8(out).unwrap())
    }
}

fn with_line(content: &str, before: &str) -> String {
    content.replacen(before, &format!("{OUR_LINE}\n{before}"), 1)
}

fn names(dir: &Path) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    found.sort();
    found
}

// @covers:AC-027-pam-enable
#[test]
fn enable_on_debian_sudo_goes_before_include_common_auth() {
    let tree = Tree::new();
    tree.put("sudo", DEBIAN_SUDO);
    let (result, _) = tree.pam(&["enable", "sudo"]);
    result.unwrap();
    let after = tree.read("sudo");
    assert_eq!(after, with_line(DEBIAN_SUDO, "@include common-auth"));
    let ours = after.find(OUR_LINE).unwrap();
    assert!(ours < after.find("@include common-auth").unwrap());
    assert!(ours > after.find("session    required   pam_limits.so").unwrap());
}

// @covers:AC-027-pam-enable
#[test]
fn enable_on_auth_include_stacks_goes_before_first_auth() {
    for original in [SUSE_SUDO, FEDORA_SUDO] {
        let tree = Tree::new();
        tree.put("sudo", original);
        tree.pam(&["enable", "sudo"]).0.unwrap();
        assert_eq!(tree.read("sudo"), with_line(original, "auth "));
    }
}

// @covers:AC-027-pam-enable
#[test]
fn enable_appends_module_arguments() {
    let tree = Tree::new();
    tree.put("sudo", SUSE_SUDO);
    tree.pam(&[
        "enable",
        "sudo",
        "--arg",
        "allowlist=/etc/openhello/pam-services",
        "--arg",
        "trusted_uid=0",
    ])
    .0
    .unwrap();
    assert!(tree.read("sudo").starts_with("#%PAM-1.0\nauth sufficient pam_openhello.so allowlist=/etc/openhello/pam-services trusted_uid=0\nauth      include"));
}

// @covers:AC-027-pam-enable
#[test]
fn enable_accepts_a_bare_flag_such_as_debug() {
    let tree = Tree::new();
    tree.put("sudo", SUSE_SUDO);
    tree.pam(&["enable", "sudo", "--arg", "debug"]).0.unwrap();
    assert!(tree
        .read("sudo")
        .starts_with("#%PAM-1.0\nauth sufficient pam_openhello.so debug\n"));
    for rejected in ["bad arg", "=x", "a;b", ""] {
        let other = Tree::new();
        other.put("sudo", SUSE_SUDO);
        assert!(
            other.pam(&["enable", "sudo", "--arg", rejected]).0.is_err(),
            "{rejected:?}"
        );
        assert_eq!(other.read("sudo"), SUSE_SUDO, "{rejected:?}");
    }
}

// @covers:AC-027-pam-enable
#[test]
fn enable_copies_the_vendor_file_first() {
    let tree = Tree::new();
    fs::write(tree.vendor("sudo"), DEBIAN_SUDO).unwrap();
    fs::set_permissions(tree.vendor("sudo"), fs::Permissions::from_mode(0o640)).unwrap();
    tree.pam(&["enable", "sudo"]).0.unwrap();
    assert_eq!(
        tree.read("sudo"),
        with_line(DEBIAN_SUDO, "@include common-auth")
    );
    assert_eq!(
        fs::metadata(tree.etc("sudo")).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        fs::read_to_string(tree.vendor("sudo")).unwrap(),
        DEBIAN_SUDO
    );
}

// @covers:AC-027-pam-enable
#[test]
fn enable_fails_clearly_when_the_service_exists_nowhere() {
    let tree = Tree::new();
    let (result, _) = tree.pam(&["enable", "swaylock"]);
    assert!(result
        .unwrap_err()
        .contains("no PAM service file for `swaylock`"));
}

// @covers:AC-027-pam-enable
#[test]
fn backup_is_written_once_with_the_original_content() {
    let tree = Tree::new();
    tree.put("sudo", DEBIAN_SUDO);
    tree.pam(&["enable", "sudo"]).0.unwrap();
    tree.pam(&["disable", "sudo"]).0.unwrap();
    tree.put("sudo", SUSE_SUDO);
    tree.pam(&["enable", "sudo"]).0.unwrap();
    assert_eq!(tree.read("sudo.openhello.bak"), DEBIAN_SUDO);
}

// @covers:AC-027-pam-enable
#[test]
fn enable_is_idempotent() {
    let tree = Tree::new();
    tree.put("sudo", DEBIAN_SUDO);
    tree.pam(&["enable", "sudo"]).0.unwrap();
    let once = tree.read("sudo");
    let (result, out) = tree.pam(&["enable", "sudo"]);
    result.unwrap();
    assert_eq!(tree.read("sudo"), once);
    assert_eq!(once.matches(OUR_LINE).count(), 1);
    assert!(out.contains("already enabled"));
}

// @covers:AC-027-pam-enable
#[test]
fn symlinked_service_is_refused_and_left_untouched() {
    let tree = Tree::new();
    let managed = tree.dir.path().join("managed-sudo");
    fs::write(&managed, DEBIAN_SUDO).unwrap();
    symlink(&managed, tree.etc("sudo")).unwrap();
    for action in ["enable", "disable"] {
        let (result, _) = tree.pam(&[action, "sudo"]);
        assert!(result.unwrap_err().contains("is a symlink"));
    }
    assert_eq!(fs::read_to_string(&managed).unwrap(), DEBIAN_SUDO);
    assert!(fs::symlink_metadata(tree.etc("sudo"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(!tree.etc("sudo.openhello.bak").exists());
}

// @covers:AC-027-pam-enable
#[test]
fn shared_stacks_are_refused() {
    let tree = Tree::new();
    for stack in [
        "common-auth",
        "system-auth",
        "password-auth",
        "common-account",
        "common-session",
        "common-password",
        "system-login",
        "postlogin",
    ] {
        tree.put(stack, SUSE_SUDO);
        let (result, _) = tree.pam(&["enable", stack]);
        assert!(result.unwrap_err().contains("shared stack"), "{stack}");
        assert_eq!(tree.read(stack), SUSE_SUDO);
    }
}

// @covers:AC-027-pam-enable
#[test]
fn invalid_service_names_are_refused() {
    let tree = Tree::new();
    tree.put("sudo", SUSE_SUDO);
    for bad in ["../sudo", "a/b", "Sudo", "sudo x", ".hidden", "sudo;rm"] {
        let (result, _) = tree.pam(&["enable", bad]);
        assert!(
            result.unwrap_err().contains("not a valid service name"),
            "{bad}"
        );
    }
    assert_eq!(names(&tree.dir.path().join("etc/pam.d")), ["sudo"]);
}

// @covers:AC-027-pam-enable
#[test]
fn disable_removes_only_our_line_and_keeps_the_rest_byte_for_byte() {
    for original in [DEBIAN_SUDO, SUSE_SUDO, FEDORA_SUDO] {
        let tree = Tree::new();
        tree.put("sudo", original);
        tree.pam(&["enable", "sudo"]).0.unwrap();
        tree.pam(&["disable", "sudo"]).0.unwrap();
        assert_eq!(tree.read("sudo"), original);
        let (result, out) = tree.pam(&["disable", "sudo"]);
        result.unwrap();
        assert!(out.contains("not enabled"));
        assert_eq!(tree.read("sudo"), original);
    }
}

// @covers:AC-027-pam-enable
#[test]
fn disable_keeps_a_file_without_trailing_newline_and_unrelated_lines() {
    let tree = Tree::new();
    let original = "auth required pam_unix.so\n# auth sufficient pam_openhello.so note\nauth optional pam_openhello_other.so\naccount required pam_permit.so";
    tree.put("login", original);
    tree.pam(&["enable", "login"]).0.unwrap();
    tree.pam(&["disable", "login"]).0.unwrap();
    assert_eq!(tree.read("login"), original);
}

// @covers:AC-027-pam-enable
#[test]
fn file_mode_survives_the_rewrite() {
    let tree = Tree::new();
    tree.put("sudo", DEBIAN_SUDO);
    fs::set_permissions(tree.etc("sudo"), fs::Permissions::from_mode(0o640)).unwrap();
    tree.pam(&["enable", "sudo"]).0.unwrap();
    assert_eq!(
        fs::metadata(tree.etc("sudo")).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        fs::metadata(tree.etc("sudo.openhello.bak"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert!(names(&tree.dir.path().join("etc/pam.d"))
        .iter()
        .all(|n| !n.ends_with(".tmp")));
}

// @covers:AC-027-pam-enable
#[test]
fn status_lists_every_service() {
    let tree = Tree::new();
    tree.put("sudo", DEBIAN_SUDO);
    tree.put("login", SUSE_SUDO);
    tree.put("kde", FEDORA_SUDO);
    symlink(tree.etc("kde"), tree.etc("other")).unwrap();
    tree.pam(&["enable", "sudo"]).0.unwrap();
    let (result, out) = tree.pam(&["status"]);
    result.unwrap();
    assert!(out.contains("sudo: enabled (per-service line)\n"));
    assert!(out.contains("login: disabled\n"));
    assert!(out.contains("kde: disabled\n"));
    assert!(out.contains("other: symlink"));
}

// @covers:AC-027-pam-enable
#[test]
fn enable_migrates_the_earlier_installer_and_says_what_it_removed() {
    let tree = Tree::new();
    let old_sudo = DEBIAN_SUDO.replacen(
        "@include common-auth",
        "auth include sudo-openhello\n@include common-auth",
        1,
    );
    tree.put("sudo", &old_sudo);
    tree.put("sudo.openhello.bak", DEBIAN_SUDO);
    tree.put("sudo-openhello", OLD_STACK);
    tree.put("openhello-lockscreen", OLD_STACK);
    tree.put(
        "kde-face",
        "#%PAM-1.0\nauth include openhello-lockscreen\naccount include common-account\n",
    );
    tree.put(
        "kde",
        "auth include openhello-lockscreen\nauth required pam_unix.so\n",
    );
    let (result, out) = tree.pam(&["enable", "sudo"]);
    result.unwrap();
    assert_eq!(
        tree.read("sudo"),
        with_line(DEBIAN_SUDO, "@include common-auth")
    );
    assert_eq!(tree.read("kde"), "auth required pam_unix.so\n");
    assert_eq!(
        names(&tree.dir.path().join("etc/pam.d")),
        ["kde", "kde.openhello.bak", "sudo", "sudo.openhello.bak"]
    );
    assert_eq!(tree.read("sudo.openhello.bak"), DEBIAN_SUDO);
    assert_eq!(
        tree.read("kde.openhello.bak"),
        "auth include openhello-lockscreen\nauth required pam_unix.so\n"
    );
    for removed in ["sudo-openhello", "openhello-lockscreen", "kde-face"] {
        assert!(out.contains(removed), "{removed}: {out}");
    }
}

// @covers:AC-027-pam-enable
#[test]
fn migrate_alone_keeps_third_party_files_with_our_old_names() {
    let tree = Tree::new();
    let foreign = "#%PAM-1.0\nauth required pam_faillock.so\n";
    tree.put("kde-face", foreign);
    tree.put("sudo-openhello", OLD_STACK);
    let (result, out) = tree.pam(&["migrate"]);
    result.unwrap();
    assert_eq!(tree.read("kde-face"), foreign);
    assert!(!tree.etc("sudo-openhello").exists());
    assert!(out.contains("kept"));
    let (_, again) = tree.pam(&["migrate"]);
    assert!(!again.contains("removed"));
}

// @covers:AC-027-pam-enable
#[test]
fn unwritable_directory_fails_without_corrupting_the_service() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let tree = Tree::new();
    tree.put("sudo", DEBIAN_SUDO);
    let dir = tree.dir.path().join("etc/pam.d");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
    let (result, _) = tree.pam(&["enable", "sudo"]);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(result.unwrap_err().contains("cannot write"));
    assert_eq!(tree.read("sudo"), DEBIAN_SUDO);
    assert_eq!(names(&dir), ["sudo"]);
}

// @covers:AC-027-pam-enable
#[test]
fn partial_failure_still_enables_the_other_services_and_exits_nonzero() {
    let tree = Tree::new();
    tree.put("sudo", SUSE_SUDO);
    let (result, out) = tree.pam(&["enable", "common-auth", "sudo"]);
    assert!(result.unwrap_err().contains("common-auth"));
    assert!(out.contains("sudo: enabled"));
    assert!(tree.read("sudo").contains(OUR_LINE));
}

// @covers:AC-027-pam-enable
#[test]
fn binary_exits_nonzero_for_a_symlink_and_zero_for_success() {
    let tree = Tree::new();
    tree.put("sudo", SUSE_SUDO);
    let root = tree.dir.path().to_str().unwrap();
    let bin = env!("CARGO_BIN_EXE_openhello-cli");
    let ok = Command::new(bin)
        .args(["pam", "enable", "sudo", "--root", root])
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    symlink(tree.etc("sudo"), tree.etc("linked")).unwrap();
    let refused = Command::new(bin)
        .args(["pam", "enable", "linked", "--root", root])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("symlink"));
}

// @covers:AC-027-pam-enable
#[test]
fn usage_errors_exit_with_code_two() {
    let tree = Tree::new();
    let root = tree.dir.path().to_str().unwrap();
    let bin = env!("CARGO_BIN_EXE_openhello-cli");
    let output = Command::new(bin)
        .args(["pam", "bogus", "--root", root])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

const DEBIAN_COMMON_AUTH: &str = "#\n# /etc/pam.d/common-auth - authentication settings common to all services\n#\n\n# here are the per-package modules (the \"Primary\" block)\nauth\t[success=2 default=ignore]\tpam_unix.so nullok\nauth\t[success=1 default=ignore]\tpam_sss.so use_first_pass\n# here's the fallback if no module succeeds\nauth\trequisite\t\t\tpam_deny.so\nauth\trequired\t\t\tpam_permit.so\n";
const SYSTEM_AUTH: &str = "auth      required  pam_faillock.so preauth\nauth      [success=1 default=bad] pam_unix.so try_first_pass nullok\nauth      required  pam_deny.so\n";
const COMMON_LINE: &str = "auth sufficient pam_openhello.so allowlist=/etc/openhello/pam-services";
const SERVICES: [&str; 14] = [
    "sudo",
    "polkit-1",
    "kde",
    "gdm-password",
    "sddm",
    "lightdm",
    "swaylock",
    "hyprlock",
    "i3lock",
    "xscreensaver",
    "xsecurelock",
    "cinnamon-screensaver",
    "mate-screensaver",
    "xfce4-screensaver",
];

fn allowlist(tree: &Tree) -> PathBuf {
    tree.dir.path().join("etc/openhello/pam-services")
}

fn debian() -> Tree {
    let tree = Tree::new();
    tree.put("sudo", DEBIAN_SUDO);
    tree.put("common-auth", DEBIAN_COMMON_AUTH);
    tree
}

// @covers:AC-027-pam-common-stack
#[test]
fn enable_without_services_inserts_before_pam_unix_in_the_debian_common_auth() {
    let tree = debian();
    tree.pam(&["enable"]).0.unwrap();
    let after = tree.read("common-auth");
    let ours = after.find(COMMON_LINE).unwrap();
    assert!(
        ours < after
            .find("auth\t[success=2 default=ignore]\tpam_unix.so nullok")
            .unwrap()
    );
    assert!(ours > after.find("# here are the per-package modules").unwrap());
    assert_eq!(
        after.replacen(&format!("{COMMON_LINE}\n"), "", 1),
        DEBIAN_COMMON_AUTH
    );
    assert_eq!(tree.read("sudo"), DEBIAN_SUDO);
}

// @covers:AC-027-pam-common-stack
#[test]
fn enable_without_services_handles_the_auth_include_layouts() {
    for (sudo, stack) in [(SUSE_SUDO, SYSTEM_AUTH), (FEDORA_SUDO, SYSTEM_AUTH)] {
        let tree = Tree::new();
        tree.put("sudo", sudo);
        fs::write(tree.vendor("system-auth"), stack).unwrap();
        tree.pam(&["enable", "--arg", "debug"]).0.unwrap();
        assert_eq!(
            tree.read("system-auth"),
            format!("{COMMON_LINE} debug\n{stack}")
        );
        assert_eq!(tree.read("sudo"), sudo);
        assert_eq!(
            fs::read_to_string(tree.vendor("system-auth")).unwrap(),
            stack
        );
    }
}

// @covers:AC-027-pam-common-stack
#[test]
fn managed_common_stack_symlink_is_refused_with_the_fallback() {
    let tree = Tree::new();
    tree.put("sudo", DEBIAN_SUDO);
    let managed = tree.dir.path().join("managed-common-auth");
    fs::write(&managed, DEBIAN_COMMON_AUTH).unwrap();
    symlink(&managed, tree.etc("common-auth")).unwrap();
    let (result, _) = tree.pam(&["enable"]);
    let message = result.unwrap_err();
    assert!(message.contains("is a symlink"));
    assert!(message.contains("openhello-cli pam enable <service>"));
    assert_eq!(fs::read_to_string(&managed).unwrap(), DEBIAN_COMMON_AUTH);
    assert!(!allowlist(&tree).exists());
    assert!(!tree.etc("common-auth.openhello.bak").exists());
}

// @covers:AC-027-pam-common-stack
#[test]
fn sudo_without_a_common_stack_include_is_reported_clearly() {
    let tree = Tree::new();
    tree.put(
        "sudo",
        "auth required pam_unix.so\naccount required pam_permit.so\n",
    );
    let (result, _) = tree.pam(&["enable"]);
    let message = result.unwrap_err();
    assert!(message.contains("sudo includes no common auth stack"));
    assert!(message.contains("pam enable"));
    assert!(!allowlist(&tree).exists());
}

// @covers:AC-027-pam-common-stack
#[test]
fn enable_without_services_is_idempotent_with_a_single_backup() {
    let tree = debian();
    tree.pam(&["enable"]).0.unwrap();
    let once = tree.read("common-auth");
    let (result, out) = tree.pam(&["enable"]);
    result.unwrap();
    assert_eq!(tree.read("common-auth"), once);
    assert_eq!(once.matches("pam_openhello.so").count(), 1);
    assert!(out.contains("already enabled"));
    assert_eq!(tree.read("common-auth.openhello.bak"), DEBIAN_COMMON_AUTH);
}

// @covers:AC-027-pam-common-stack
#[test]
fn enable_without_services_removes_the_per_service_lines_added_earlier() {
    let tree = debian();
    tree.put("kde", "auth required pam_unix.so\n");
    tree.pam(&["enable", "sudo", "kde"]).0.unwrap();
    assert!(tree.read("sudo").contains(OUR_LINE));
    let (result, out) = tree.pam(&["enable"]);
    result.unwrap();
    assert_eq!(tree.read("sudo"), DEBIAN_SUDO);
    assert_eq!(tree.read("kde"), "auth required pam_unix.so\n");
    assert!(out.contains("sudo: removed 1 per-service line"));
    let all: usize = ["sudo", "kde", "common-auth"]
        .iter()
        .map(|n| tree.read(n).matches("pam_openhello.so").count())
        .sum();
    assert_eq!(all, 1);
}

// @covers:AC-028-pam-common-stack
#[test]
fn disable_without_services_restores_every_touched_file_byte_for_byte() {
    let tree = debian();
    tree.put("kde", "auth required pam_unix.so\n");
    tree.pam(&["enable", "kde"]).0.unwrap();
    tree.pam(&["enable"]).0.unwrap();
    tree.pam(&["enable", "sudo"]).0.unwrap();
    let (result, out) = tree.pam(&["disable"]);
    result.unwrap();
    assert_eq!(tree.read("common-auth"), DEBIAN_COMMON_AUTH);
    assert_eq!(tree.read("sudo"), DEBIAN_SUDO);
    assert_eq!(tree.read("kde"), "auth required pam_unix.so\n");
    assert!(allowlist(&tree).exists());
    assert!(out.contains("left in place"));
}

// @covers:AC-028-pam-common-stack
#[test]
fn allowlist_is_created_with_the_fourteen_services_and_a_header() {
    let tree = debian();
    tree.pam(&["enable"]).0.unwrap();
    let text = fs::read_to_string(allowlist(&tree)).unwrap();
    let listed: Vec<&str> = text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(listed, SERVICES);
    let header: String = text.lines().filter(|l| l.starts_with('#')).collect();
    assert!(header.contains("sudo and kde"));
    assert!(header.contains("NOT verified"));
    for left_out in ["login", "su", "sshd", "cron"] {
        assert!(header.contains(left_out));
        assert!(!listed.contains(&left_out));
    }
    assert_eq!(
        fs::metadata(allowlist(&tree)).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

// @covers:AC-028-pam-common-stack
#[test]
fn an_edited_allowlist_is_never_overwritten() {
    let tree = debian();
    fs::create_dir_all(allowlist(&tree).parent().unwrap()).unwrap();
    fs::write(allowlist(&tree), "sudo\n").unwrap();
    tree.pam(&["enable"]).0.unwrap();
    assert_eq!(fs::read_to_string(allowlist(&tree)).unwrap(), "sudo\n");
}

// @covers:AC-028-pam-common-stack
#[test]
fn status_reports_the_common_stack_allowlist_and_per_service_lines() {
    let tree = debian();
    let (_, before) = tree.pam(&["status"]);
    assert!(before.contains("common stack: common-auth, line absent"));
    assert!(before.contains("allowlist /etc/openhello/pam-services: missing"));
    tree.pam(&["enable"]).0.unwrap();
    tree.put("kde", "auth required pam_unix.so\n");
    tree.pam(&["enable", "kde"]).0.unwrap();
    let (result, out) = tree.pam(&["status"]);
    result.unwrap();
    assert!(out.contains("common stack: common-auth, line present"));
    assert!(out.contains(&format!(
        "allowlist /etc/openhello/pam-services: {}",
        SERVICES.join(", ")
    )));
    assert!(out.contains("kde: enabled (per-service line)"));
}
