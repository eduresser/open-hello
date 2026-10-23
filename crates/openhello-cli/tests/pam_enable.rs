use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use openhello_cli::pam_enable::run;

const INCLUDE_DIRECTIVE_SUDO: &str = "#%PAM-1.0\n\nsession    required   pam_env.so readenv=1 user_readenv=0\nsession    required   pam_limits.so\n\n@include base-auth\n@include base-account\n@include base-session\n";
const AUTH_INCLUDE_SUDO: &str = "#%PAM-1.0\nauth      include       alt-auth\naccount   include       alt-auth\nsession   include       alt-auth\n";
const AUTH_INCLUDE_FULL_SUDO: &str = "#%PAM-1.0\nauth       include      alt-auth\naccount    include      alt-auth\npassword   include      alt-auth\nsession    include      alt-auth\n";
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
fn enable_on_an_include_directive_goes_before_the_include() {
    let tree = Tree::new();
    tree.put("sudo", INCLUDE_DIRECTIVE_SUDO);
    let (result, _) = tree.pam(&["enable", "sudo"]);
    result.unwrap();
    let after = tree.read("sudo");
    assert_eq!(
        after,
        with_line(INCLUDE_DIRECTIVE_SUDO, "@include base-auth")
    );
    let ours = after.find(OUR_LINE).unwrap();
    assert!(ours < after.find("@include base-auth").unwrap());
    assert!(ours > after.find("session    required   pam_limits.so").unwrap());
}

// @covers:AC-027-pam-enable
#[test]
fn enable_on_auth_include_stacks_goes_before_first_auth() {
    for original in [AUTH_INCLUDE_SUDO, AUTH_INCLUDE_FULL_SUDO] {
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
    tree.put("sudo", AUTH_INCLUDE_SUDO);
    tree.pam(&[
        "enable",
        "sudo",
        "--arg",
        "authdir=/etc/openhello/auth",
        "--arg",
        "trusted_uid=0",
    ])
    .0
    .unwrap();
    assert!(tree.read("sudo").starts_with("#%PAM-1.0\nauth sufficient pam_openhello.so authdir=/etc/openhello/auth trusted_uid=0\nauth      include"));
}

// @covers:AC-027-pam-enable
#[test]
fn enable_accepts_a_bare_flag_such_as_debug() {
    let tree = Tree::new();
    tree.put("sudo", AUTH_INCLUDE_SUDO);
    tree.pam(&["enable", "sudo", "--arg", "debug"]).0.unwrap();
    assert!(tree
        .read("sudo")
        .starts_with("#%PAM-1.0\nauth sufficient pam_openhello.so debug\n"));
    for rejected in ["bad arg", "=x", "a;b", ""] {
        let other = Tree::new();
        other.put("sudo", AUTH_INCLUDE_SUDO);
        assert!(
            other.pam(&["enable", "sudo", "--arg", rejected]).0.is_err(),
            "{rejected:?}"
        );
        assert_eq!(other.read("sudo"), AUTH_INCLUDE_SUDO, "{rejected:?}");
    }
}

// @covers:AC-027-pam-enable
#[test]
fn enable_copies_the_vendor_file_first() {
    let tree = Tree::new();
    fs::write(tree.vendor("sudo"), INCLUDE_DIRECTIVE_SUDO).unwrap();
    fs::set_permissions(tree.vendor("sudo"), fs::Permissions::from_mode(0o640)).unwrap();
    tree.pam(&["enable", "sudo"]).0.unwrap();
    assert_eq!(
        tree.read("sudo"),
        with_line(INCLUDE_DIRECTIVE_SUDO, "@include base-auth")
    );
    assert_eq!(
        fs::metadata(tree.etc("sudo")).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        fs::read_to_string(tree.vendor("sudo")).unwrap(),
        INCLUDE_DIRECTIVE_SUDO
    );
}

// @covers:AC-027-pam-enable
#[test]
fn enable_fails_clearly_when_the_service_exists_nowhere() {
    let tree = Tree::new();
    let (result, _) = tree.pam(&["enable", "no-such-service"]);
    assert!(result
        .unwrap_err()
        .contains("no PAM service file for `no-such-service`"));
}

// @covers:AC-027-pam-enable
#[test]
fn backup_is_written_once_with_the_original_content() {
    let tree = Tree::new();
    tree.put("sudo", INCLUDE_DIRECTIVE_SUDO);
    tree.pam(&["enable", "sudo"]).0.unwrap();
    tree.pam(&["disable", "sudo"]).0.unwrap();
    tree.put("sudo", AUTH_INCLUDE_SUDO);
    tree.pam(&["enable", "sudo"]).0.unwrap();
    assert_eq!(tree.read("sudo.openhello.bak"), INCLUDE_DIRECTIVE_SUDO);
}

// @covers:AC-027-pam-enable
#[test]
fn enable_is_idempotent() {
    let tree = Tree::new();
    tree.put("sudo", INCLUDE_DIRECTIVE_SUDO);
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
    fs::write(&managed, INCLUDE_DIRECTIVE_SUDO).unwrap();
    symlink(&managed, tree.etc("sudo")).unwrap();
    for action in ["enable", "disable"] {
        let (result, _) = tree.pam(&[action, "sudo"]);
        assert!(result.unwrap_err().contains("is a symlink"));
    }
    assert_eq!(
        fs::read_to_string(&managed).unwrap(),
        INCLUDE_DIRECTIVE_SUDO
    );
    assert!(fs::symlink_metadata(tree.etc("sudo"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(!tree.etc("sudo.openhello.bak").exists());
}

// @covers:AC-027-pam-enable
#[test]
fn a_file_included_by_another_service_is_refused_as_a_shared_stack() {
    for (name, include) in [
        ("base-auth", "@include base-auth\n"),
        ("alt-auth", "auth include alt-auth\n"),
        ("third-auth", "auth substack third-auth\n"),
        ("base-account", "account include base-account\n"),
        ("base-session", "session substack base-session\n"),
        ("base-password", "password include base-password\n"),
    ] {
        let tree = Tree::new();
        tree.put("sudo", &format!("#%PAM-1.0\n{include}"));
        tree.put(name, ALT_STACK);
        let (result, _) = tree.pam(&["enable", name]);
        assert!(result.unwrap_err().contains("shared stack"), "{name}");
        assert_eq!(tree.read(name), ALT_STACK);
    }
}

// @covers:AC-027-pam-enable
#[test]
fn invalid_service_names_are_refused() {
    let tree = Tree::new();
    tree.put("sudo", AUTH_INCLUDE_SUDO);
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
    for original in [
        INCLUDE_DIRECTIVE_SUDO,
        AUTH_INCLUDE_SUDO,
        AUTH_INCLUDE_FULL_SUDO,
    ] {
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
    tree.put("sudo", INCLUDE_DIRECTIVE_SUDO);
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
    tree.put("sudo", INCLUDE_DIRECTIVE_SUDO);
    tree.put("login", AUTH_INCLUDE_SUDO);
    tree.put("polkit-1", AUTH_INCLUDE_FULL_SUDO);
    symlink(tree.etc("polkit-1"), tree.etc("other")).unwrap();
    tree.pam(&["enable", "sudo"]).0.unwrap();
    let (result, out) = tree.pam(&["status"]);
    result.unwrap();
    assert!(out.contains("sudo: enabled (per-service line)\n"));
    assert!(out.contains("login: disabled\n"));
    assert!(out.contains("polkit-1: disabled\n"));
    assert!(out.contains("other: symlink"));
}

// @covers:AC-027-pam-enable
#[test]
fn enable_migrates_the_earlier_installer_and_says_what_it_removed() {
    let tree = Tree::new();
    let old_sudo = INCLUDE_DIRECTIVE_SUDO.replacen(
        "@include base-auth",
        "auth include sudo-openhello\n@include base-auth",
        1,
    );
    tree.put("sudo", &old_sudo);
    tree.put("sudo.openhello.bak", INCLUDE_DIRECTIVE_SUDO);
    tree.put("sudo-openhello", OLD_STACK);
    tree.put("openhello-lockscreen", OLD_STACK);
    tree.put(
        "polkit-1",
        "auth include openhello-lockscreen\nauth required pam_unix.so\n",
    );
    let (result, out) = tree.pam(&["enable", "sudo"]);
    result.unwrap();
    assert_eq!(
        tree.read("sudo"),
        with_line(INCLUDE_DIRECTIVE_SUDO, "@include base-auth")
    );
    assert_eq!(tree.read("polkit-1"), "auth required pam_unix.so\n");
    assert_eq!(
        names(&tree.dir.path().join("etc/pam.d")),
        [
            "polkit-1",
            "polkit-1.openhello.bak",
            "sudo",
            "sudo.openhello.bak"
        ]
    );
    assert_eq!(tree.read("sudo.openhello.bak"), INCLUDE_DIRECTIVE_SUDO);
    assert_eq!(
        tree.read("polkit-1.openhello.bak"),
        "auth include openhello-lockscreen\nauth required pam_unix.so\n"
    );
    for removed in ["sudo-openhello", "openhello-lockscreen"] {
        assert!(out.contains(removed), "{removed}: {out}");
    }
}

// @covers:AC-027-pam-enable
#[test]
fn migrate_alone_keeps_third_party_files_with_our_old_names() {
    let tree = Tree::new();
    let foreign = "#%PAM-1.0\nauth required pam_faillock.so\n";
    tree.put("openhello-lockscreen", foreign);
    tree.put("sudo-openhello", OLD_STACK);
    let (result, out) = tree.pam(&["migrate"]);
    result.unwrap();
    assert_eq!(tree.read("openhello-lockscreen"), foreign);
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
    tree.put("sudo", INCLUDE_DIRECTIVE_SUDO);
    let dir = tree.dir.path().join("etc/pam.d");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
    let (result, _) = tree.pam(&["enable", "sudo"]);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(result.unwrap_err().contains("cannot write"));
    assert_eq!(tree.read("sudo"), INCLUDE_DIRECTIVE_SUDO);
    assert_eq!(names(&dir), ["sudo"]);
}

// @covers:AC-027-pam-enable
#[test]
fn partial_failure_still_enables_the_other_services_and_exits_nonzero() {
    let tree = Tree::new();
    tree.put("sudo", AUTH_INCLUDE_SUDO);
    tree.put("alt-auth", ALT_STACK);
    let (result, out) = tree.pam(&["enable", "alt-auth", "sudo"]);
    assert!(result.unwrap_err().contains("alt-auth"));
    assert!(out.contains("sudo: enabled"));
    assert!(tree.read("sudo").contains(OUR_LINE));
}

// @covers:AC-027-pam-enable
#[test]
fn binary_exits_nonzero_for_a_symlink_and_zero_for_success() {
    let tree = Tree::new();
    tree.put("sudo", AUTH_INCLUDE_SUDO);
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

const BASE_STACK: &str = "#\n# /etc/pam.d/base-auth - authentication settings common to all services\n#\n\n# here are the per-package modules (the \"Primary\" block)\nauth\t[success=2 default=ignore]\tpam_unix.so nullok\nauth\t[success=1 default=ignore]\tpam_sss.so use_first_pass\n# here's the fallback if no module succeeds\nauth\trequisite\t\t\tpam_deny.so\nauth\trequired\t\t\tpam_permit.so\n";
const ALT_STACK: &str = "auth      required  pam_faillock.so preauth\nauth      [success=1 default=bad] pam_unix.so try_first_pass nullok\nauth      required  pam_deny.so\n";
const COMMON_LINE: &str = "auth sufficient pam_openhello.so";
const RETIRED_COMMON_LINE: &str =
    "auth sufficient pam_openhello.so allowlist=/etc/openhello/pam-services";
const RETIRED_SERVICES_FILE: &str = "# Services where pam_openhello may use the camera; read through allowlist=/etc/openhello/pam-services.\nsudo\npolkit-1\n";

fn retired_services(tree: &Tree) -> PathBuf {
    tree.dir.path().join("etc/openhello/pam-services")
}

fn written_files(tree: &Tree) -> Vec<String> {
    let mut found = names(&tree.dir.path().join("etc/pam.d"));
    found.retain(|n| !n.ends_with(".openhello.bak"));
    found
}

fn base_tree() -> Tree {
    let tree = Tree::new();
    tree.put("sudo", INCLUDE_DIRECTIVE_SUDO);
    tree.put("base-auth", BASE_STACK);
    tree
}

// @covers:AC-027-pam-common-stack
#[test]
fn enable_without_services_inserts_before_pam_unix_in_the_base_stack() {
    let tree = base_tree();
    tree.pam(&["enable"]).0.unwrap();
    let after = tree.read("base-auth");
    let ours = after.find(COMMON_LINE).unwrap();
    assert!(
        ours < after
            .find("auth\t[success=2 default=ignore]\tpam_unix.so nullok")
            .unwrap()
    );
    assert!(ours > after.find("# here are the per-package modules").unwrap());
    assert_eq!(
        after.replacen(&format!("{COMMON_LINE}\n"), "", 1),
        BASE_STACK
    );
    assert_eq!(tree.read("sudo"), INCLUDE_DIRECTIVE_SUDO);
}

// @covers:AC-027-pam-common-stack
#[test]
fn enable_without_services_handles_the_auth_include_layouts() {
    for (sudo, stack) in [
        (AUTH_INCLUDE_SUDO, ALT_STACK),
        (AUTH_INCLUDE_FULL_SUDO, ALT_STACK),
    ] {
        let tree = Tree::new();
        tree.put("sudo", sudo);
        fs::write(tree.vendor("alt-auth"), stack).unwrap();
        tree.pam(&["enable", "--arg", "debug"]).0.unwrap();
        assert_eq!(
            tree.read("alt-auth"),
            format!("{COMMON_LINE} debug\n{stack}")
        );
        assert_eq!(tree.read("sudo"), sudo);
        assert_eq!(fs::read_to_string(tree.vendor("alt-auth")).unwrap(), stack);
    }
}

// @covers:AC-027-pam-common-stack
#[test]
fn managed_common_stack_symlink_is_refused_with_the_fallback() {
    let tree = Tree::new();
    tree.put("sudo", INCLUDE_DIRECTIVE_SUDO);
    let managed = tree.dir.path().join("managed-base-auth");
    fs::write(&managed, BASE_STACK).unwrap();
    symlink(&managed, tree.etc("base-auth")).unwrap();
    let (result, _) = tree.pam(&["enable"]);
    let message = result.unwrap_err();
    assert!(message.contains("is a symlink"));
    assert!(message.contains("openhello-cli pam enable <service>"));
    assert_eq!(fs::read_to_string(&managed).unwrap(), BASE_STACK);
    assert!(!retired_services(&tree).exists());
    assert!(!tree.etc("base-auth.openhello.bak").exists());
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
    assert!(!retired_services(&tree).exists());
}

// @covers:AC-027-pam-common-stack
#[test]
fn enable_without_services_is_idempotent_with_a_single_backup() {
    let tree = base_tree();
    tree.pam(&["enable"]).0.unwrap();
    let once = tree.read("base-auth");
    let (result, out) = tree.pam(&["enable"]);
    result.unwrap();
    assert_eq!(tree.read("base-auth"), once);
    assert_eq!(once.matches("pam_openhello.so").count(), 1);
    assert!(out.contains("already enabled"));
    assert_eq!(tree.read("base-auth.openhello.bak"), BASE_STACK);
}

// @covers:AC-027-pam-common-stack
#[test]
fn enable_without_services_removes_the_per_service_lines_added_earlier() {
    let tree = base_tree();
    tree.put("polkit-1", "auth required pam_unix.so\n");
    tree.pam(&["enable", "sudo", "polkit-1"]).0.unwrap();
    assert!(tree.read("sudo").contains(OUR_LINE));
    let (result, out) = tree.pam(&["enable"]);
    result.unwrap();
    assert_eq!(tree.read("sudo"), INCLUDE_DIRECTIVE_SUDO);
    assert_eq!(tree.read("polkit-1"), "auth required pam_unix.so\n");
    assert!(out.contains("sudo: removed 1 per-service line"));
    let all: usize = ["sudo", "polkit-1", "base-auth"]
        .iter()
        .map(|n| tree.read(n).matches("pam_openhello.so").count())
        .sum();
    assert_eq!(all, 1);
}

// @covers:AC-028-pam-common-stack
#[test]
fn disable_without_services_restores_every_touched_file_byte_for_byte() {
    let tree = base_tree();
    tree.put("polkit-1", "auth required pam_unix.so\n");
    tree.pam(&["enable", "polkit-1"]).0.unwrap();
    tree.pam(&["enable"]).0.unwrap();
    tree.pam(&["enable", "sudo"]).0.unwrap();
    let (result, _) = tree.pam(&["disable"]);
    result.unwrap();
    assert_eq!(tree.read("base-auth"), BASE_STACK);
    assert_eq!(tree.read("sudo"), INCLUDE_DIRECTIVE_SUDO);
    assert_eq!(tree.read("polkit-1"), "auth required pam_unix.so\n");
    assert!(!retired_services(&tree).exists());
    let (_, again) = tree.pam(&["disable"]);
    assert!(again.contains("not enabled anywhere"));
}

// @covers:AC-028-pam-common-stack
#[test]
fn enable_writes_no_data_file_and_leaves_only_the_common_stack_line() {
    let tree = base_tree();
    tree.pam(&["enable"]).0.unwrap();
    assert!(!retired_services(&tree).exists());
    assert!(!tree.dir.path().join("etc/openhello").exists());
    assert_eq!(written_files(&tree), ["base-auth", "sudo"]);
    assert!(!tree.read("base-auth").contains("allowlist"));
}

// @covers:AC-028-pam-common-stack
#[test]
fn a_common_stack_line_with_the_retired_allowlist_argument_is_rewritten_once() {
    let tree = base_tree();
    tree.put("base-auth", &with_retired_line(BASE_STACK, " debug"));
    let (result, out) = tree.pam(&["enable"]);
    result.unwrap();
    assert_eq!(
        tree.read("base-auth"),
        BASE_STACK.replacen(
            "auth\t[success=2",
            &format!("{COMMON_LINE} debug\nauth\t[success=2"),
            1
        )
    );
    assert!(out.contains("migrated"));
    assert_eq!(
        tree.read("base-auth.openhello.bak"),
        with_retired_line(BASE_STACK, " debug")
    );
    let once = tree.read("base-auth");
    let (_, again) = tree.pam(&["enable"]);
    assert_eq!(tree.read("base-auth"), once);
    assert!(!again.contains("migrated"));
    assert_eq!(once.matches("pam_openhello.so").count(), 1);
    tree.pam(&["disable"]).0.unwrap();
    assert_eq!(tree.read("base-auth"), BASE_STACK,);
}

fn with_retired_line(content: &str, extra: &str) -> String {
    content.replacen(
        "auth\t[success=2",
        &format!("{RETIRED_COMMON_LINE}{extra}\nauth\t[success=2"),
        1,
    )
}

// @covers:AC-028-pam-common-stack
#[test]
fn the_retired_services_file_is_deleted_only_when_it_carries_the_tools_header() {
    let tree = base_tree();
    fs::create_dir_all(retired_services(&tree).parent().unwrap()).unwrap();
    fs::write(retired_services(&tree), RETIRED_SERVICES_FILE).unwrap();
    let (result, out) = tree.pam(&["enable"]);
    result.unwrap();
    assert!(!retired_services(&tree).exists());
    assert!(out.contains("removed retired"));

    let edited = base_tree();
    fs::create_dir_all(retired_services(&edited).parent().unwrap()).unwrap();
    fs::write(retired_services(&edited), "sudo\n").unwrap();
    edited.pam(&["enable"]).0.unwrap();
    assert_eq!(
        fs::read_to_string(retired_services(&edited)).unwrap(),
        "sudo\n"
    );
}

// @covers:AC-028-pam-common-stack
#[test]
fn status_reports_the_common_stack_and_per_service_lines() {
    let tree = base_tree();
    let (_, before) = tree.pam(&["status"]);
    assert!(before.contains("common stack: base-auth, line absent"));
    assert!(!before.contains("allowlist"));
    tree.pam(&["enable"]).0.unwrap();
    tree.put("polkit-1", "auth required pam_unix.so\n");
    tree.pam(&["enable", "polkit-1"]).0.unwrap();
    let (result, out) = tree.pam(&["status"]);
    result.unwrap();
    assert!(out.contains("common stack: base-auth, line present"));
    assert!(out.contains("polkit-1: enabled (per-service line)"));
}

const FPRINTD_LINE: &str =
    "auth sufficient pam_fprintd.so max-tries=3 timeout=10 # added by open-hello";
const SYSTEM_FPRINTD: &str = "auth      sufficient  pam_fprintd.so\n";

fn with_fprintd_module(tree: &Tree) {
    let dir = openhello_cli::pam_enable::security_dir().expect(
        "libpam.so.0 not found in the loader cache; install the PAM runtime to run the PAM tests",
    );
    let target = tree.dir.path().join(dir.strip_prefix("/").unwrap_or(&dir));
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("pam_fprintd.so"), b"").unwrap();
}

fn fingerprint_lines(text: &str) -> usize {
    text.lines()
        .filter(|l| l.contains("pam_fprintd.so"))
        .count()
}

fn fingerprint_stacks() -> Vec<Tree> {
    let base = base_tree();
    let alt = Tree::new();
    alt.put("sudo", AUTH_INCLUDE_SUDO);
    fs::write(alt.vendor("alt-auth"), ALT_STACK).unwrap();
    vec![base, alt]
}

fn stack_name(tree: &Tree) -> &'static str {
    if tree.etc("base-auth").exists() {
        "base-auth"
    } else {
        "alt-auth"
    }
}

// @spec:AC-061
#[test]
fn enable_adds_the_fingerprint_line_right_after_ours_in_both_stack_styles() {
    for tree in fingerprint_stacks() {
        with_fprintd_module(&tree);
        let (result, out) = tree.pam(&["enable"]);
        result.unwrap();
        let after = tree.read(stack_name(&tree));
        let expected = format!("{COMMON_LINE}\n{FPRINTD_LINE}\n");
        assert!(after.contains(&expected), "{after}");
        assert_eq!(fingerprint_lines(&after), 1);
        assert!(out.contains("fingerprint login switched on"), "{out}");
    }
}

// @spec:AC-061
#[test]
fn enable_twice_adds_nothing_and_keeps_one_backup() {
    for tree in fingerprint_stacks() {
        with_fprintd_module(&tree);
        let name = stack_name(&tree);
        tree.pam(&["enable"]).0.unwrap();
        let once = tree.read(name);
        let (result, out) = tree.pam(&["enable"]);
        result.unwrap();
        assert_eq!(tree.read(name), once);
        assert_eq!(fingerprint_lines(&once), 1);
        assert!(
            out.contains("fingerprint login already switched on"),
            "{out}"
        );
        let original = if name == "base-auth" {
            BASE_STACK
        } else {
            ALT_STACK
        };
        let backup = tree.read(&format!("{name}.openhello.bak"));
        assert_eq!(backup, original);
    }
}

// @spec:AC-061
#[test]
fn enable_adds_the_fingerprint_line_when_our_line_was_already_there() {
    let tree = base_tree();
    tree.pam(&["enable"]).0.unwrap();
    with_fprintd_module(&tree);
    tree.pam(&["enable"]).0.unwrap();
    let after = tree.read("base-auth");
    assert!(after.contains(&format!("{COMMON_LINE}\n{FPRINTD_LINE}\n")));
    assert_eq!(after.matches(COMMON_LINE).count(), 1);
}

// @spec:AC-061
#[test]
fn the_backup_keeps_the_stack_as_it_was_before_the_fingerprint_line() {
    let tree = base_tree();
    with_fprintd_module(&tree);
    tree.pam(&["enable"]).0.unwrap();
    assert_eq!(tree.read("base-auth.openhello.bak"), BASE_STACK);
}

// @spec:AC-074
#[test]
fn no_fingerprint_flag_writes_no_line_and_says_why() {
    let tree = base_tree();
    with_fprintd_module(&tree);
    let (result, out) = tree.pam(&["enable", "--no-fingerprint"]);
    result.unwrap();
    let after = tree.read("base-auth");
    assert_eq!(fingerprint_lines(&after), 0);
    assert_eq!(
        after.replacen(&format!("{COMMON_LINE}\n"), "", 1),
        BASE_STACK
    );
    assert!(
        out.contains("not switched on: --no-fingerprint was given"),
        "{out}"
    );
}

// @spec:AC-074
#[test]
fn a_machine_without_the_module_gets_no_line_and_a_reason() {
    let tree = base_tree();
    let (result, out) = tree.pam(&["enable"]);
    result.unwrap();
    let after = tree.read("base-auth");
    assert_eq!(fingerprint_lines(&after), 0);
    assert!(after.contains(COMMON_LINE));
    assert!(
        out.contains("not switched on: pam_fprintd.so is not installed"),
        "{out}"
    );
}

// @spec:AC-061
// @spec:AC-072
#[test]
fn an_existing_fingerprint_line_is_left_alone_directly_and_through_an_include() {
    let direct = base_tree();
    with_fprintd_module(&direct);
    direct.put("base-auth", &format!("{SYSTEM_FPRINTD}{BASE_STACK}"));
    let included = Tree::new();
    included.put("sudo", AUTH_INCLUDE_SUDO);
    with_fprintd_module(&included);
    included.put(
        "alt-auth",
        &format!("auth include fprintd-auth\n{ALT_STACK}"),
    );
    included.put("fprintd-auth", SYSTEM_FPRINTD);
    for (tree, name) in [(&direct, "base-auth"), (&included, "alt-auth")] {
        let (result, out) = tree.pam(&["enable"]);
        result.unwrap();
        assert_eq!(
            fingerprint_lines(&tree.read(name)),
            usize::from(name == "base-auth")
        );
        assert!(!tree.read(name).contains("# added by open-hello"));
        assert!(out.contains("the system already uses pam_fprintd"), "{out}");
        tree.pam(&["disable"]).0.unwrap();
        assert!(!tree.read(name).contains("pam_openhello"));
    }
    assert!(direct.read("base-auth").contains(SYSTEM_FPRINTD));
    assert_eq!(included.read("fprintd-auth"), SYSTEM_FPRINTD);
}

// @spec:AC-072
#[test]
fn disable_removes_only_the_line_open_hello_added() {
    let tree = base_tree();
    with_fprintd_module(&tree);
    tree.pam(&["enable"]).0.unwrap();
    tree.pam(&["disable"]).0.unwrap();
    assert_eq!(tree.read("base-auth"), BASE_STACK);

    let kept = base_tree();
    kept.put("base-auth", &format!("{SYSTEM_FPRINTD}{BASE_STACK}"));
    kept.pam(&["enable"]).0.unwrap();
    kept.pam(&["disable"]).0.unwrap();
    assert_eq!(
        kept.read("base-auth"),
        format!("{SYSTEM_FPRINTD}{BASE_STACK}")
    );
}

// @spec:AC-072
#[test]
fn status_reports_the_fingerprint_line_in_all_three_states() {
    let absent = base_tree();
    absent.pam(&["enable"]).0.unwrap();
    assert!(absent
        .pam(&["status"])
        .1
        .contains("fingerprint line (pam_fprintd): absent\n"));

    let added = base_tree();
    with_fprintd_module(&added);
    added.pam(&["enable"]).0.unwrap();
    assert!(added
        .pam(&["status"])
        .1
        .contains("fingerprint line (pam_fprintd): present, added by open-hello\n"));

    let system = base_tree();
    system.put("base-auth", &format!("{SYSTEM_FPRINTD}{BASE_STACK}"));
    assert!(system
        .pam(&["status"])
        .1
        .contains("fingerprint line (pam_fprintd): present, not added by open-hello\n"));
}

// @spec:AC-061
#[test]
fn per_service_enable_never_writes_the_fingerprint_line() {
    let tree = base_tree();
    with_fprintd_module(&tree);
    tree.pam(&["enable", "sudo"]).0.unwrap();
    assert_eq!(fingerprint_lines(&tree.read("sudo")), 0);
    assert_eq!(tree.read("base-auth"), BASE_STACK);
}

const ARBITRARY_STACK: &str = "base-auth";
const OTHER_SHARED: &str = "extra-auth";

fn arbitrary_tree(sudo: &str) -> Tree {
    let tree = Tree::new();
    tree.put("sudo", sudo);
    tree.put(ARBITRARY_STACK, BASE_STACK);
    tree
}

// @spec:AC-075
#[test]
fn plain_enable_edits_the_stack_sudo_includes_whatever_its_name() {
    for sudo in [
        "#%PAM-1.0\n@include base-auth\n",
        "#%PAM-1.0\nauth include base-auth\naccount include base-auth\n",
        "#%PAM-1.0\nauth substack base-auth\n",
    ] {
        let tree = arbitrary_tree(sudo);
        tree.put("other", "auth required pam_unix.so\n");
        tree.pam(&["enable", "--no-fingerprint"]).0.unwrap();
        assert_eq!(
            tree.read(ARBITRARY_STACK)
                .replacen(&format!("{COMMON_LINE}\n"), "", 1),
            BASE_STACK
        );
        assert_eq!(tree.read("sudo"), sudo);
        assert_eq!(tree.read("other"), "auth required pam_unix.so\n");
        assert_eq!(written_files(&tree), ["base-auth", "other", "sudo"]);
    }
}

// @spec:AC-075
#[test]
fn a_file_another_service_includes_is_refused_and_an_unincluded_one_is_accepted() {
    let tree = arbitrary_tree("#%PAM-1.0\n@include base-auth\n");
    tree.put(
        "login-like",
        &format!("#%PAM-1.0\nauth include {OTHER_SHARED}\n"),
    );
    tree.put(OTHER_SHARED, BASE_STACK);
    tree.put("standalone", "#%PAM-1.0\nauth required pam_unix.so\n");
    let (refused, _) = tree.pam(&["enable", OTHER_SHARED]);
    assert!(refused.unwrap_err().contains("another service includes it"));
    assert_eq!(tree.read(OTHER_SHARED), BASE_STACK);
    tree.pam(&["enable", "standalone"]).0.unwrap();
    assert!(tree.read("standalone").contains(COMMON_LINE));
}

// @spec:AC-075
#[test]
fn a_service_nobody_includes_is_accepted_even_when_named_like_a_well_known_stack() {
    let tree = Tree::new();
    tree.put("sudo", "#%PAM-1.0\n@include base-auth\n");
    tree.put(ARBITRARY_STACK, BASE_STACK);
    for name in ["system-auth", "common-auth", "password-auth", "postlogin"] {
        tree.put(name, "#%PAM-1.0\nauth required pam_unix.so\n");
        let (result, _) = tree.pam(&["enable", name]);
        result.unwrap();
        assert!(tree.read(name).contains(COMMON_LINE), "{name}");
    }
}

// @spec:AC-075
#[test]
fn a_vendor_file_included_by_an_etc_service_is_refused() {
    let tree = Tree::new();
    tree.put("sudo", "#%PAM-1.0\n@include base-auth\n");
    fs::write(
        tree.vendor("extra"),
        "#%PAM-1.0\nauth include vendor-stack\n",
    )
    .unwrap();
    fs::write(tree.vendor("vendor-stack"), BASE_STACK).unwrap();
    let (result, _) = tree.pam(&["enable", "vendor-stack"]);
    assert!(result.unwrap_err().contains("shared stack"));
    assert!(!tree.etc("vendor-stack").exists());
}

// @spec:AC-075
#[test]
fn disable_and_status_work_when_the_shared_file_has_an_arbitrary_name() {
    let tree = arbitrary_tree("#%PAM-1.0\n@include base-auth\n");
    tree.pam(&["enable", "--no-fingerprint"]).0.unwrap();
    let (_, status) = tree.pam(&["status"]);
    assert!(
        status.contains("common stack: base-auth, line present"),
        "{status}"
    );
    assert!(status.contains("base-auth: enabled"));
    let (_, out) = tree.pam(&["disable"]);
    assert!(out.contains("base-auth: disabled"), "{out}");
    assert_eq!(tree.read(ARBITRARY_STACK), BASE_STACK);
    let (_, status) = tree.pam(&["status"]);
    assert!(
        status.contains("common stack: base-auth, line absent"),
        "{status}"
    );
}
