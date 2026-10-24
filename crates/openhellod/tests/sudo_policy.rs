mod support {
    pub mod fake_sudo;
}

use std::fs;
use std::os::unix::fs::PermissionsExt;

use openhellod::sudo_policy::{policy_from_listing, SudoPolicy, SudoPolicyStore};
use support::fake_sudo::{my_uid, FakeSudo, Reads, Visudo, TUMBLEWEED_DEFAULTS};

fn listing(defaults: &str) -> String {
    format!("Matching Defaults entries for ana on host:\n{defaults}\n\nRunas and Command-specific defaults for ana:\n    Defaults>root targetpw\n\nUser ana may run the following commands on host:\n    (ALL) ALL\n")
}

#[test]
fn the_last_targetpw_rootpw_or_runaspw_entry_decides_whose_password_sudo_asks() {
    assert_eq!(policy_from_listing(&listing(TUMBLEWEED_DEFAULTS)), SudoPolicy::RootPassword);
    let ours = format!("{TUMBLEWEED_DEFAULTS}, !targetpw, !rootpw, !runaspw");
    assert_eq!(policy_from_listing(&listing(&ours)), SudoPolicy::OwnPassword);
    assert_eq!(policy_from_listing(&listing("    env_reset, mail_badpass, use_pty")), SudoPolicy::OwnPassword);
    assert_eq!(policy_from_listing(&listing("    env_reset, rootpw")), SudoPolicy::RootPassword);
    assert_eq!(policy_from_listing(&listing("    env_reset, runaspw, !targetpw")), SudoPolicy::RootPassword);
}

#[test]
fn entries_wrapped_over_lines_and_quoted_commas_are_read_correctly() {
    let wrapped = "    env_reset, env_keep=\"A, targetpw, B\",\n    !insults, targetpw";
    assert_eq!(policy_from_listing(&listing(wrapped)), SudoPolicy::RootPassword);
    let quoted_only = "    env_reset, env_keep=\"A, targetpw, B\"";
    assert_eq!(policy_from_listing(&listing(quoted_only)), SudoPolicy::OwnPassword);
}

#[test]
fn a_listing_without_defaults_is_unavailable() {
    assert_eq!(policy_from_listing(""), SudoPolicy::Unavailable);
    assert_eq!(policy_from_listing("sudo: unknown user ana\n"), SudoPolicy::Unavailable);
}

#[test]
fn detection_asks_sudo_about_the_uid_owner_without_a_password() {
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Accepts, Reads::DropIns);
    assert_eq!(fake.store().detect(my_uid()), SudoPolicy::RootPassword);
    let log = fs::read_to_string(fake.dir.path().join("sudo.log")).unwrap();
    let name = std::process::Command::new("id").arg("-un").output().unwrap().stdout;
    assert_eq!(log.trim(), format!("-n -l -U {}", String::from_utf8_lossy(&name).trim()));
}

#[test]
fn a_missing_sudo_or_an_unknown_uid_is_unavailable() {
    let missing = SudoPolicyStore::new("/nonexistent/sudoers.d", "/nonexistent/sudo", "/nonexistent/visudo");
    assert_eq!(missing.detect(my_uid()), SudoPolicy::Unavailable);
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Accepts, Reads::DropIns);
    assert_eq!(fake.store().detect(4_000_000_000), SudoPolicy::Unavailable);
}

#[test]
fn own_password_writes_one_validated_read_only_drop_in_scoped_to_the_uid() {
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Accepts, Reads::DropIns);
    assert_eq!(fake.store().use_own_password(my_uid()), Ok(SudoPolicy::OwnPassword));
    let path = fake.drop_in(my_uid());
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        format!("Defaults:#{} !targetpw, !rootpw, !runaspw\n", my_uid())
    );
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o440);
    assert_eq!(fake.entries(), [format!("openhello-uid{}", my_uid())]);
    assert_eq!(fake.store().detect(my_uid()), SudoPolicy::OwnPassword);
}

#[test]
fn a_drop_in_visudo_rejects_is_never_installed() {
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Rejects, Reads::DropIns);
    let error = fake.store().use_own_password(my_uid()).unwrap_err();
    assert!(error.contains("visudo rejected"), "{error}");
    assert!(fake.entries().is_empty(), "{:?}", fake.entries());
    assert_eq!(fake.store().detect(my_uid()), SudoPolicy::RootPassword);
}

#[test]
fn a_sudo_that_ignores_the_drop_in_directory_gets_the_file_removed_and_an_error() {
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Accepts, Reads::Nothing);
    let error = fake.store().use_own_password(my_uid()).unwrap_err();
    assert!(error.contains("does not read that directory"), "{error}");
    assert!(fake.entries().is_empty(), "{:?}", fake.entries());
}

#[test]
fn nothing_is_written_when_sudo_already_asks_for_the_users_own_password() {
    let fake = FakeSudo::new("    env_reset, use_pty", Visudo::Rejects, Reads::DropIns);
    assert_eq!(fake.store().use_own_password(my_uid()), Ok(SudoPolicy::OwnPassword));
    assert!(fake.entries().is_empty());
}

#[test]
fn restore_removes_only_the_uid_drop_in_and_is_idempotent() {
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Accepts, Reads::DropIns);
    fake.store().use_own_password(my_uid()).unwrap();
    fs::write(fake.drop_in_dir().join("admin"), "Defaults env_reset\n").unwrap();
    assert_eq!(fake.store().restore(my_uid()), Ok(true));
    assert_eq!(fake.store().restore(my_uid()), Ok(false));
    assert_eq!(fake.entries(), ["admin"]);
    assert_eq!(fake.store().detect(my_uid()), SudoPolicy::RootPassword);
}
