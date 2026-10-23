use std::io::Write;
use std::path::PathBuf;

use openhellod::polkit_admin::PolkitAdminStore;
use openhellod::sudo_policy::SudoPolicyStore;

pub const ADMIN_USAGE: &str = "usage: openhello-cli admin <status | own-password | restore> UID [--root DIR]";

pub struct AdminFailure {
    pub code: u8,
    pub message: String,
}

enum Action {
    Status,
    OwnPassword,
    Restore,
}

fn usage(message: &str) -> AdminFailure {
    AdminFailure { code: 2, message: format!("{message}\n{ADMIN_USAGE}") }
}

fn failed(message: String) -> AdminFailure {
    AdminFailure { code: 3, message }
}

pub fn run(args: &[String], out: &mut dyn Write) -> Result<(), AdminFailure> {
    let action = match args.first().map(String::as_str) {
        Some("status") => Action::Status,
        Some("own-password") => Action::OwnPassword,
        Some("restore") => Action::Restore,
        Some(other) => return Err(usage(&format!("unknown admin command `{other}`"))),
        None => return Err(usage("an admin command is required")),
    };
    let uid: u32 = args
        .get(1)
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| usage("a numeric UID is required"))?;
    let root = match args.get(2..).unwrap_or_default() {
        [] => None,
        [flag, dir] if flag == "--root" => Some(PathBuf::from(dir)),
        _ => return Err(usage("unexpected arguments")),
    };
    let writes = !matches!(action, Action::Status);
    if writes && root.is_none() && unsafe { libc::geteuid() } != 0 {
        return Err(failed("changing /etc/sudoers.d and /etc/polkit-1/rules.d requires root; run with sudo".into()));
    }
    let (sudo, polkit) = match &root {
        Some(root) => (
            SudoPolicyStore::new(root.join("etc/sudoers.d"), "sudo", "visudo"),
            PolkitAdminStore::new(root.join("etc/polkit-1/rules.d")),
        ),
        None => (SudoPolicyStore::system(), PolkitAdminStore::system()),
    };
    let mut say = |text: String| {
        let _ = writeln!(out, "{text}");
    };
    match action {
        Action::Status => {
            say(format!("sudo: {}", sudo.detect(uid).as_str()));
            say(format!("polkit: {}", polkit_state(polkit.is_own(uid))));
        }
        Action::OwnPassword => {
            let policy = sudo.use_own_password(uid).map_err(failed)?;
            polkit.use_own_identity(uid).map_err(failed)?;
            say(format!("sudo: {}", policy.as_str()));
            say(format!("polkit: {}", polkit_state(true)));
        }
        Action::Restore => {
            let sudo_removed = sudo.restore(uid).map_err(failed)?;
            let polkit_removed = polkit.restore(uid).map_err(failed)?;
            say(format!("sudo: {}", restored_state(sudo_removed)));
            say(format!("polkit: {}", restored_state(polkit_removed)));
        }
    }
    Ok(())
}

fn polkit_state(own: bool) -> &'static str {
    if own {
        "own-password"
    } else {
        "system-default"
    }
}

fn restored_state(removed: bool) -> &'static str {
    if removed {
        "restored"
    } else {
        "nothing to restore"
    }
}
