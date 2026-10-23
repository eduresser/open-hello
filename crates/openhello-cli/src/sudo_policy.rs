use std::io::Write;
use std::path::PathBuf;

use openhellod::sudo_policy::{SudoPolicy, SudoPolicyStore};

pub const SUDO_USAGE: &str = "usage: openhello-cli sudo <status | own-password | restore> UID [--root DIR]";

pub struct SudoFailure {
    pub code: u8,
    pub message: String,
}

enum Action {
    Status,
    OwnPassword,
    Restore,
}

fn usage(message: &str) -> SudoFailure {
    SudoFailure { code: 2, message: format!("{message}\n{SUDO_USAGE}") }
}

fn failed(message: String) -> SudoFailure {
    SudoFailure { code: 3, message }
}

pub fn run(args: &[String], out: &mut dyn Write) -> Result<(), SudoFailure> {
    let action = match args.first().map(String::as_str) {
        Some("status") => Action::Status,
        Some("own-password") => Action::OwnPassword,
        Some("restore") => Action::Restore,
        Some(other) => return Err(usage(&format!("unknown sudo command `{other}`"))),
        None => return Err(usage("a sudo command is required")),
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
        return Err(failed("changing /etc/sudoers.d requires root; run with sudo".into()));
    }
    let store = match &root {
        Some(root) => SudoPolicyStore::new(root.join("etc/sudoers.d"), "sudo", "visudo"),
        None => SudoPolicyStore::system(),
    };
    let report = |out: &mut dyn Write, policy: SudoPolicy| {
        let _ = writeln!(out, "{}", policy.as_str());
    };
    match action {
        Action::Status => report(out, store.detect(uid)),
        Action::OwnPassword => report(out, store.use_own_password(uid).map_err(failed)?),
        Action::Restore => {
            let removed = store.restore(uid).map_err(failed)?;
            let _ = writeln!(out, "{}", if removed { "restored" } else { "nothing to restore" });
        }
    }
    Ok(())
}
