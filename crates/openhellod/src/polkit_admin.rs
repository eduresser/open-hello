use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use crate::sudo_policy::user_name;

const SYSTEM_RULES_DIR: &str = "/etc/polkit-1/rules.d";

pub struct PolkitAdminStore {
    rules_dir: PathBuf,
}

impl PolkitAdminStore {
    pub fn system() -> Self {
        Self::new(SYSTEM_RULES_DIR)
    }

    pub fn new(rules_dir: impl Into<PathBuf>) -> Self {
        Self { rules_dir: rules_dir.into() }
    }

    // 49 sorts before the distros' 50-default.rules, and the first admin rule that answers wins.
    fn rule(&self, uid: u32) -> PathBuf {
        self.rules_dir.join(format!("49-openhello-uid{uid}.rules"))
    }

    pub fn is_own(&self, uid: u32) -> bool {
        self.rule(uid).is_file()
    }

    pub fn use_own_identity(&self, uid: u32) -> Result<(), String> {
        let user = user_name(uid)
            .filter(|name| plain_user_name(name))
            .ok_or_else(|| format!("uid {uid} has no plain user name for a polkit rule"))?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&self.rules_dir)
            .map_err(|e| format!("cannot create {}: {e}", self.rules_dir.display()))?;
        let staged = self.rules_dir.join(format!(".openhello-uid{uid}.tmp"));
        let _ = fs::remove_file(&staged);
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&staged)
            .and_then(|mut file| file.write_all(admin_rule(&user).as_bytes()).and_then(|()| file.sync_all()))
            .and_then(|()| fs::rename(&staged, self.rule(uid)));
        written.map_err(|e| {
            let _ = fs::remove_file(&staged);
            format!("cannot install {}: {e}", self.rule(uid).display())
        })
    }

    pub fn restore(&self, uid: u32) -> Result<bool, String> {
        match fs::remove_file(self.rule(uid)) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("cannot remove {}: {error}", self.rule(uid).display())),
        }
    }
}

pub fn admin_rule(user: &str) -> String {
    format!(
        "polkit.addAdminRule(function(action, subject) {{\n    if (subject.user == \"{user}\") {{\n        return [\"unix-user:{user}\"];\n    }}\n}});\n"
    )
}

fn plain_user_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
