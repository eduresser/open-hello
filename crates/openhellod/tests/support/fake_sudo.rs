#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use openhellod::sudo_policy::SudoPolicyStore;

pub const TUMBLEWEED_DEFAULTS: &str = "    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin, always_set_home, env_reset, env_keep=\"LANG LC_ADDRESS LC_ALL LANGUAGE LINGUAS XDG_SESSION_COOKIE\", !insults, secure_path=/usr/sbin\\:/usr/bin\\:/sbin\\:/bin, targetpw";

pub struct FakeSudo {
    pub dir: tempfile::TempDir,
}

pub enum Visudo {
    Accepts,
    Rejects,
}

pub enum Reads {
    DropIns,
    Nothing,
}

impl FakeSudo {
    pub fn new(defaults: &str, visudo: Visudo, reads: Reads) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let drop_ins = dir.path().join("etc/sudoers.d");
        let extra = match reads {
            Reads::DropIns => format!(
                "for f in {}/*; do [ -f \"$f\" ] && printf ', %s' \"$(sed -n 's/^Defaults:[^ ]* //p' \"$f\")\"; done",
                drop_ins.display()
            ),
            Reads::Nothing => String::new(),
        };
        let sudo = format!(
            "#!/bin/sh\n[ -n \"$FAKE_PROBE\" ] && exit 0\necho \"$*\" >> {log}\nprintf 'Matching Defaults entries for %s on host:\\n' \"$4\"\nprintf '%s' '{defaults}'\n{extra}\nprintf '\\n\\nUser %s may run the following commands on host:\\n    (ALL) ALL\\n' \"$4\"\n",
            log = dir.path().join("sudo.log").display(),
        );
        let visudo = match visudo {
            Visudo::Accepts => "#!/bin/sh\nexit 0\n".to_string(),
            Visudo::Rejects => "#!/bin/sh\n[ -n \"$FAKE_PROBE\" ] && exit 0\necho 'syntax error' >&2\nexit 1\n".to_string(),
        };
        write_exec(&dir.path().join("sudo"), &sudo);
        write_exec(&dir.path().join("visudo"), &visudo);
        Self { dir }
    }

    pub fn store(&self) -> SudoPolicyStore {
        SudoPolicyStore::new(self.drop_in_dir(), self.dir.path().join("sudo"), self.dir.path().join("visudo"))
    }

    pub fn drop_in_dir(&self) -> PathBuf {
        self.dir.path().join("etc/sudoers.d")
    }

    pub fn drop_in(&self, uid: u32) -> PathBuf {
        self.drop_in_dir().join(format!("openhello-uid{uid}"))
    }

    pub fn entries(&self) -> Vec<String> {
        fs::read_dir(self.drop_in_dir())
            .map(|dir| dir.map(|e| e.unwrap().file_name().into_string().unwrap()).collect())
            .unwrap_or_default()
    }
}

fn write_exec(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    // Another test thread may fork while this file is still open for writing; exec fails with ETXTBSY until that child execs.
    for _ in 0..200 {
        match std::process::Command::new(path).env("FAKE_PROBE", "1").status() {
            Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => std::thread::sleep(std::time::Duration::from_millis(5)),
            _ => return,
        }
    }
    panic!("{} stayed busy", path.display());
}

pub fn my_uid() -> u32 {
    unsafe { libc::getuid() }
}
