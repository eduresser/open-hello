use std::path::Path;

const DISPLAY_VARS: [&str; 4] = [
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "WAYLAND_SOCKET",
    "XDG_SESSION_TYPE",
];
const GRAPHICAL_SESSION_TYPES: [&str; 3] = ["wayland", "x11", "mir"];
const SESSION_DIR: &str = "/run/systemd/sessions";

#[derive(Debug, PartialEq, Eq)]
pub enum Locality {
    Remote,
    Local,
    Unknown,
}

pub struct Probes<'a> {
    pub rhost: bool,
    pub tty: bool,
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub cgroup: &'a dyn Fn() -> Option<String>,
    pub session: &'a dyn Fn(&str) -> Option<String>,
}

pub fn locate(probes: &Probes) -> Locality {
    let present = |name: &str| (probes.env)(name).is_some();
    let logind = logind_remote(probes);
    if probes.rhost || present("SSH_CONNECTION") || logind == Some(true) {
        return Locality::Remote;
    }
    let graphical = DISPLAY_VARS.iter().any(|name| match (probes.env)(name) {
        Some(value) if *name == "XDG_SESSION_TYPE" => {
            GRAPHICAL_SESSION_TYPES.contains(&value.as_str())
        }
        Some(value) => !value.is_empty(),
        None => false,
    });
    if probes.tty || graphical || logind == Some(false) {
        Locality::Local
    } else {
        Locality::Unknown
    }
}

fn logind_remote(probes: &Probes) -> Option<bool> {
    let id = session_id(&(probes.cgroup)()?)?;
    let text = (probes.session)(&id)?;
    text.lines()
        .find_map(|line| line.strip_prefix("REMOTE="))
        .map(|value| value.trim() != "0")
}

fn session_id(cgroup: &str) -> Option<String> {
    cgroup
        .lines()
        .flat_map(|line| line.split('/'))
        .find_map(|part| part.strip_prefix("session-")?.strip_suffix(".scope"))
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(str::to_string)
}

pub fn process_env(name: &str) -> Option<String> {
    std::env::var_os(name).map(|v| v.to_string_lossy().into_owned())
}

pub fn process_cgroup() -> Option<String> {
    std::fs::read_to_string("/proc/self/cgroup").ok()
}

pub fn process_session(id: &str) -> Option<String> {
    std::fs::read_to_string(Path::new(SESSION_DIR).join(id)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Case<'a> {
        env: &'a [(&'a str, &'a str)],
        cgroup: Option<&'a str>,
        session: Option<&'a str>,
        rhost: bool,
        tty: bool,
    }

    const SESSION_CGROUP: &str = "0::/user.slice/user-1000.slice/session-7.scope\n";

    fn run(case: Case) -> Locality {
        let env = |name: &str| {
            case.env
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        };
        let cgroup = || case.cgroup.map(str::to_string);
        let session = |id: &str| {
            assert_eq!(id, "7");
            case.session.map(str::to_string)
        };
        locate(&Probes {
            rhost: case.rhost,
            tty: case.tty,
            env: &env,
            cgroup: &cgroup,
            session: &session,
        })
    }

    const NOTHING: Case = Case {
        env: &[],
        cgroup: None,
        session: None,
        rhost: false,
        tty: false,
    };

    // @covers:AC-028-pam-local-session
    #[test]
    fn a_process_with_no_session_signal_is_not_local() {
        assert_eq!(run(NOTHING), Locality::Unknown);
        let cron = Case {
            cgroup: Some("0::/system.slice/cron.service\n"),
            ..NOTHING
        };
        assert_eq!(run(cron), Locality::Unknown);
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn each_graphical_hint_alone_makes_the_session_local() {
        for env in [
            &[("WAYLAND_SOCKET", "3")][..],
            &[("WAYLAND_DISPLAY", "wayland-0")],
            &[("DISPLAY", ":0")],
            &[("XDG_SESSION_TYPE", "wayland")],
            &[("XDG_SESSION_TYPE", "x11")],
            &[("XDG_SESSION_TYPE", "mir")],
        ] {
            assert_eq!(run(Case { env, ..NOTHING }), Locality::Local, "{env:?}");
        }
        let tty = Case {
            tty: true,
            ..NOTHING
        };
        assert_eq!(run(tty), Locality::Local);
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn a_text_session_type_or_empty_display_is_not_a_local_hint() {
        for env in [
            &[("XDG_SESSION_TYPE", "tty")][..],
            &[("XDG_SESSION_TYPE", "unspecified")],
            &[("DISPLAY", "")],
        ] {
            assert_eq!(run(Case { env, ..NOTHING }), Locality::Unknown, "{env:?}");
        }
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn the_logind_session_decides_when_the_environment_is_silent() {
        let local = Case {
            cgroup: Some(SESSION_CGROUP),
            session: Some("USER=1000\nREMOTE=0\n"),
            ..NOTHING
        };
        assert_eq!(run(local), Locality::Local);
        let remote = Case {
            cgroup: Some(SESSION_CGROUP),
            session: Some("USER=1000\nREMOTE=1\n"),
            ..NOTHING
        };
        assert_eq!(run(remote), Locality::Remote);
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn a_remote_logind_session_beats_a_local_looking_environment() {
        let case = Case {
            env: &[("DISPLAY", ":0")],
            cgroup: Some(SESSION_CGROUP),
            session: Some("REMOTE=1\n"),
            ..NOTHING
        };
        assert_eq!(run(case), Locality::Remote);
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn ssh_wins_over_an_inherited_display_and_a_local_session_file() {
        let case = Case {
            env: &[
                ("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22"),
                ("DISPLAY", ":0"),
            ],
            cgroup: Some(SESSION_CGROUP),
            session: Some("REMOTE=0\n"),
            ..NOTHING
        };
        assert_eq!(run(case), Locality::Remote);
        let rhost = Case {
            rhost: true,
            tty: true,
            ..NOTHING
        };
        assert_eq!(run(rhost), Locality::Remote);
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn an_unreadable_session_file_or_cgroup_falls_back_to_the_other_probes() {
        let unreadable = Case {
            env: &[("WAYLAND_SOCKET", "3")],
            cgroup: Some(SESSION_CGROUP),
            session: None,
            ..NOTHING
        };
        assert_eq!(run(unreadable), Locality::Local);
        let no_cgroup = Case {
            env: &[("XDG_SESSION_TYPE", "x11")],
            ..NOTHING
        };
        assert_eq!(run(no_cgroup), Locality::Local);
        let silent = Case {
            cgroup: Some(SESSION_CGROUP),
            session: None,
            ..NOTHING
        };
        assert_eq!(run(silent), Locality::Unknown);
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn session_ids_are_taken_only_from_a_session_scope_component() {
        assert_eq!(session_id(SESSION_CGROUP).as_deref(), Some("7"));
        assert_eq!(session_id("0::/system.slice/cron.service"), None);
        assert_eq!(session_id("0::/x/session-..%2f.scope"), None);
        assert_eq!(session_id("0::/x/session-.scope"), None);
    }
}
