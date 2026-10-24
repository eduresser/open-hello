use std::path::Path;

const DISPLAY_VARS: [&str; 4] = [
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "WAYLAND_SOCKET",
    "XDG_SESSION_TYPE",
];
const GRAPHICAL_SESSION_TYPES: [&str; 3] = ["wayland", "x11", "mir"];
const SESSION_DIR: &str = "/run/systemd/sessions";
const USER_DIR: &str = "/run/systemd/users";

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
    pub user: &'a dyn Fn(&str) -> Option<String>,
    pub sessions: &'a dyn Fn() -> Vec<String>,
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
    if probes.tty || graphical || logind == Some(false) || local_greeter_present(probes) {
        Locality::Local
    } else {
        Locality::Unknown
    }
}

pub fn describe(probes: &Probes) -> String {
    let cgroup = (probes.cgroup)();
    let unit = |cgroup: &Option<String>| {
        cgroup
            .as_deref()
            .and_then(|text| text.trim().rsplit('/').next())
            .unwrap_or("none")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
            .take(80)
            .collect::<String>()
    };
    let peer = socket_peer_pid(libc::STDIN_FILENO);
    format!(
        "locality cgroup={} peer_pid={} logind_remote={:?} rhost={} tty={}",
        unit(&cgroup),
        peer.map_or("none".to_string(), |pid| pid.to_string()),
        logind_remote(probes),
        probes.rhost,
        probes.tty,
    )
}

pub fn is_login_manager_helper(probes: &Probes) -> bool {
    let Some(cgroup) = (probes.cgroup)() else {
        return false;
    };
    !in_user_tree(&cgroup) && local_greeter_present(probes)
}

fn in_user_tree(cgroup: &str) -> bool {
    session_id(cgroup).is_some()
        || cgroup
            .lines()
            .flat_map(|line| line.split('/'))
            .any(|part| part.starts_with("user-") && part.ends_with(".slice"))
}

// polkit 126+ runs its agent helper as a socket-activated system service; the agent on the
// other end of stdin lives in the requesting session, so its cgroup is the one to judge.
pub fn requester_cgroup(own: Option<String>, peer: impl FnOnce() -> Option<String>) -> Option<String> {
    match own {
        Some(own) if in_user_tree(&own) => Some(own),
        own => peer().filter(|cgroup| in_user_tree(cgroup)).or(own),
    }
}

pub fn socket_peer_pid(fd: i32) -> Option<i32> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut credentials as *mut libc::ucred).cast(), &mut length)
    };
    (rc == 0 && credentials.pid > 0).then_some(credentials.pid)
}

fn local_greeter_present(probes: &Probes) -> bool {
    (probes.sessions)().iter().any(|text| {
        let has = |entry: &str| text.lines().any(|line| line.trim() == entry);
        has("CLASS=greeter") && has("REMOTE=0")
    })
}

fn logind_remote(probes: &Probes) -> Option<bool> {
    let cgroup = (probes.cgroup)()?;
    let id = session_id(&cgroup).or_else(|| display_session_id(&cgroup, probes))?;
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

fn display_session_id(cgroup: &str, probes: &Probes) -> Option<String> {
    let uid = cgroup
        .lines()
        .flat_map(|line| line.split('/'))
        .find_map(|part| part.strip_prefix("user-")?.strip_suffix(".slice"))
        .filter(|uid| !uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()))?;
    (probes.user)(uid)?
        .lines()
        .find_map(|line| line.strip_prefix("DISPLAY="))
        .map(str::trim)
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(str::to_string)
}

pub fn process_env(name: &str) -> Option<String> {
    std::env::var_os(name).map(|v| v.to_string_lossy().into_owned())
}

pub fn process_cgroup() -> Option<String> {
    requester_cgroup(std::fs::read_to_string("/proc/self/cgroup").ok(), || {
        let pid = socket_peer_pid(libc::STDIN_FILENO)?;
        std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()
    })
}

pub fn process_session(id: &str) -> Option<String> {
    std::fs::read_to_string(Path::new(SESSION_DIR).join(id)).ok()
}

pub fn process_sessions() -> Vec<String> {
    std::fs::read_dir(SESSION_DIR)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric())
            })
        })
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .collect()
}

pub fn process_user(uid: &str) -> Option<String> {
    std::fs::read_to_string(Path::new(USER_DIR).join(uid)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Case<'a> {
        env: &'a [(&'a str, &'a str)],
        cgroup: Option<&'a str>,
        session: Option<&'a str>,
        user: Option<&'a str>,
        sessions: &'a [&'a str],
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
        let user = |uid: &str| {
            assert_eq!(uid, "1000");
            case.user.map(str::to_string)
        };
        let sessions = || case.sessions.iter().map(|s| s.to_string()).collect();
        locate(&Probes {
            sessions: &sessions,
            rhost: case.rhost,
            tty: case.tty,
            env: &env,
            cgroup: &cgroup,
            session: &session,
            user: &user,
        })
    }

    const NOTHING: Case = Case {
        env: &[],
        cgroup: None,
        session: None,
        user: None,
        sessions: &[],
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

    const SERVICE_CGROUP: &str =
        "0::/user.slice/user-1000.slice/user@1000.service/background.slice/polkit-agent.service\n";

    // @covers:AC-028-pam-local-session
    #[test]
    fn a_user_service_has_no_session_scope_so_the_users_display_session_decides() {
        let local = Case {
            cgroup: Some(SERVICE_CGROUP),
            user: Some("NAME=eduresser\nDISPLAY=7\n"),
            session: Some("REMOTE=0\n"),
            ..NOTHING
        };
        assert_eq!(run(local), Locality::Local);
        let remote = Case {
            cgroup: Some(SERVICE_CGROUP),
            user: Some("DISPLAY=7\n"),
            session: Some("REMOTE=1\n"),
            ..NOTHING
        };
        assert_eq!(run(remote), Locality::Remote);
        for user in [
            None,
            Some("NAME=eduresser\n"),
            Some("DISPLAY=\n"),
            Some("DISPLAY=../x\n"),
        ] {
            let unknown = Case {
                cgroup: Some(SERVICE_CGROUP),
                user,
                session: Some("REMOTE=0\n"),
                ..NOTHING
            };
            assert_eq!(run(unknown), Locality::Unknown, "{user:?}");
        }
        let system = Case {
            cgroup: Some("0::/system.slice/cron.service\n"),
            user: Some("DISPLAY=7\n"),
            session: Some("REMOTE=0\n"),
            ..NOTHING
        };
        assert_eq!(run(system), Locality::Unknown);
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn session_ids_are_taken_only_from_a_session_scope_component() {
        assert_eq!(session_id(SESSION_CGROUP).as_deref(), Some("7"));
        assert_eq!(session_id("0::/system.slice/cron.service"), None);
        assert_eq!(session_id("0::/x/session-..%2f.scope"), None);
        assert_eq!(session_id("0::/x/session-.scope"), None);
    }

    const GREETER_CGROUP: &str = "0::/system.slice/display-manager.service\n";

    // @covers:AC-028-pam-local-session
    #[test]
    fn a_login_manager_helper_is_local_when_logind_has_a_local_greeter_session() {
        let greeter = Case {
            cgroup: Some(GREETER_CGROUP),
            sessions: &[
                "CLASS=user\nREMOTE=0\n",
                "CLASS=greeter\nSEAT=seat0\nREMOTE=0\n",
            ],
            ..NOTHING
        };
        assert_eq!(run(greeter), Locality::Local);
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn a_greeter_session_does_not_make_remote_or_unrelated_processes_local() {
        let remote_greeter = Case {
            cgroup: Some(GREETER_CGROUP),
            sessions: &["CLASS=greeter\nREMOTE=1\n"],
            ..NOTHING
        };
        assert_eq!(run(remote_greeter), Locality::Unknown);
        let user_only = Case {
            cgroup: Some(GREETER_CGROUP),
            sessions: &["CLASS=user\nREMOTE=0\n"],
            ..NOTHING
        };
        assert_eq!(run(user_only), Locality::Unknown);
        let ssh = Case {
            env: &[("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22")],
            sessions: &["CLASS=greeter\nREMOTE=0\n"],
            ..NOTHING
        };
        assert_eq!(run(ssh), Locality::Remote);
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn the_login_manager_helper_is_outside_every_user_session_with_a_local_greeter() {
        let greeters: &[&str] = &["CLASS=greeter\nREMOTE=0\n"];
        let helper = Case {
            cgroup: Some(GREETER_CGROUP),
            sessions: greeters,
            ..NOTHING
        };
        assert!(helper_of(helper));
        for cgroup in [
            Some(SESSION_CGROUP),
            Some(SERVICE_CGROUP),
            Some("0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n"),
            None,
        ] {
            let other = Case {
                cgroup,
                sessions: greeters,
                ..NOTHING
            };
            assert!(!helper_of(other), "{cgroup:?}");
        }
        let no_greeter = Case {
            cgroup: Some(GREETER_CGROUP),
            ..NOTHING
        };
        assert!(!helper_of(no_greeter));
    }

    fn helper_of(case: Case) -> bool {
        let env = |_: &str| None;
        let cgroup = || case.cgroup.map(str::to_string);
        let session = |_: &str| None;
        let user = |_: &str| None;
        let sessions = || case.sessions.iter().map(|s| s.to_string()).collect();
        is_login_manager_helper(&Probes {
            rhost: false,
            tty: false,
            env: &env,
            cgroup: &cgroup,
            session: &session,
            user: &user,
            sessions: &sessions,
        })
    }

    const HELPER_CGROUP: &str = "0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@3-1234-1000.service\n";

    // @covers:AC-028-pam-local-session
    #[test]
    fn a_socket_activated_polkit_helper_is_judged_by_the_session_of_the_agent_it_serves() {
        let agent = Some(SERVICE_CGROUP.to_string());
        assert_eq!(requester_cgroup(Some(HELPER_CGROUP.into()), || agent.clone()), agent);
        assert_eq!(requester_cgroup(Some(SESSION_CGROUP.into()), || panic!("own session wins")), Some(SESSION_CGROUP.into()));
        assert_eq!(requester_cgroup(Some(HELPER_CGROUP.into()), || None), Some(HELPER_CGROUP.into()));
        let system_peer = Some("0::/system.slice/cron.service\n".to_string());
        assert_eq!(requester_cgroup(Some(HELPER_CGROUP.into()), || system_peer), Some(HELPER_CGROUP.into()));
        assert_eq!(requester_cgroup(None, || agent.clone()), agent);
    }

    #[test]
    fn the_peer_of_a_unix_socket_is_the_process_on_the_other_end_and_other_fds_have_none() {
        use std::os::fd::AsRawFd;
        let (left, _right) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(socket_peer_pid(left.as_raw_fd()), Some(std::process::id() as i32));
        let file = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(socket_peer_pid(file.as_raw_fd()), None);
        assert_eq!(socket_peer_pid(-1), None);
    }
}
