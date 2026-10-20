use std::io::Write;

pub mod dbus_client;

const MAX_CAPTURES: u32 = 400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub verdict: String,
    pub state: String,
    pub filled: u32,
    pub required: u32,
}

pub trait BiometricsClient {
    fn enroll_begin(&mut self, uid: u32) -> Result<String, String>;
    fn enroll_capture(&mut self, handle: &str) -> Result<Progress, String>;
    fn enroll_commit(&mut self, handle: &str) -> Result<(), String>;
    fn enroll_discard(&mut self, handle: &str) -> Result<(), String>;
    fn verify(&mut self, uid: u32) -> Result<bool, String>;
    fn identify(&mut self) -> Result<Option<u32>, String>;
    fn purge(&mut self, uid: u32) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Enroll { uid: u32 },
    Verify { uid: u32 },
    Identify,
    Purge { uid: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bus {
    System,
    Session,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Invocation {
    pub bus: Bus,
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Rejected,
    Failed(String),
}

impl Outcome {
    pub fn exit_code(&self) -> u8 {
        match self {
            Outcome::Success => 0,
            Outcome::Rejected => 1,
            Outcome::Failed(_) => 3,
        }
    }
}

pub const USAGE: &str = "usage: openhello-cli [--bus system|session] <enroll|verify|purge> [--uid N] | identify";

pub fn parse_args(args: impl IntoIterator<Item = String>, current_uid: u32) -> Result<Invocation, String> {
    let mut bus = Bus::System;
    let mut uid = None;
    let mut command_name = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bus" => {
                bus = match args.next().as_deref() {
                    Some("system") => Bus::System,
                    Some("session") => Bus::Session,
                    other => return Err(format!("--bus must be `system` or `session`, got `{}`", other.unwrap_or("nothing"))),
                }
            }
            "--uid" => {
                let text = args.next().ok_or("--uid needs a value")?;
                uid = Some(text.parse::<u32>().map_err(|_| format!("--uid must be a non-negative integer, got `{text}`"))?);
            }
            name if command_name.is_none() && !name.starts_with("--") => command_name = Some(arg),
            other => return Err(format!("unexpected argument `{other}`")),
        }
    }
    let uid_or_current = uid.unwrap_or(current_uid);
    let command = match command_name.as_deref() {
        Some("enroll") => Command::Enroll { uid: uid_or_current },
        Some("verify") => Command::Verify { uid: uid_or_current },
        Some("purge") => Command::Purge { uid: uid_or_current },
        Some("identify") if uid.is_none() => Command::Identify,
        Some("identify") => return Err("identify checks every enrolled account and takes no --uid".into()),
        Some(other) => return Err(format!("unknown command `{other}`")),
        None => return Err("a command is required".into()),
    };
    Ok(Invocation { bus, command })
}

pub fn execute(client: &mut dyn BiometricsClient, command: Command, out: &mut dyn Write) -> Outcome {
    match run(client, command, out) {
        Ok(outcome) => outcome,
        Err(problem) => Outcome::Failed(problem),
    }
}

fn run(client: &mut dyn BiometricsClient, command: Command, out: &mut dyn Write) -> Result<Outcome, String> {
    let mut say = |line: String| writeln!(out, "{line}").map_err(|e| format!("cannot write output: {e}"));
    match command {
        Command::Enroll { uid } => enroll(client, uid, &mut say),
        Command::Verify { uid } => {
            if client.verify(uid)? {
                say(format!("verified uid {uid}"))?;
                Ok(Outcome::Success)
            } else {
                say(format!("rejected uid {uid}"))?;
                Ok(Outcome::Rejected)
            }
        }
        Command::Identify => match client.identify()? {
            Some(uid) => {
                say(format!("identified uid {uid}"))?;
                Ok(Outcome::Success)
            }
            None => {
                say("no enrolled face matched".to_string())?;
                Ok(Outcome::Rejected)
            }
        },
        Command::Purge { uid } => {
            client.purge(uid)?;
            say(format!("purged uid {uid}"))?;
            Ok(Outcome::Success)
        }
    }
}

fn enroll(client: &mut dyn BiometricsClient, uid: u32, say: &mut dyn FnMut(String) -> Result<(), String>) -> Result<Outcome, String> {
    let handle = client.enroll_begin(uid)?;
    say(format!("enrolling uid {uid}: turn your head slowly through all poses"))?;
    for _ in 0..MAX_CAPTURES {
        let progress = client.enroll_capture(&handle)?;
        say(format!("frame {}: {}/{} poses covered", progress.verdict, progress.filled, progress.required))?;
        match progress.state.as_str() {
            "complete" => {
                client.enroll_commit(&handle)?;
                say(format!("enrolled uid {uid}"))?;
                return Ok(Outcome::Success);
            }
            "failed" => return Err("enrollment failed: timed out without covering every pose".into()),
            _ => {}
        }
    }
    client.enroll_discard(&handle)?;
    Err(format!("enrollment abandoned after {MAX_CAPTURES} captures without covering every pose"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeClient {
        calls: Vec<String>,
        progress: Vec<Progress>,
        verify_result: bool,
        identify_result: Option<u32>,
        fail_with: Option<String>,
    }

    fn progress(state: &str, filled: u32) -> Progress {
        Progress { verdict: "accepted".into(), state: state.into(), filled, required: 6 }
    }

    impl BiometricsClient for FakeClient {
        fn enroll_begin(&mut self, uid: u32) -> Result<String, String> {
            self.calls.push(format!("begin {uid}"));
            Ok("h1".into())
        }

        fn enroll_capture(&mut self, handle: &str) -> Result<Progress, String> {
            self.calls.push(format!("capture {handle}"));
            if let Some(problem) = &self.fail_with {
                return Err(problem.clone());
            }
            Ok(if self.progress.is_empty() { progress("in-progress", 0) } else { self.progress.remove(0) })
        }

        fn enroll_commit(&mut self, handle: &str) -> Result<(), String> {
            self.calls.push(format!("commit {handle}"));
            Ok(())
        }

        fn enroll_discard(&mut self, handle: &str) -> Result<(), String> {
            self.calls.push(format!("discard {handle}"));
            Ok(())
        }

        fn verify(&mut self, uid: u32) -> Result<bool, String> {
            self.calls.push(format!("verify {uid}"));
            Ok(self.verify_result)
        }

        fn identify(&mut self) -> Result<Option<u32>, String> {
            self.calls.push("identify".into());
            Ok(self.identify_result)
        }

        fn purge(&mut self, uid: u32) -> Result<(), String> {
            self.calls.push(format!("purge {uid}"));
            Ok(())
        }
    }

    fn run_command(client: &mut FakeClient, command: Command) -> (Outcome, String) {
        let mut out = Vec::new();
        let outcome = execute(client, command, &mut out);
        (outcome, String::from_utf8(out).unwrap())
    }

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn enroll_captures_until_complete_then_commits() {
        let mut client = FakeClient { progress: vec![progress("in-progress", 2), progress("in-progress", 5), progress("complete", 6)], ..Default::default() };
        let (outcome, output) = run_command(&mut client, Command::Enroll { uid: 1000 });
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(client.calls, vec!["begin 1000", "capture h1", "capture h1", "capture h1", "commit h1"]);
        assert!(output.contains("6/6 poses covered") && output.contains("enrolled uid 1000"));
    }

    #[test]
    fn enroll_reports_daemon_timeout_and_never_commits() {
        let mut client = FakeClient { progress: vec![progress("failed", 1)], ..Default::default() };
        let (outcome, _) = run_command(&mut client, Command::Enroll { uid: 1000 });
        assert!(matches!(&outcome, Outcome::Failed(m) if m.contains("timed out")));
        assert!(!client.calls.iter().any(|c| c.starts_with("commit")));
    }

    #[test]
    fn enroll_gives_up_and_discards_after_the_capture_budget() {
        let mut client = FakeClient::default();
        let (outcome, _) = run_command(&mut client, Command::Enroll { uid: 1000 });
        assert!(matches!(outcome, Outcome::Failed(_)));
        assert_eq!(client.calls.iter().filter(|c| c.starts_with("capture")).count(), MAX_CAPTURES as usize);
        assert_eq!(client.calls.last().unwrap(), "discard h1");
    }

    #[test]
    fn daemon_errors_become_failed_outcomes_with_exit_code_three() {
        let mut client = FakeClient { fail_with: Some("camera busy".into()), ..Default::default() };
        let (outcome, _) = run_command(&mut client, Command::Enroll { uid: 1000 });
        assert_eq!(outcome, Outcome::Failed("camera busy".into()));
        assert_eq!(outcome.exit_code(), 3);
    }

    #[test]
    fn verify_identify_and_purge_map_results_to_outcomes() {
        let mut yes = FakeClient { verify_result: true, identify_result: Some(1001), ..Default::default() };
        assert_eq!(run_command(&mut yes, Command::Verify { uid: 1000 }).0, Outcome::Success);
        let (outcome, output) = run_command(&mut yes, Command::Identify);
        assert_eq!((outcome, output.trim()), (Outcome::Success, "identified uid 1001"));
        assert_eq!(run_command(&mut yes, Command::Purge { uid: 1000 }).0, Outcome::Success);

        let mut no = FakeClient::default();
        assert_eq!(run_command(&mut no, Command::Verify { uid: 1000 }).0.exit_code(), 1);
        assert_eq!(run_command(&mut no, Command::Identify).0, Outcome::Rejected);
    }

    #[test]
    fn arguments_default_to_the_current_user_and_validate_input() {
        let parsed = parse_args(args(&["verify"]), 1000).unwrap();
        assert_eq!(parsed, Invocation { bus: Bus::System, command: Command::Verify { uid: 1000 } });
        let parsed = parse_args(args(&["--bus", "session", "purge", "--uid", "1002"]), 1000).unwrap();
        assert_eq!(parsed, Invocation { bus: Bus::Session, command: Command::Purge { uid: 1002 } });
        assert_eq!(parse_args(args(&["identify"]), 1000).unwrap().command, Command::Identify);

        for bad in [vec![], vec!["dance"], vec!["verify", "--uid", "-1"], vec!["--bus", "mars", "verify"], vec!["identify", "--uid", "5"], vec!["verify", "extra"], vec!["--uid"]] {
            assert!(parse_args(args(&bad), 1000).is_err(), "{bad:?}");
        }
    }
}
