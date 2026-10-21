use std::io::Write;

pub mod dbus_client;
pub mod keyd_client;
pub mod pam_enable;
pub mod terminal;

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

pub trait KeyClient {
    fn provision(&mut self, uid: u32) -> Result<String, String>;
    fn set_pin(&mut self, uid: u32, pin: &str) -> Result<(), String>;
}

pub trait PinPrompt {
    fn read_secret(&mut self, prompt: &str) -> Result<String, String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Enroll { uid: u32 },
    Verify { uid: u32 },
    Identify,
    Purge { uid: u32 },
    SetPin { uid: u32 },
    Provision { uid: u32 },
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
    ProvisionFailed(String),
}

impl Outcome {
    pub fn exit_code(&self) -> u8 {
        match self {
            Outcome::Success => 0,
            Outcome::Rejected => 1,
            Outcome::Failed(_) => 3,
            Outcome::ProvisionFailed(_) => 4,
        }
    }
}

pub const USAGE: &str = "usage: openhello-cli [--bus system|session] <enroll|verify|purge|set-pin|provision> [--uid N] | identify";

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
        Some("set-pin") => Command::SetPin { uid: uid_or_current },
        Some("provision") => Command::Provision { uid: uid_or_current },
        Some("identify") if uid.is_none() => Command::Identify,
        Some("identify") => return Err("identify checks every enrolled account and takes no --uid".into()),
        Some(other) => return Err(format!("unknown command `{other}`")),
        None => return Err("a command is required".into()),
    };
    Ok(Invocation { bus, command })
}

pub struct Services<'a> {
    pub biometrics: &'a mut dyn BiometricsClient,
    pub keys: &'a mut dyn KeyClient,
    pub pins: &'a mut dyn PinPrompt,
}

pub fn execute(services: &mut Services, command: Command, out: &mut dyn Write) -> Outcome {
    match run(services, command, out) {
        Ok(outcome) => outcome,
        Err(problem) => Outcome::Failed(problem),
    }
}

fn run(services: &mut Services, command: Command, out: &mut dyn Write) -> Result<Outcome, String> {
    let Services { biometrics: client, keys, pins } = services;
    let mut say = |line: String| writeln!(out, "{line}").map_err(|e| format!("cannot write output: {e}"));
    match command {
        Command::Enroll { uid } => enroll(*client, *keys, uid, &mut say),
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
        Command::Provision { uid } => provision(*keys, uid, RETRY_FAILURE, &mut say),
        Command::SetPin { uid } => {
            let pin = pins.read_secret("New PIN: ")?;
            if pin.is_empty() {
                return Err("the PIN cannot be empty".into());
            }
            if pins.read_secret("Repeat the PIN: ")? != pin {
                return Err("the two PINs differ; nothing was changed".into());
            }
            keys.set_pin(uid, &pin)?;
            say(format!("PIN set for uid {uid}"))?;
            Ok(Outcome::Success)
        }
    }
}

fn enroll(
    client: &mut dyn BiometricsClient,
    keys: &mut dyn KeyClient,
    uid: u32,
    say: &mut dyn FnMut(String) -> Result<(), String>,
) -> Result<Outcome, String> {
    let handle = client.enroll_begin(uid)?;
    say(format!("enrolling uid {uid}: turn your head slowly through all poses"))?;
    for _ in 0..MAX_CAPTURES {
        let progress = client.enroll_capture(&handle)?;
        say(format!("frame {}: {}/{} poses covered", progress.verdict, progress.filled, progress.required))?;
        match progress.state.as_str() {
            "complete" => {
                client.enroll_commit(&handle)?;
                say(format!("enrolled uid {uid}"))?;
                return provision(keys, uid, &enrolled_failure(uid), say);
            }
            "failed" => return Err("enrollment failed: timed out without covering every pose".into()),
            _ => {}
        }
    }
    client.enroll_discard(&handle)?;
    Err(format!("enrollment abandoned after {MAX_CAPTURES} captures without covering every pose"))
}

const RETRY_FAILURE: &str = "the login key could not be created; run this from the desktop session and check the openhello-keyd service log";

fn enrolled_failure(uid: u32) -> String {
    format!("the face of uid {uid} was enrolled and kept, but the login key could not be created, so sudo face login will not work yet; run `openhello-cli provision` from the desktop session (no new enrollment needed) and check the openhello-keyd service log")
}

fn provision(keys: &mut dyn KeyClient, uid: u32, failure: &str, say: &mut dyn FnMut(String) -> Result<(), String>) -> Result<Outcome, String> {
    match keys.provision(uid) {
        Ok(code) => {
            say("recovery code (shown only now, store it safely; it unlocks the key if the PIN is lost):".to_string())?;
            say(code)?;
            Ok(Outcome::Success)
        }
        Err(_) => Ok(Outcome::ProvisionFailed(failure.to_string())),
    }
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

    #[derive(Default)]
    struct FakeKeys {
        calls: Vec<String>,
        provision_fails: bool,
    }

    const RECOVERY_CODE: &str = "RC-7Q2M-4KXD";

    impl KeyClient for FakeKeys {
        fn provision(&mut self, uid: u32) -> Result<String, String> {
            self.calls.push(format!("provision {uid}"));
            if self.provision_fails {
                return Err("Provision refused (io.openhello.Keyd1.Failed)".into());
            }
            Ok(RECOVERY_CODE.into())
        }

        fn set_pin(&mut self, uid: u32, pin: &str) -> Result<(), String> {
            self.calls.push(format!("set-pin {uid} {pin}"));
            Ok(())
        }
    }

    struct TypedPins(Vec<&'static str>);

    impl PinPrompt for TypedPins {
        fn read_secret(&mut self, _: &str) -> Result<String, String> {
            Ok(self.0.remove(0).to_string())
        }
    }

    fn run_with(client: &mut FakeClient, keys: &mut FakeKeys, pins: &mut TypedPins, command: Command) -> (Outcome, String) {
        let mut out = Vec::new();
        let mut services = Services { biometrics: client, keys, pins };
        let outcome = execute(&mut services, command, &mut out);
        (outcome, String::from_utf8(out).unwrap())
    }

    fn run_command(client: &mut FakeClient, command: Command) -> (Outcome, String) {
        run_with(client, &mut FakeKeys::default(), &mut TypedPins(vec![]), command)
    }

    fn enrolled_client() -> FakeClient {
        FakeClient { progress: vec![progress("complete", 6)], ..Default::default() }
    }

    // @covers:AC-016-cli
    #[test]
    fn enroll_provisions_the_key_after_the_commit_and_prints_the_recovery_code_once() {
        let mut client = enrolled_client();
        let mut keys = FakeKeys::default();
        let (outcome, output) = run_with(&mut client, &mut keys, &mut TypedPins(vec![]), Command::Enroll { uid: 1000 });
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(keys.calls, vec!["provision 1000"]);
        assert_eq!(client.calls.last().unwrap(), "commit h1");
        assert_eq!(output.matches(RECOVERY_CODE).count(), 1);
    }

    // @covers:AC-016-cli
    #[test]
    fn a_provision_failure_keeps_the_template_exits_with_its_own_code_and_prints_no_code() {
        let mut client = enrolled_client();
        let mut keys = FakeKeys { provision_fails: true, ..Default::default() };
        let (outcome, output) = run_with(&mut client, &mut keys, &mut TypedPins(vec![]), Command::Enroll { uid: 1000 });
        assert!(matches!(&outcome, Outcome::ProvisionFailed(m) if m.contains("enrolled and kept") && m.contains("openhello-cli provision") && !m.contains("Keyd1")));
        assert_eq!(outcome.exit_code(), 4);
        assert!(!client.calls.iter().any(|c| c.starts_with("discard")));
        assert!(!output.contains(RECOVERY_CODE) && !output.contains("recovery"));
    }

    // @covers:AC-016-cli
    #[test]
    fn provision_command_retries_the_key_without_enrolling_and_prints_the_code_once() {
        let mut client = FakeClient::default();
        let mut keys = FakeKeys::default();
        let (outcome, output) = run_with(&mut client, &mut keys, &mut TypedPins(vec![]), Command::Provision { uid: 1000 });
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(keys.calls, vec!["provision 1000"]);
        assert!(client.calls.is_empty());
        assert_eq!(output.matches(RECOVERY_CODE).count(), 1);

        let mut keys = FakeKeys { provision_fails: true, ..Default::default() };
        let (outcome, output) = run_with(&mut client, &mut keys, &mut TypedPins(vec![]), Command::Provision { uid: 1000 });
        assert!(matches!(&outcome, Outcome::ProvisionFailed(m) if !m.contains("Keyd1")));
        assert_eq!(outcome.exit_code(), 4);
        assert!(!output.contains(RECOVERY_CODE));
    }

    #[test]
    fn enroll_that_never_commits_does_not_provision() {
        let mut client = FakeClient { progress: vec![progress("failed", 1)], ..Default::default() };
        let mut keys = FakeKeys::default();
        run_with(&mut client, &mut keys, &mut TypedPins(vec![]), Command::Enroll { uid: 1000 });
        assert!(keys.calls.is_empty());
    }

    // @covers:AC-025-cli
    #[test]
    fn set_pin_asks_twice_and_sends_the_confirmed_pin() {
        let mut keys = FakeKeys::default();
        let (outcome, output) = run_with(&mut FakeClient::default(), &mut keys, &mut TypedPins(vec!["482916", "482916"]), Command::SetPin { uid: 1000 });
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(keys.calls, vec!["set-pin 1000 482916"]);
        assert!(!output.contains("482916"));
    }

    // @covers:AC-025-cli
    #[test]
    fn set_pin_rejects_a_mismatch_or_an_empty_pin_without_calling_the_keyd() {
        for typed in [vec!["482916", "482917"], vec!["", ""]] {
            let mut keys = FakeKeys::default();
            let (outcome, _) = run_with(&mut FakeClient::default(), &mut keys, &mut TypedPins(typed), Command::SetPin { uid: 1000 });
            assert!(matches!(&outcome, Outcome::Failed(m) if !m.contains("482916")), "{outcome:?}");
            assert!(keys.calls.is_empty());
        }
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
        assert_eq!(parse_args(args(&["set-pin"]), 1000).unwrap().command, Command::SetPin { uid: 1000 });
        assert_eq!(parse_args(args(&["provision", "--uid", "1001"]), 1000).unwrap().command, Command::Provision { uid: 1001 });

        for bad in [vec![], vec!["dance"], vec!["verify", "--uid", "-1"], vec!["--bus", "mars", "verify"], vec!["identify", "--uid", "5"], vec!["verify", "extra"], vec!["--uid"]] {
            assert!(parse_args(args(&bad), 1000).is_err(), "{bad:?}");
        }
    }
}
