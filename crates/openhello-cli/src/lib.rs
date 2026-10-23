use std::io::Write;

pub mod dbus_client;
pub mod keyd_client;
pub mod pam_enable;
pub mod admin;

const MAX_CAPTURES: u32 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub verdict: String,
    pub state: String,
    pub filled: u32,
    pub required: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub error_name: Option<String>,
    pub message: String,
}

impl Refusal {
    pub fn local(message: impl Into<String>) -> Self {
        Self { error_name: None, message: message.into() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyStatus {
    pub key: bool,
    pub pin: bool,
}

pub trait BiometricsClient {
    fn enroll_begin(&mut self, uid: u32) -> Result<String, String>;
    fn enroll_capture(&mut self, handle: &str) -> Result<Progress, String>;
    fn enroll_commit(&mut self, handle: &str) -> Result<(), String>;
    fn enroll_discard(&mut self, handle: &str) -> Result<(), String>;
    fn verify(&mut self, uid: u32) -> Result<bool, String>;
    fn identify(&mut self) -> Result<Option<u32>, String>;
    fn purge(&mut self, uid: u32) -> Result<(), String>;
    fn face_status(&mut self, uid: u32) -> Result<bool, String>;
}

pub trait KeyClient {
    fn provision(&mut self, uid: u32) -> Result<String, String>;
    fn key_status(&mut self, uid: u32) -> Result<KeyStatus, String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Enroll { uid: u32 },
    Verify { uid: u32 },
    Identify,
    Purge { uid: u32 },
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

pub const USAGE: &str = "usage: openhello-cli [--bus system|session] <enroll|verify|purge|provision> [--uid N] | identify";

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
}

pub fn execute(services: &mut Services, command: Command, out: &mut dyn Write) -> Outcome {
    match run(services, command, out) {
        Ok(outcome) => outcome,
        Err(problem) => Outcome::Failed(problem),
    }
}

fn run(services: &mut Services, command: Command, out: &mut dyn Write) -> Result<Outcome, String> {
    let Services { biometrics: client, keys } = services;
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
        Command::Provision { uid } => provision(*keys, uid, RETRY_FAILURE),
    }
}

fn enroll(
    client: &mut dyn BiometricsClient,
    keys: &mut dyn KeyClient,
    uid: u32,
    say: &mut dyn FnMut(String) -> Result<(), String>,
) -> Result<Outcome, String> {
    let handle = client.enroll_begin(uid)?;
    say(ENROLL_INTRO.to_string())?;
    let mut last_line = String::new();
    for _ in 0..MAX_CAPTURES {
        let progress = client.enroll_capture(&handle)?;
        let line = format!("{} ({}%)", enroll_guidance(&progress.verdict), percent(progress.filled, progress.required));
        if line != last_line {
            say(line.clone())?;
            last_line = line;
        }
        match progress.state.as_str() {
            "complete" => {
                client.enroll_commit(&handle)?;
                say(format!("enrolled uid {uid}"))?;
                return provision(keys, uid, &enrolled_failure(uid));
            }
            "failed" => return Err("enrollment failed: timed out before enough frontal samples were collected".into()),
            _ => {}
        }
    }
    client.enroll_discard(&handle)?;
    Err(format!("enrollment abandoned after {MAX_CAPTURES} captures without enough frontal samples"))
}

fn percent(filled: u32, required: u32) -> u32 {
    if required == 0 {
        return 0;
    }
    (u64::from(filled.min(required)) * 100 / u64::from(required)) as u32
}

const ENROLL_INTRO: &str = "Face the camera and keep your face centered. The prompts tell you whether to move closer or back";

pub fn enroll_guidance(verdict: &str) -> &str {
    match verdict {
        "accepted" | "too-soon" => "Hold still and look at the camera",
        "no-face" => "No face found. Center your face in the oval",
        "move-left" => "Move a little to your left",
        "move-right" => "Move a little to your right",
        "move-up" => "Move up a little",
        "move-down" => "Move down a little",
        "too-close" => "Too close. Move back a little",
        "too-far" => "Too far. Move a little closer",
        "too-dark" => "Not enough light on your face",
        "too-bright" => "Too much light. Avoid glare in front of or behind you",
        "yaw-out-of-range" => "Face the camera straight on",
        "blurred" => "Hold still. The image is blurry",
        "occluded" => "Something is covering your face. Clear it from view",
        other => other,
    }
}

const RETRY_FAILURE: &str = "the login key could not be created; run this from the desktop session and check the openhello-keyd service log";

fn enrolled_failure(uid: u32) -> String {
    format!("the face of uid {uid} was enrolled and kept, but the login key could not be created, so sudo face login will not work yet; run `openhello-cli provision` from the desktop session (no new enrollment needed) and check the openhello-keyd service log")
}

fn provision(keys: &mut dyn KeyClient, uid: u32, failure: &str) -> Result<Outcome, String> {
    match keys.provision(uid) {
        Ok(_) => Ok(Outcome::Success),
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
        face_enrolled: bool,
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

        fn face_status(&mut self, uid: u32) -> Result<bool, String> {
            self.calls.push(format!("face-status {uid}"));
            Ok(self.face_enrolled)
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

        fn key_status(&mut self, uid: u32) -> Result<KeyStatus, String> {
            self.calls.push(format!("key-status {uid}"));
            Ok(KeyStatus { key: true, pin: false })
        }
    }

    fn run_with(client: &mut FakeClient, keys: &mut FakeKeys, command: Command) -> (Outcome, String) {
        let mut out = Vec::new();
        let mut services = Services { biometrics: client, keys };
        let outcome = execute(&mut services, command, &mut out);
        (outcome, String::from_utf8(out).unwrap())
    }

    fn assert_no_recovery_code(output: &str) {
        assert!(!output.contains(RECOVERY_CODE) && !output.to_lowercase().contains("recovery"));
    }

    fn run_command(client: &mut FakeClient, command: Command) -> (Outcome, String) {
        run_with(client, &mut FakeKeys::default(), command)
    }

    fn enrolled_client() -> FakeClient {
        FakeClient { progress: vec![progress("complete", 6)], ..Default::default() }
    }

    // @covers:AC-016-cli
    #[test]
    fn enroll_provisions_the_key_after_the_commit_and_never_prints_the_recovery_code() {
        let mut client = enrolled_client();
        let mut keys = FakeKeys::default();
        let (outcome, output) = run_with(&mut client, &mut keys, Command::Enroll { uid: 1000 });
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(keys.calls, vec!["provision 1000"]);
        assert_eq!(client.calls.last().unwrap(), "commit h1");
        assert_no_recovery_code(&output);
    }

    // @covers:AC-016-cli
    #[test]
    fn a_provision_failure_keeps_the_template_exits_with_its_own_code_and_prints_no_code() {
        let mut client = enrolled_client();
        let mut keys = FakeKeys { provision_fails: true, ..Default::default() };
        let (outcome, output) = run_with(&mut client, &mut keys, Command::Enroll { uid: 1000 });
        assert!(matches!(&outcome, Outcome::ProvisionFailed(m) if m.contains("enrolled and kept") && m.contains("openhello-cli provision") && !m.contains("Keyd1")));
        assert_eq!(outcome.exit_code(), 4);
        assert!(!client.calls.iter().any(|c| c.starts_with("discard")));
        assert_no_recovery_code(&output);
    }

    // @covers:AC-016-cli
    #[test]
    fn provision_command_retries_the_key_without_enrolling_and_never_prints_the_code() {
        let mut client = FakeClient::default();
        let mut keys = FakeKeys::default();
        let (outcome, output) = run_with(&mut client, &mut keys, Command::Provision { uid: 1000 });
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(keys.calls, vec!["provision 1000"]);
        assert!(client.calls.is_empty());
        assert_no_recovery_code(&output);

        let mut keys = FakeKeys { provision_fails: true, ..Default::default() };
        let (outcome, output) = run_with(&mut client, &mut keys, Command::Provision { uid: 1000 });
        assert!(matches!(&outcome, Outcome::ProvisionFailed(m) if !m.contains("Keyd1")));
        assert_eq!(outcome.exit_code(), 4);
        assert_no_recovery_code(&output);
    }

    #[test]
    fn enroll_that_never_commits_does_not_provision() {
        let mut client = FakeClient { progress: vec![progress("failed", 1)], ..Default::default() };
        let mut keys = FakeKeys::default();
        run_with(&mut client, &mut keys, Command::Enroll { uid: 1000 });
        assert!(keys.calls.is_empty());
    }

    // @spec:AC-058
    #[test]
    fn set_pin_is_not_a_command_any_more_and_the_usage_does_not_mention_it() {
        assert!(parse_args(args(&["set-pin"]), 1000).is_err());
        assert!(!USAGE.contains("set-pin"));
    }

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // @spec:AC-060
    #[test]
    fn enroll_prints_one_original_intro_line_before_capturing() {
        let mut client = FakeClient { progress: vec![progress("failed", 0)], ..Default::default() };
        let (_, output) = run_command(&mut client, Command::Enroll { uid: 1000 });
        let intro = "Face the camera and keep your face centered. The prompts tell you whether to move closer or back";
        assert_eq!(output.lines().next(), Some(intro));
        assert_eq!(output.matches(intro).count(), 1);
        assert!(!output.contains("look straight at the camera"));
    }

    // @spec:AC-060
    #[test]
    fn enroll_guidance_uses_the_approved_sentences() {
        let deck = [
            ("accepted", "Hold still and look at the camera"),
            ("too-soon", "Hold still and look at the camera"),
            ("no-face", "No face found. Center your face in the oval"),
            ("move-left", "Move a little to your left"),
            ("move-right", "Move a little to your right"),
            ("move-up", "Move up a little"),
            ("move-down", "Move down a little"),
            ("too-close", "Too close. Move back a little"),
            ("too-far", "Too far. Move a little closer"),
            ("too-dark", "Not enough light on your face"),
            ("too-bright", "Too much light. Avoid glare in front of or behind you"),
            ("yaw-out-of-range", "Face the camera straight on"),
            ("blurred", "Hold still. The image is blurry"),
            ("occluded", "Something is covering your face. Clear it from view"),
        ];
        for (verdict, sentence) in deck {
            assert_eq!(enroll_guidance(verdict), sentence, "{verdict}");
        }
    }

    #[test]
    fn enroll_captures_until_complete_then_commits() {
        let mut client = FakeClient { progress: vec![progress("in-progress", 2), progress("in-progress", 5), progress("complete", 6)], ..Default::default() };
        let (outcome, output) = run_command(&mut client, Command::Enroll { uid: 1000 });
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(client.calls, vec!["begin 1000", "capture h1", "capture h1", "capture h1", "commit h1"]);
        assert!(output.contains("(33%)") && output.contains("(83%)") && output.contains("(100%)") && output.contains("enrolled uid 1000"));
        assert!(!output.contains("samples"));
    }

    // @spec:AC-053
    #[test]
    fn enroll_tells_the_user_where_to_move_and_does_not_repeat_the_same_line() {
        let guided = |verdict: &str| Progress { verdict: verdict.into(), state: "in-progress".into(), filled: 0, required: 6 };
        let mut client = FakeClient {
            progress: vec![guided("move-left"), guided("move-left"), guided("too-far"), guided("no-face"), progress("failed", 0)],
            ..Default::default()
        };
        let (_, output) = run_command(&mut client, Command::Enroll { uid: 1000 });
        assert_eq!(output.matches("Move a little to your left").count(), 1);
        assert!(output.contains("Too far. Move a little closer") && output.contains("No face found"));
        let verdicts = ["move-right", "move-up", "move-down", "too-close", "yaw-out-of-range", "blurred", "occluded", "accepted", "too-dark", "too-bright"];
        assert!(verdicts.iter().all(|v| enroll_guidance(v) != *v));
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
        assert_eq!(parse_args(args(&["provision", "--uid", "1001"]), 1000).unwrap().command, Command::Provision { uid: 1001 });

        for bad in [vec![], vec!["dance"], vec!["verify", "--uid", "-1"], vec!["--bus", "mars", "verify"], vec!["identify", "--uid", "5"], vec!["verify", "extra"], vec!["--uid"]] {
            assert!(parse_args(args(&bad), 1000).is_err(), "{bad:?}");
        }
    }
}
