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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerReader {
    pub present: bool,
    pub enrolled: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerProgress {
    pub status: String,
    pub state: String,
    pub passed: u32,
    pub total: u32,
}

pub trait BiometricsClient {
    fn enroll_begin(&mut self, uid: u32) -> Result<String, String>;
    fn enroll_capture(&mut self, handle: &str) -> Result<Progress, String>;
    fn enroll_commit(&mut self, handle: &str) -> Result<(), String>;
    fn enroll_discard(&mut self, handle: &str) -> Result<(), String>;
    fn finger_status(&mut self, uid: u32) -> Result<FingerReader, String>;
    fn finger_enroll_begin(&mut self, uid: u32, finger: &str) -> Result<String, String>;
    fn finger_enroll_next(&mut self, handle: &str) -> Result<FingerProgress, String>;
    fn finger_enroll_discard(&mut self, handle: &str) -> Result<(), String>;
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

pub trait Answers {
    fn ask(&mut self, question: &str) -> Result<String, String>;
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
    pub answers: &'a mut dyn Answers,
}

pub fn execute(services: &mut Services, command: Command, out: &mut dyn Write) -> Outcome {
    match run(services, command, out) {
        Ok(outcome) => outcome,
        Err(problem) => Outcome::Failed(problem),
    }
}

fn run(services: &mut Services, command: Command, out: &mut dyn Write) -> Result<Outcome, String> {
    let Services { biometrics: client, keys, pins, answers } = services;
    let mut say = |line: String| writeln!(out, "{line}").map_err(|e| format!("cannot write output: {e}"));
    match command {
        Command::Enroll { uid } => enroll(*client, *keys, *answers, uid, &mut say),
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
    answers: &mut dyn Answers,
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
                finger_step(client, answers, uid, say)?;
                return provision(keys, uid, &enrolled_failure(uid), say);
            }
            "failed" => return Err("enrollment failed: timed out without covering every pose".into()),
            _ => {}
        }
    }
    client.enroll_discard(&handle)?;
    Err(format!("enrollment abandoned after {MAX_CAPTURES} captures without covering every pose"))
}

const FINGERS: [&str; 10] = [
    "left-thumb",
    "left-index-finger",
    "left-middle-finger",
    "left-ring-finger",
    "left-little-finger",
    "right-thumb",
    "right-index-finger",
    "right-middle-finger",
    "right-ring-finger",
    "right-little-finger",
];
const DEFAULT_FINGER: &str = "right-index-finger";
const MAX_FINGER_OFFERS: u32 = 30;
const MAX_FINGER_STEPS: u32 = 200;
const MAX_FINGER_CHOICES: u32 = 3;

type Say<'a> = &'a mut dyn FnMut(String) -> Result<(), String>;

fn finger_label(finger: &str) -> String {
    finger.replace('-', " ")
}

fn finger_step(client: &mut dyn BiometricsClient, answers: &mut dyn Answers, uid: u32, say: Say) -> Result<(), String> {
    let reader = match client.finger_status(uid) {
        Ok(reader) => reader,
        Err(_) => return say("the fingerprint reader could not be checked, so no finger was offered".to_string()),
    };
    if !reader.present {
        return say("no fingerprint reader was found, so only the face was enrolled".to_string());
    }
    let mut enrolled = reader.enrolled;
    let mut first = true;
    for _ in 0..MAX_FINGER_OFFERS {
        let remaining: Vec<&str> = FINGERS.iter().copied().filter(|finger| !enrolled.iter().any(|done| done == finger)).collect();
        if remaining.is_empty() {
            return say("all ten fingers are already enrolled".to_string());
        }
        let question = if first { "Add a fingerprint now? [Y/n] " } else { "Add another finger? [y/N] " };
        if !confirm(answers, question, first) {
            return Ok(());
        }
        let Some(finger) = choose_finger(answers, &remaining, say)? else { return Ok(()) };
        if enroll_finger(client, uid, finger, say)? {
            enrolled.push(finger.to_string());
            first = false;
        }
    }
    Ok(())
}

fn confirm(answers: &mut dyn Answers, question: &str, default: bool) -> bool {
    match answers.ask(question) {
        Ok(reply) => match reply.trim().to_lowercase().as_str() {
            "" => default,
            "y" | "yes" => true,
            _ => false,
        },
        Err(_) => false,
    }
}

fn choose_finger(answers: &mut dyn Answers, remaining: &[&'static str], say: Say) -> Result<Option<&'static str>, String> {
    let default = if remaining.contains(&DEFAULT_FINGER) { DEFAULT_FINGER } else { remaining[0] };
    let default_number = FINGERS.iter().position(|finger| *finger == default).map_or(1, |index| index + 1);
    say("Which finger do you want to add?".to_string())?;
    for (index, finger) in FINGERS.iter().enumerate().filter(|(_, finger)| remaining.contains(finger)) {
        say(format!("  {}  {}", index + 1, finger_label(finger)))?;
    }
    for _ in 0..MAX_FINGER_CHOICES {
        let Ok(reply) = answers.ask(&format!("Finger number [{default_number}]: ")) else { break };
        let reply = reply.trim().to_lowercase();
        let chosen = if reply.is_empty() {
            Some(default)
        } else if let Ok(number) = reply.parse::<usize>() {
            FINGERS.get(number.wrapping_sub(1)).copied()
        } else {
            FINGERS.iter().copied().find(|finger| *finger == reply || finger_label(finger) == reply)
        };
        match chosen.filter(|finger| remaining.contains(finger)) {
            Some(finger) => return Ok(Some(finger)),
            None => say("that is not one of the fingers listed above".to_string())?,
        }
    }
    say("no finger was chosen".to_string())?;
    Ok(None)
}

fn enroll_finger(client: &mut dyn BiometricsClient, uid: u32, finger: &str, say: Say) -> Result<bool, String> {
    let label = finger_label(finger);
    let handle = match client.finger_enroll_begin(uid, finger) {
        Ok(handle) => handle,
        Err(problem) => {
            say(format!("the {label} could not be enrolled: {problem}"))?;
            return Ok(false);
        }
    };
    say(format!("place your {label} on the reader, lift it, and place it again until it is done"))?;
    for _ in 0..MAX_FINGER_STEPS {
        let progress = match client.finger_enroll_next(&handle) {
            Ok(progress) => progress,
            Err(problem) => {
                let _ = client.finger_enroll_discard(&handle);
                say(format!("the {label} could not be enrolled: {problem}; fingers enrolled earlier were not changed"))?;
                return Ok(false);
            }
        };
        say(describe_finger_step(&progress))?;
        match progress.state.as_str() {
            "complete" => {
                say(format!("enrolled the {label}"))?;
                return Ok(true);
            }
            "failed" => {
                say("the finger was not saved; fingers enrolled earlier were not changed".to_string())?;
                return Ok(false);
            }
            _ => {}
        }
    }
    let _ = client.finger_enroll_discard(&handle);
    say(format!("the {label} was not saved after too many attempts; fingers enrolled earlier were not changed"))?;
    Ok(false)
}

fn describe_finger_step(progress: &FingerProgress) -> String {
    let stage = format!("stage {} of {}", progress.passed, progress.total);
    match progress.status.as_str() {
        "stage-passed" => format!("{stage} done, lift your finger and place it again"),
        "completed" => format!("{stage} done"),
        "retry-scan" => "the reader could not read that touch, try again".to_string(),
        "swipe-too-short" => "the swipe was too short, try again".to_string(),
        "finger-not-centered" => "center your finger on the reader and try again".to_string(),
        "remove-and-retry" => "lift your finger, then place it on the reader again".to_string(),
        "failed" => "the reader could not complete the enrollment".to_string(),
        "data-full" => "the reader has no space left for more fingerprints".to_string(),
        "disconnected" => "the reader was disconnected".to_string(),
        "cancelled" => "the enrollment was cancelled".to_string(),
        _ => "the reader reported an error".to_string(),
    }
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
        reader: Option<Vec<&'static str>>,
        reader_check_fails: bool,
        finger_steps: Vec<FingerProgress>,
        finger_step_fails: bool,
        finger_begin_fails: bool,
    }

    fn finger_progress(status: &str, state: &str, passed: u32) -> FingerProgress {
        FingerProgress { status: status.into(), state: state.into(), passed, total: 5 }
    }

    fn five_stages() -> Vec<FingerProgress> {
        let mut steps: Vec<FingerProgress> = (1..5).map(|n| finger_progress("stage-passed", "in-progress", n)).collect();
        steps.push(finger_progress("completed", "complete", 5));
        steps
    }

    struct Replies(Vec<&'static str>, Vec<String>);

    impl Answers for Replies {
        fn ask(&mut self, question: &str) -> Result<String, String> {
            self.1.push(question.to_string());
            if self.0.is_empty() {
                return Err("no more answers".into());
            }
            Ok(self.0.remove(0).to_string())
        }
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

        fn finger_status(&mut self, uid: u32) -> Result<FingerReader, String> {
            self.calls.push(format!("finger-status {uid}"));
            if self.reader_check_fails {
                return Err("FingerStatus refused".into());
            }
            Ok(match &self.reader {
                Some(enrolled) => FingerReader { present: true, enrolled: enrolled.iter().map(|f| f.to_string()).collect() },
                None => FingerReader { present: false, enrolled: Vec::new() },
            })
        }

        fn finger_enroll_begin(&mut self, uid: u32, finger: &str) -> Result<String, String> {
            self.calls.push(format!("finger-begin {uid} {finger}"));
            if self.finger_begin_fails {
                return Err("FingerEnrollBegin refused".into());
            }
            Ok("f1".into())
        }

        fn finger_enroll_next(&mut self, handle: &str) -> Result<FingerProgress, String> {
            self.calls.push(format!("finger-next {handle}"));
            if self.finger_step_fails {
                return Err("the reader went away".into());
            }
            Ok(if self.finger_steps.is_empty() { finger_progress("retry-scan", "in-progress", 0) } else { self.finger_steps.remove(0) })
        }

        fn finger_enroll_discard(&mut self, handle: &str) -> Result<(), String> {
            self.calls.push(format!("finger-discard {handle}"));
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
        run_asked(client, keys, pins, &mut Replies(vec![], vec![]), command)
    }

    fn run_asked(client: &mut FakeClient, keys: &mut FakeKeys, pins: &mut TypedPins, answers: &mut Replies, command: Command) -> (Outcome, String) {
        let mut out = Vec::new();
        let mut services = Services { biometrics: client, keys, pins, answers };
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
        assert_eq!(client.calls[client.calls.len() - 2..], ["commit h1", "finger-status 1000"]);
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

    fn enroll_with_a_reader(client: &mut FakeClient, replies: Vec<&'static str>) -> (Outcome, String, FakeKeys, Replies) {
        let mut keys = FakeKeys::default();
        let mut answers = Replies(replies, vec![]);
        let (outcome, output) = run_asked(client, &mut keys, &mut TypedPins(vec![]), &mut answers, Command::Enroll { uid: 1000 });
        (outcome, output, keys, answers)
    }

    fn reader_client(enrolled: Vec<&'static str>) -> FakeClient {
        FakeClient { progress: vec![progress("complete", 6)], reader: Some(enrolled), finger_steps: five_stages(), ..Default::default() }
    }

    fn finger_calls(client: &FakeClient) -> Vec<&str> {
        client.calls.iter().filter(|c| c.starts_with("finger-")).map(String::as_str).collect()
    }

    // @spec:AC-057
    #[test]
    fn without_a_reader_the_face_is_enrolled_and_one_plain_line_says_no_reader_was_found() {
        let mut client = FakeClient { progress: vec![progress("complete", 6)], ..Default::default() };
        let (outcome, output, keys, answers) = enroll_with_a_reader(&mut client, vec!["", ""]);
        assert_eq!(outcome, Outcome::Success);
        assert!(output.contains("enrolled uid 1000"));
        assert_eq!(output.lines().filter(|line| line.contains("no fingerprint reader was found")).count(), 1, "{output}");
        assert_eq!(finger_calls(&client), vec!["finger-status 1000"]);
        assert!(answers.1.is_empty(), "the finger step must not be offered");
        assert_eq!(keys.calls, vec!["provision 1000"]);
        assert!(output.contains(RECOVERY_CODE));
    }

    // @spec:AC-057
    #[test]
    fn a_reader_that_cannot_be_checked_skips_the_finger_step_with_one_line_and_still_provisions() {
        let mut client = FakeClient { progress: vec![progress("complete", 6)], reader_check_fails: true, ..Default::default() };
        let (outcome, output, keys, answers) = enroll_with_a_reader(&mut client, vec![""]);
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(output.lines().filter(|line| line.contains("could not be checked")).count(), 1, "{output}");
        assert!(!output.contains("FingerStatus"));
        assert!(answers.1.is_empty());
        assert_eq!(keys.calls, vec!["provision 1000"]);
    }

    // @spec:AC-057
    #[test]
    fn a_failed_face_enrollment_never_reaches_the_finger_step() {
        let mut client = FakeClient { progress: vec![progress("failed", 1)], reader: Some(vec![]), ..Default::default() };
        let (outcome, _, _, answers) = enroll_with_a_reader(&mut client, vec![""]);
        assert!(matches!(outcome, Outcome::Failed(_)));
        assert!(finger_calls(&client).is_empty());
        assert!(answers.1.is_empty());
    }

    // @spec:AC-055
    #[test]
    fn a_finger_is_added_after_the_face_with_five_stage_lines_and_the_key_is_provisioned_after() {
        let mut client = reader_client(vec![]);
        let (outcome, output, keys, answers) = enroll_with_a_reader(&mut client, vec!["", "", "n"]);
        assert_eq!(outcome, Outcome::Success, "{output}");
        let commit = client.calls.iter().position(|c| c == "commit h1").unwrap();
        let begin = client.calls.iter().position(|c| c == "finger-begin 1000 right-index-finger").unwrap();
        assert!(commit < begin);
        assert_eq!(finger_calls(&client).iter().filter(|c| c.starts_with("finger-next")).count(), 5);
        for stage in 1..=5 {
            assert!(output.contains(&format!("stage {stage} of 5 done")), "{output}");
        }
        assert!(output.contains("enrolled the right index finger"));
        assert_eq!(keys.calls, vec!["provision 1000"]);
        assert_eq!(output.lines().last().unwrap(), RECOVERY_CODE);
        assert_eq!(answers.1, vec!["Add a fingerprint now? [Y/n] ", "Finger number [7]: ", "Add another finger? [y/N] "]);
    }

    // @spec:AC-055
    #[test]
    fn several_fingers_are_added_in_one_run_and_an_enrolled_finger_is_never_offered_again() {
        let mut client = reader_client(vec!["left-thumb"]);
        client.finger_steps = [five_stages(), five_stages()].concat();
        let (outcome, output, _, _) = enroll_with_a_reader(&mut client, vec!["y", "left index finger", "y", "", "n"]);
        assert_eq!(outcome, Outcome::Success, "{output}");
        let begins: Vec<&str> = client.calls.iter().filter(|c| c.starts_with("finger-begin")).map(String::as_str).collect();
        assert_eq!(begins, vec!["finger-begin 1000 left-index-finger", "finger-begin 1000 right-index-finger"]);
        let listed_after_first: Vec<&str> = output.lines().filter(|line| line.starts_with("  ")).collect();
        assert!(!listed_after_first[..9].iter().any(|line| line.contains("left thumb")), "{listed_after_first:?}");
        assert!(!listed_after_first[9..].iter().any(|line| line.contains("left thumb") || line.contains("left index")), "{listed_after_first:?}");
    }

    // @spec:AC-055
    #[test]
    fn an_already_enrolled_finger_cannot_be_chosen_and_the_default_moves_to_a_free_finger() {
        let mut client = reader_client(vec!["right-index-finger"]);
        let (outcome, output, _, answers) = enroll_with_a_reader(&mut client, vec!["", "7", "7", "7"]);
        assert_eq!(outcome, Outcome::Success);
        assert!(finger_calls(&client).iter().all(|c| !c.starts_with("finger-begin")), "{:?}", client.calls);
        assert_eq!(answers.1[1], "Finger number [1]: ");
        assert_eq!(output.matches("that is not one of the fingers listed above").count(), 3);
        assert!(output.contains("no finger was chosen"));
    }

    // @spec:AC-055
    #[test]
    fn declining_or_having_no_terminal_adds_no_finger_and_still_provisions() {
        for replies in [vec!["n"], vec!["no"], vec!["maybe"], vec![]] {
            let mut client = reader_client(vec![]);
            let (outcome, _, keys, _) = enroll_with_a_reader(&mut client, replies.clone());
            assert_eq!(outcome, Outcome::Success, "{replies:?}");
            assert!(finger_calls(&client).iter().all(|c| !c.starts_with("finger-begin")), "{replies:?}");
            assert_eq!(keys.calls, vec!["provision 1000"]);
        }
    }

    // @spec:AC-055
    #[test]
    fn all_ten_fingers_enrolled_ends_the_step_with_one_line() {
        let all = FINGERS.to_vec();
        let mut client = reader_client(all);
        let (outcome, output, _, answers) = enroll_with_a_reader(&mut client, vec![""]);
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(output.matches("all ten fingers are already enrolled").count(), 1);
        assert!(answers.1.is_empty());
    }

    // @spec:AC-055
    #[test]
    fn retries_are_explained_and_a_failed_finger_leaves_the_face_enrolled_and_the_key_provisioned() {
        let mut client = reader_client(vec![]);
        client.finger_steps = vec![
            finger_progress("stage-passed", "in-progress", 1),
            finger_progress("retry-scan", "in-progress", 1),
            finger_progress("swipe-too-short", "in-progress", 1),
            finger_progress("finger-not-centered", "in-progress", 1),
            finger_progress("remove-and-retry", "in-progress", 1),
            finger_progress("failed", "failed", 1),
        ];
        let (outcome, output, keys, _) = enroll_with_a_reader(&mut client, vec!["", "", "n"]);
        assert_eq!(outcome, Outcome::Success, "{output}");
        for line in ["stage 1 of 5 done", "could not read that touch", "swipe was too short", "center your finger", "lift your finger, then place it", "could not complete the enrollment", "enrolled earlier were not changed"] {
            assert!(output.contains(line), "{line}: {output}");
        }
        assert!(!output.contains("enrolled the right"));
        assert_eq!(keys.calls, vec!["provision 1000"]);
    }

    // @spec:AC-055
    #[test]
    fn reader_error_statuses_are_described_in_plain_words() {
        for (status, words) in [("data-full", "no space left"), ("disconnected", "disconnected"), ("unknown-error", "reported an error"), ("cancelled", "cancelled")] {
            let mut client = reader_client(vec![]);
            client.finger_steps = vec![finger_progress(status, "failed", 0)];
            let (_, output, _, _) = enroll_with_a_reader(&mut client, vec!["", "", "n"]);
            assert!(output.contains(words), "{status}: {output}");
        }
    }

    // @spec:AC-055
    #[test]
    fn a_refused_start_or_a_broken_wait_is_reported_without_failing_the_enrollment() {
        let mut client = reader_client(vec![]);
        client.finger_begin_fails = true;
        let (outcome, output, keys, _) = enroll_with_a_reader(&mut client, vec!["", "", "n"]);
        assert_eq!(outcome, Outcome::Success);
        assert!(output.contains("could not be enrolled: FingerEnrollBegin refused"));
        assert_eq!(keys.calls, vec!["provision 1000"]);

        let mut client = reader_client(vec![]);
        client.finger_step_fails = true;
        let (outcome, output, _, _) = enroll_with_a_reader(&mut client, vec!["", "", "n"]);
        assert_eq!(outcome, Outcome::Success);
        assert!(output.contains("the reader went away"));
        assert!(client.calls.contains(&"finger-discard f1".to_string()));
    }

    // @spec:AC-055
    #[test]
    fn a_finger_that_never_finishes_is_discarded_after_the_step_budget() {
        let mut client = reader_client(vec![]);
        client.finger_steps = vec![];
        let (outcome, output, _, _) = enroll_with_a_reader(&mut client, vec!["", "", "n"]);
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(finger_calls(&client).iter().filter(|c| c.starts_with("finger-next")).count(), MAX_FINGER_STEPS as usize);
        assert!(client.calls.contains(&"finger-discard f1".to_string()));
        assert!(output.contains("too many attempts"));
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
        assert_eq!(client.calls, vec!["begin 1000", "capture h1", "capture h1", "capture h1", "commit h1", "finger-status 1000"]);
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
