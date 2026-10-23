use std::io::Write;
use std::path::Path;

use pam_enable::{fingerprint_login, FingerprintLogin};

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

pub const ALREADY_PROVISIONED: &str = "this user already has a login key";

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
    EnrollFinger { uid: u32 },
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

pub const USAGE: &str = "usage: openhello-cli [--bus system|session] <enroll [face|finger]|verify|purge|set-pin|provision> [--uid N] | identify (`enroll` alone means `enroll face`)";

pub fn parse_args(args: impl IntoIterator<Item = String>, current_uid: u32) -> Result<Invocation, String> {
    let mut bus = Bus::System;
    let mut uid = None;
    let mut command_name = None;
    let mut modality = None;
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
            name if command_name.as_deref() == Some("enroll") && modality.is_none() && !name.starts_with("--") => modality = Some(arg),
            other => return Err(format!("unexpected argument `{other}`")),
        }
    }
    let uid_or_current = uid.unwrap_or(current_uid);
    let command = match command_name.as_deref() {
        Some("enroll") => match modality.as_deref() {
            None | Some("face") => Command::Enroll { uid: uid_or_current },
            Some("finger") => Command::EnrollFinger { uid: uid_or_current },
            Some(other) => return Err(format!("unknown enrollment `{other}`, use `enroll face` or `enroll finger`")),
        },
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
    pub pam_root: &'a Path,
}

pub fn execute(services: &mut Services, command: Command, out: &mut dyn Write) -> Outcome {
    match run(services, command, out) {
        Ok(outcome) => outcome,
        Err(problem) => Outcome::Failed(problem),
    }
}

fn run(services: &mut Services, command: Command, out: &mut dyn Write) -> Result<Outcome, String> {
    let Services { biometrics: client, keys, pins, answers, pam_root } = services;
    let mut say = |line: String| writeln!(out, "{line}").map_err(|e| format!("cannot write output: {e}"));
    match command {
        Command::Enroll { uid } => enroll(*client, *keys, uid, &mut say),
        Command::EnrollFinger { uid } => enroll_finger_command(*client, *keys, *answers, pam_root, uid, &mut say),
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

fn enroll_finger_command(
    client: &mut dyn BiometricsClient,
    keys: &mut dyn KeyClient,
    answers: &mut dyn Answers,
    pam_root: &Path,
    uid: u32,
    say: Say,
) -> Result<Outcome, String> {
    let reader = client.finger_status(uid).map_err(|_| "the fingerprint reader could not be checked; nothing was changed".to_string())?;
    if !reader.present {
        say("no fingerprint reader was found; nothing was changed".to_string())?;
        return Ok(Outcome::Success);
    }
    let mut enrolled = reader.enrolled;
    let mut first = true;
    let mut added = 0;
    for _ in 0..MAX_FINGER_OFFERS {
        let remaining: Vec<&str> = FINGERS.iter().copied().filter(|finger| !enrolled.iter().any(|done| done == finger)).collect();
        if remaining.is_empty() {
            say("all ten fingers are already enrolled".to_string())?;
            break;
        }
        if !first && !confirm(answers, "Add another finger? [y/N] ", false) {
            break;
        }
        let Some(finger) = choose_finger(answers, &remaining, say)? else { break };
        if enroll_finger(client, uid, finger, say)? {
            enrolled.push(finger.to_string());
            added += 1;
            first = false;
        }
    }
    if enrolled.is_empty() {
        return Ok(Outcome::Success);
    }
    if added > 0 {
        say(fingerprint_login_line(fingerprint_login(pam_root)).to_string())?;
    }
    match provision(keys, uid, &finger_failure(uid), say) {
        Ok(Outcome::ProvisionFailed(failure)) if failure == ALREADY_PROVISIONED => Ok(Outcome::Success),
        other => other,
    }
}

fn fingerprint_login_line(state: FingerprintLogin) -> &'static str {
    match state {
        FingerprintLogin::On => "the system's fingerprint login is on: your enrolled finger can be used where the system asks for it",
        FingerprintLogin::Off => "the system's fingerprint login is not on, so your finger is not asked for yet; an administrator switches it on with `sudo openhello-cli pam enable`",
        FingerprintLogin::Unknown => "could not check whether the system's fingerprint login is on; an administrator can switch it on with `sudo openhello-cli pam enable`",
    }
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

fn finger_failure(uid: u32) -> String {
    format!("the fingers of uid {uid} were enrolled and kept, but the login key could not be created, so sudo finger login will not work yet; run `openhello-cli provision` from the desktop session (no new enrollment needed) and check the openhello-keyd service log")
}

fn provision(keys: &mut dyn KeyClient, uid: u32, failure: &str, say: &mut dyn FnMut(String) -> Result<(), String>) -> Result<Outcome, String> {
    match keys.provision(uid) {
        Ok(code) => {
            say("recovery code (shown only now, store it safely; it unlocks the key if the PIN is lost):".to_string())?;
            say(code)?;
            Ok(Outcome::Success)
        }
        Err(problem) if problem == ALREADY_PROVISIONED => Ok(Outcome::ProvisionFailed(problem)),
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

    const NO_PAM_ROOT: &str = "/nonexistent-pam-root";

    fn run_asked(client: &mut FakeClient, keys: &mut FakeKeys, pins: &mut TypedPins, answers: &mut Replies, command: Command) -> (Outcome, String) {
        run_asked_in(Path::new(NO_PAM_ROOT), client, keys, pins, answers, command)
    }

    fn run_asked_in(pam_root: &Path, client: &mut FakeClient, keys: &mut FakeKeys, pins: &mut TypedPins, answers: &mut Replies, command: Command) -> (Outcome, String) {
        let mut out = Vec::new();
        let mut services = Services { biometrics: client, keys, pins, answers, pam_root };
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
        assert_eq!(client.calls[client.calls.len() - 2..], ["capture h1", "commit h1"]);
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

    fn enroll_finger_with(client: &mut FakeClient, keys: &mut FakeKeys, replies: Vec<&'static str>) -> (Outcome, String, Replies) {
        let mut answers = Replies(replies, vec![]);
        let (outcome, output) = run_asked(client, keys, &mut TypedPins(vec![]), &mut answers, Command::EnrollFinger { uid: 1000 });
        (outcome, output, answers)
    }

    fn finger_run(client: &mut FakeClient, replies: Vec<&'static str>) -> (Outcome, String, FakeKeys, Replies) {
        let mut keys = FakeKeys::default();
        let (outcome, output, answers) = enroll_finger_with(client, &mut keys, replies);
        (outcome, output, keys, answers)
    }

    fn reader_client(enrolled: Vec<&'static str>) -> FakeClient {
        FakeClient { reader: Some(enrolled), finger_steps: five_stages(), ..Default::default() }
    }

    fn finger_calls(client: &FakeClient) -> Vec<&str> {
        client.calls.iter().filter(|c| c.starts_with("finger-")).map(String::as_str).collect()
    }

    // @spec:AC-060
    #[test]
    fn enroll_face_never_touches_the_reader_and_enroll_finger_never_touches_the_camera() {
        let mut client = reader_client(vec![]);
        client.progress = vec![progress("complete", 6)];
        let mut answers = Replies(vec![], vec![]);
        let (outcome, _) = run_asked(&mut client, &mut FakeKeys::default(), &mut TypedPins(vec![]), &mut answers, Command::Enroll { uid: 1000 });
        assert_eq!(outcome, Outcome::Success);
        assert!(client.calls.contains(&"commit h1".to_string()));
        assert!(client.calls.iter().all(|c| !c.starts_with("finger-")), "{:?}", client.calls);
        assert!(answers.1.is_empty());

        let mut client = reader_client(vec![]);
        let (outcome, _, _, _) = finger_run(&mut client, vec!["", "n"]);
        assert_eq!(outcome, Outcome::Success);
        let camera = ["begin", "capture", "commit", "discard"];
        assert!(client.calls.iter().all(|c| !camera.iter().any(|name| c.starts_with(name))), "{:?}", client.calls);
        assert!(client.calls.contains(&"finger-begin 1000 right-index-finger".to_string()));
    }

    // @spec:AC-060
    #[test]
    fn enroll_face_with_a_reader_present_makes_no_finger_call_and_asks_nothing() {
        let mut client = FakeClient { progress: vec![progress("complete", 6)], reader: Some(vec![]), ..Default::default() };
        let mut keys = FakeKeys::default();
        let mut answers = Replies(vec!["", ""], vec![]);
        let (outcome, output) = run_asked(&mut client, &mut keys, &mut TypedPins(vec![]), &mut answers, Command::Enroll { uid: 1000 });
        assert_eq!(outcome, Outcome::Success, "{output}");
        assert!(output.contains("enrolled uid 1000") && !output.contains("finger"));
        assert!(finger_calls(&client).is_empty() && !client.calls.iter().any(|c| c.starts_with("finger-status")));
        assert!(answers.1.is_empty());
        assert_eq!(keys.calls, vec!["provision 1000"]);
    }

    // @spec:AC-057
    #[test]
    fn without_a_reader_one_plain_line_says_so_and_nothing_is_enrolled_or_provisioned() {
        let mut client = FakeClient::default();
        let (outcome, output, keys, answers) = finger_run(&mut client, vec!["", ""]);
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(outcome.exit_code(), 0);
        assert_eq!(output.lines().filter(|line| line.contains("no fingerprint reader was found")).count(), 1, "{output}");
        assert_eq!(output.lines().count(), 1);
        assert_eq!(client.calls, vec!["finger-status 1000"]);
        assert!(answers.1.is_empty());
        assert!(keys.calls.is_empty());
    }

    // @spec:AC-057
    #[test]
    fn a_reader_that_cannot_be_checked_fails_without_changing_anything() {
        let mut client = FakeClient { reader_check_fails: true, ..Default::default() };
        let (outcome, output, keys, _) = finger_run(&mut client, vec![""]);
        assert!(matches!(&outcome, Outcome::Failed(m) if m.contains("could not be checked") && !m.contains("FingerStatus")), "{outcome:?}");
        assert_eq!(outcome.exit_code(), 3);
        assert!(output.is_empty());
        assert_eq!(client.calls, vec!["finger-status 1000"]);
        assert!(keys.calls.is_empty());
    }

    // @spec:AC-055
    #[test]
    fn a_finger_is_added_with_five_stage_lines_and_the_key_is_provisioned_after() {
        let mut client = reader_client(vec![]);
        let (outcome, output, keys, answers) = finger_run(&mut client, vec!["", "n"]);
        assert_eq!(outcome, Outcome::Success, "{output}");
        assert_eq!(finger_calls(&client).iter().filter(|c| c.starts_with("finger-next")).count(), 5);
        for stage in 1..=5 {
            assert!(output.contains(&format!("stage {stage} of 5 done")), "{output}");
        }
        assert!(output.contains("enrolled the right index finger"));
        assert_eq!(keys.calls, vec!["provision 1000"]);
        assert_eq!(output.lines().last().unwrap(), RECOVERY_CODE);
        assert_eq!(answers.1, vec!["Finger number [7]: ", "Add another finger? [y/N] "]);
    }

    // @spec:AC-060
    #[test]
    fn a_user_with_only_a_finger_and_no_face_gets_the_key_after_the_first_finger() {
        let mut client = reader_client(vec![]);
        let (outcome, output, keys, _) = finger_run(&mut client, vec!["", "n"]);
        assert_eq!(outcome, Outcome::Success);
        let provision_at = keys.calls.iter().position(|c| c == "provision 1000").unwrap();
        assert_eq!(provision_at, 0);
        assert!(output.contains(RECOVERY_CODE));
        assert!(!client.calls.iter().any(|c| c.starts_with("begin") || c.starts_with("capture")));
    }

    // @spec:AC-055
    #[test]
    fn a_user_who_already_has_the_key_gets_no_error_and_no_duplicate() {
        struct HasKey(Vec<String>);
        impl KeyClient for HasKey {
            fn provision(&mut self, uid: u32) -> Result<String, String> {
                self.0.push(format!("provision {uid}"));
                Err(ALREADY_PROVISIONED.into())
            }
            fn set_pin(&mut self, _: u32, _: &str) -> Result<(), String> {
                Ok(())
            }
        }
        let mut client = reader_client(vec![]);
        let mut keys = HasKey(vec![]);
        let mut out = Vec::new();
        let mut services = Services { biometrics: &mut client, keys: &mut keys, pins: &mut TypedPins(vec![]), answers: &mut Replies(vec!["", "n"], vec![]), pam_root: Path::new(NO_PAM_ROOT) };
        let outcome = execute(&mut services, Command::EnrollFinger { uid: 1000 }, &mut out);
        let output = String::from_utf8(out).unwrap();
        assert_eq!(outcome, Outcome::Success, "{output}");
        assert!(output.contains("enrolled the right index finger") && !output.contains("recovery"));
        assert_eq!(keys.0, vec!["provision 1000"]);
    }

    // @spec:AC-055
    #[test]
    fn a_key_failure_after_a_finger_keeps_the_finger_and_reports_exit_four() {
        let mut client = reader_client(vec![]);
        let mut keys = FakeKeys { provision_fails: true, ..Default::default() };
        let (outcome, output, _) = enroll_finger_with(&mut client, &mut keys, vec!["", "n"]);
        assert!(matches!(&outcome, Outcome::ProvisionFailed(m) if m.contains("fingers of uid 1000 were enrolled and kept") && !m.contains("Keyd1")), "{outcome:?}");
        assert_eq!(outcome.exit_code(), 4);
        assert!(output.contains("enrolled the right index finger") && !output.contains(RECOVERY_CODE));
    }

    // @spec:AC-055
    #[test]
    fn several_fingers_are_added_in_one_run_and_an_enrolled_finger_is_never_offered_again() {
        let mut client = reader_client(vec!["left-thumb"]);
        client.finger_steps = [five_stages(), five_stages()].concat();
        let (outcome, output, keys, _) = finger_run(&mut client, vec!["left index finger", "y", "", "n"]);
        assert_eq!(outcome, Outcome::Success, "{output}");
        let begins: Vec<&str> = client.calls.iter().filter(|c| c.starts_with("finger-begin")).map(String::as_str).collect();
        assert_eq!(begins, vec!["finger-begin 1000 left-index-finger", "finger-begin 1000 right-index-finger"]);
        let listed: Vec<&str> = output.lines().filter(|line| line.starts_with("  ")).collect();
        assert!(!listed[..9].iter().any(|line| line.contains("left thumb")), "{listed:?}");
        assert!(!listed[9..].iter().any(|line| line.contains("left thumb") || line.contains("left index")), "{listed:?}");
        assert_eq!(keys.calls, vec!["provision 1000"]);
    }

    // @spec:AC-055
    #[test]
    fn an_already_enrolled_finger_cannot_be_chosen_and_the_default_moves_to_a_free_finger() {
        let mut client = reader_client(vec!["right-index-finger"]);
        let (outcome, output, _, answers) = finger_run(&mut client, vec!["7", "7", "7"]);
        assert_eq!(outcome, Outcome::Success);
        assert!(finger_calls(&client).iter().all(|c| !c.starts_with("finger-begin")), "{:?}", client.calls);
        assert_eq!(answers.1[0], "Finger number [1]: ");
        assert_eq!(output.matches("that is not one of the fingers listed above").count(), 3);
        assert!(output.contains("no finger was chosen"));
    }

    // @spec:AC-055
    #[test]
    fn having_no_terminal_adds_no_finger_and_provisions_nothing_for_a_user_without_fingers() {
        let mut client = reader_client(vec![]);
        let (outcome, _, keys, _) = finger_run(&mut client, vec![]);
        assert_eq!(outcome, Outcome::Success);
        assert!(finger_calls(&client).iter().all(|c| !c.starts_with("finger-begin")));
        assert!(keys.calls.is_empty());
    }

    // @spec:AC-055
    #[test]
    fn all_ten_fingers_enrolled_ends_with_one_line() {
        let mut client = reader_client(FINGERS.to_vec());
        let (outcome, output, _, answers) = finger_run(&mut client, vec![""]);
        assert_eq!(outcome, Outcome::Success);
        assert_eq!(output.matches("all ten fingers are already enrolled").count(), 1);
        assert!(answers.1.is_empty());
    }

    // @spec:AC-055
    #[test]
    fn retries_are_explained_and_a_failed_finger_leaves_earlier_fingers_untouched_without_provisioning() {
        let mut client = reader_client(vec!["left-thumb"]);
        client.finger_steps = vec![
            finger_progress("stage-passed", "in-progress", 1),
            finger_progress("retry-scan", "in-progress", 1),
            finger_progress("swipe-too-short", "in-progress", 1),
            finger_progress("finger-not-centered", "in-progress", 1),
            finger_progress("remove-and-retry", "in-progress", 1),
            finger_progress("failed", "failed", 1),
        ];
        let (outcome, output, keys, _) = finger_run(&mut client, vec!["", "n"]);
        assert_eq!(outcome, Outcome::Success, "{output}");
        for line in ["stage 1 of 5 done", "could not read that touch", "swipe was too short", "center your finger", "lift your finger, then place it", "could not complete the enrollment", "enrolled earlier were not changed"] {
            assert!(output.contains(line), "{line}: {output}");
        }
        assert!(!output.contains("enrolled the right"));
        assert!(!client.calls.iter().any(|c| c.starts_with("finger-discard")));
        assert_eq!(keys.calls, vec!["provision 1000"]);
    }

    // @spec:AC-055
    #[test]
    fn a_failed_first_finger_for_a_user_with_nothing_enrolled_provisions_nothing() {
        let mut client = reader_client(vec![]);
        client.finger_steps = vec![finger_progress("failed", "failed", 0)];
        let (outcome, _, keys, _) = finger_run(&mut client, vec!["", "n"]);
        assert_eq!(outcome, Outcome::Success);
        assert!(keys.calls.is_empty());
    }

    // @spec:AC-055
    #[test]
    fn reader_error_statuses_are_described_in_plain_words() {
        for (status, words) in [("data-full", "no space left"), ("disconnected", "disconnected"), ("unknown-error", "reported an error"), ("cancelled", "cancelled")] {
            let mut client = reader_client(vec![]);
            client.finger_steps = vec![finger_progress(status, "failed", 0)];
            let (_, output, _, _) = finger_run(&mut client, vec!["", "n"]);
            assert!(output.contains(words), "{status}: {output}");
        }
    }

    // @spec:AC-055
    #[test]
    fn a_refused_start_or_a_broken_wait_is_reported_and_the_reader_is_released() {
        let mut client = reader_client(vec![]);
        client.finger_begin_fails = true;
        let (outcome, output, _, _) = finger_run(&mut client, vec!["", "n"]);
        assert_eq!(outcome, Outcome::Success);
        assert!(output.contains("could not be enrolled: FingerEnrollBegin refused"));

        let mut client = reader_client(vec![]);
        client.finger_step_fails = true;
        let (outcome, output, _, _) = finger_run(&mut client, vec!["", "n"]);
        assert_eq!(outcome, Outcome::Success);
        assert!(output.contains("the reader went away"));
        assert!(client.calls.contains(&"finger-discard f1".to_string()));
    }

    // @spec:AC-055
    #[test]
    fn a_finger_that_never_finishes_is_discarded_after_the_step_budget() {
        let mut client = reader_client(vec![]);
        client.finger_steps = vec![];
        let (outcome, output, _, _) = finger_run(&mut client, vec!["", "n"]);
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

        for (given, expected) in [
            (vec!["enroll"], Command::Enroll { uid: 1000 }),
            (vec!["enroll", "face"], Command::Enroll { uid: 1000 }),
            (vec!["enroll", "finger"], Command::EnrollFinger { uid: 1000 }),
            (vec!["enroll", "--uid", "1001"], Command::Enroll { uid: 1001 }),
            (vec!["enroll", "face", "--uid", "1001"], Command::Enroll { uid: 1001 }),
            (vec!["enroll", "finger", "--uid", "1001"], Command::EnrollFinger { uid: 1001 }),
            (vec!["enroll", "--uid", "1001", "finger"], Command::EnrollFinger { uid: 1001 }),
        ] {
            assert_eq!(parse_args(args(&given), 1000).unwrap().command, expected, "{given:?}");
        }

        for bad in [vec!["enroll", "voice"], vec!["enroll", "face", "finger"], vec!["verify", "face"], vec![], vec!["dance"], vec!["verify", "--uid", "-1"], vec!["--bus", "mars", "verify"], vec!["identify", "--uid", "5"], vec!["verify", "extra"], vec!["--uid"]] {
            assert!(parse_args(args(&bad), 1000).is_err(), "{bad:?}");
        }
    }

    fn pam_tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc/pam.d")).unwrap();
        for (name, content) in files {
            std::fs::write(root.path().join("etc/pam.d").join(name), content).unwrap();
        }
        root
    }

    fn pam_snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
        let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(root.join("etc/pam.d"))
            .unwrap()
            .map(|e| e.unwrap())
            .map(|e| (e.file_name().into_string().unwrap(), std::fs::read(e.path()).unwrap()))
            .collect();
        files.sort();
        files
    }

    fn finger_run_in(root: &Path, client: &mut FakeClient, replies: Vec<&'static str>) -> (Outcome, String) {
        let mut answers = Replies(replies, vec![]);
        run_asked_in(root, client, &mut FakeKeys::default(), &mut TypedPins(vec![]), &mut answers, Command::EnrollFinger { uid: 1000 })
    }

    fn login_lines(output: &str) -> Vec<&str> {
        output.lines().filter(|line| line.contains("fingerprint login")).collect()
    }

    const SUDO_WITH_STACK: &str = "#%PAM-1.0\n@include base-auth\n";

    // @spec:AC-073
    #[test]
    fn enrolling_a_finger_says_the_login_is_on_when_the_common_stack_has_our_marked_line() {
        let root = pam_tree(&[("sudo", SUDO_WITH_STACK), ("base-auth", "auth sufficient pam_openhello.so\nauth sufficient pam_fprintd.so max-tries=3 # added by open-hello\nauth required pam_unix.so\n")]);
        let (outcome, output) = finger_run_in(root.path(), &mut reader_client(vec![]), vec!["", "n"]);
        assert_eq!(outcome, Outcome::Success, "{output}");
        assert_eq!(login_lines(&output), vec!["the system's fingerprint login is on: your enrolled finger can be used where the system asks for it"]);
    }

    // @spec:AC-073
    #[test]
    fn enrolling_a_finger_says_the_login_is_on_when_a_system_line_is_reached_through_an_include() {
        let root = pam_tree(&[("sudo", SUDO_WITH_STACK), ("base-auth", "auth substack extra-auth\nauth required pam_unix.so\n"), ("extra-auth", "auth sufficient pam_fprintd.so\n")]);
        let (_, output) = finger_run_in(root.path(), &mut reader_client(vec![]), vec!["", "n"]);
        assert_eq!(login_lines(&output).len(), 1, "{output}");
        assert!(output.contains("the system's fingerprint login is on"), "{output}");
    }

    // @spec:AC-073
    #[test]
    fn enrolling_a_finger_says_the_login_is_off_and_how_to_switch_it_on_when_the_stack_has_no_fingerprint_line() {
        let root = pam_tree(&[("sudo", SUDO_WITH_STACK), ("base-auth", "auth required pam_unix.so\n")]);
        let (outcome, output) = finger_run_in(root.path(), &mut reader_client(vec![]), vec!["", "n"]);
        assert_eq!(outcome, Outcome::Success, "{output}");
        let lines = login_lines(&output);
        assert_eq!(lines.len(), 1, "{output}");
        assert!(lines[0].contains("is not on") && lines[0].contains("sudo openhello-cli pam enable"), "{output}");
    }

    // @spec:AC-073
    #[test]
    fn enrolling_a_finger_says_the_check_could_not_be_made_when_the_stack_cannot_be_found() {
        let missing_sudo = pam_tree(&[("base-auth", "auth sufficient pam_fprintd.so\n")]);
        let no_include = pam_tree(&[("sudo", "#%PAM-1.0\nauth required pam_unix.so\n"), ("base-auth", "auth sufficient pam_fprintd.so\n")]);
        for root in [missing_sudo, no_include] {
            let (outcome, output) = finger_run_in(root.path(), &mut reader_client(vec![]), vec!["", "n"]);
            assert_eq!(outcome, Outcome::Success, "{output}");
            let lines = login_lines(&output);
            assert_eq!(lines.len(), 1, "{output}");
            assert!(lines[0].contains("could not check") && lines[0].contains("sudo openhello-cli pam enable"), "{output}");
        }
    }

    // @spec:AC-073
    #[test]
    fn no_login_line_is_printed_when_no_finger_was_enrolled() {
        let root = pam_tree(&[("sudo", SUDO_WITH_STACK), ("base-auth", "auth sufficient pam_fprintd.so\n")]);

        let mut no_reader = FakeClient::default();
        let (_, output) = finger_run_in(root.path(), &mut no_reader, vec!["", "n"]);
        assert!(login_lines(&output).is_empty() && output.lines().count() == 1, "{output}");

        let mut failing = reader_client(vec![]);
        failing.finger_begin_fails = true;
        let (_, output) = finger_run_in(root.path(), &mut failing, vec!["", "n"]);
        assert!(login_lines(&output).is_empty(), "{output}");

        let mut failed_step = reader_client(vec![]);
        failed_step.finger_step_fails = true;
        let (_, output) = finger_run_in(root.path(), &mut failed_step, vec!["", "n"]);
        assert!(login_lines(&output).is_empty(), "{output}");

        let mut cancelled = reader_client(vec![]);
        let (_, output) = finger_run_in(root.path(), &mut cancelled, vec![]);
        assert!(login_lines(&output).is_empty(), "{output}");

        let mut already = reader_client(vec!["left-thumb"]);
        let (_, output) = finger_run_in(root.path(), &mut already, vec!["", "", "n"]);
        assert_eq!(login_lines(&output).len(), 1, "{output}");
        let mut only_existing = reader_client(vec!["left-thumb"]);
        let (_, output) = finger_run_in(root.path(), &mut only_existing, vec![]);
        assert!(login_lines(&output).is_empty(), "{output}");
    }

    // @spec:AC-073
    #[test]
    fn several_fingers_in_one_run_print_the_login_line_once_at_the_end_of_the_enrollment() {
        let root = pam_tree(&[("sudo", SUDO_WITH_STACK), ("base-auth", "auth required pam_unix.so\n")]);
        let mut client = reader_client(vec![]);
        client.finger_steps = [five_stages(), five_stages()].concat();
        let (outcome, output) = finger_run_in(root.path(), &mut client, vec!["", "y", "1", "n"]);
        assert_eq!(outcome, Outcome::Success, "{output}");
        assert_eq!(login_lines(&output).len(), 1, "{output}");
        let line_at = output.lines().position(|line| line.contains("fingerprint login")).unwrap();
        let last_enrolled = output.lines().enumerate().filter(|(_, line)| line.contains("enrolled the")).map(|(i, _)| i).last().unwrap();
        assert!(line_at > last_enrolled, "{output}");
        assert_eq!(output.lines().last().unwrap(), RECOVERY_CODE);
    }

    // @spec:AC-073
    #[test]
    fn enrolling_a_finger_never_edits_the_pam_files() {
        for stack in ["auth required pam_unix.so\n", "auth sufficient pam_fprintd.so\n"] {
            let root = pam_tree(&[("sudo", SUDO_WITH_STACK), ("base-auth", stack), ("other", "auth required pam_unix.so\n")]);
            let before = pam_snapshot(root.path());
            let (_, output) = finger_run_in(root.path(), &mut reader_client(vec![]), vec!["", "n"]);
            assert_eq!(login_lines(&output).len(), 1, "{output}");
            assert_eq!(pam_snapshot(root.path()), before);
        }
    }
}
