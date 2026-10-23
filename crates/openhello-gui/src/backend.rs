use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use openhello_gui_core::{ClientResult, EnrollClient, EnrollmentFlow, FailureCause, Language, ManageClient, Manager, RemoveOutcome, Step, TestOutcome};

use crate::capture::CaptureView;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
const JOIN_POLL: Duration = Duration::from_millis(20);

pub enum Command {
    Start,
    Retry,
    Cancel,
    Test,
    Remove,
    Shutdown,
}

pub enum Event {
    Welcome { blocked: Option<FailureCause> },
    Identity,
    CaptureStarted,
    Capture(CaptureView),
    Done,
    Failed(FailureCause),
    Manage { blocked: Option<FailureCause> },
    TestResult(TestOutcome),
}

pub struct Backend {
    commands: Sender<Command>,
    thread: Option<JoinHandle<()>>,
}

impl Backend {
    pub fn sender(&self) -> Sender<Command> {
        self.commands.clone()
    }

    pub fn shutdown(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
        let Some(thread) = self.thread.take() else { return };
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        while !thread.is_finished() && Instant::now() < deadline {
            thread::sleep(JOIN_POLL);
        }
        if thread.is_finished() {
            let _ = thread.join();
        }
    }
}

pub fn spawn<C, F, E>(factory: F, uid: u32, language: Language, emit: E) -> Backend
where
    C: EnrollClient + ManageClient + 'static,
    F: Fn() -> ClientResult<C> + Send + 'static,
    E: Fn(Event) -> bool + Send + 'static,
{
    let (commands, inbox) = mpsc::channel();
    let thread = thread::spawn(move || run(&factory, uid, language, &emit, &inbox));
    Backend { commands, thread: Some(thread) }
}

fn run<C: EnrollClient + ManageClient>(factory: &impl Fn() -> ClientResult<C>, uid: u32, language: Language, emit: &impl Fn(Event) -> bool, inbox: &Receiver<Command>) {
    loop {
        match connect(factory, uid, language) {
            Ok((flow, manager)) => return Worker { flow, manager, emit, inbox, stopped: false, begun: false, face: false }.serve(),
            Err(error) => {
                if !emit(Event::Failed(error.kind.into())) || !wait_for_retry(inbox) {
                    return;
                }
            }
        }
    }
}

fn connect<C: EnrollClient + ManageClient>(factory: &impl Fn() -> ClientResult<C>, uid: u32, language: Language) -> ClientResult<(EnrollmentFlow<C>, Manager<C>)> {
    Ok((EnrollmentFlow::new(factory()?, uid, language), Manager::new(factory()?, uid)))
}

fn wait_for_retry(inbox: &Receiver<Command>) -> bool {
    loop {
        match inbox.recv() {
            Ok(Command::Retry | Command::Remove) => return true,
            Ok(Command::Shutdown) | Err(_) => return false,
            Ok(_) => {}
        }
    }
}

struct Worker<'a, C: EnrollClient + ManageClient, E: Fn(Event) -> bool> {
    flow: EnrollmentFlow<C>,
    manager: Manager<C>,
    emit: &'a E,
    inbox: &'a Receiver<Command>,
    stopped: bool,
    begun: bool,
    face: bool,
}

impl<C: EnrollClient + ManageClient, E: Fn(Event) -> bool> Worker<'_, C, E> {
    fn serve(mut self) {
        self.launch();
        while !self.stopped {
            match self.inbox.recv() {
                Ok(command) => self.handle(command),
                Err(_) => self.stop(),
            }
        }
        self.flow.cancel();
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Start => self.start(),
            Command::Retry => self.retry(),
            Command::Cancel => self.cancel(),
            Command::Test => self.test(),
            Command::Remove => self.remove(),
            Command::Shutdown => self.stop(),
        }
    }

    fn launch(&mut self) {
        match self.manager.status() {
            Ok(status) => {
                self.set_face(status.face);
                self.home();
            }
            Err(error) => self.send(Event::Failed(error.kind.into())),
        }
    }

    fn set_face(&mut self, face: bool) {
        self.face = face;
    }

    fn home(&mut self) {
        self.begun = false;
        if self.face {
            let blocked = self.flow.probe();
            self.send(Event::Manage { blocked });
            return;
        }
        self.flow.start();
        self.emit_step();
    }

    fn start(&mut self) {
        self.flow.start();
        if self.flow.blocked().is_some() {
            self.begun = false;
            self.emit_step();
            return;
        }
        self.begun = true;
        self.drive();
    }

    fn cancel(&mut self) {
        self.flow.cancel();
        self.home();
    }

    fn retry(&mut self) {
        if matches!(self.flow.step(), Step::Error(_)) {
            self.flow.retry();
            self.resume();
        } else if self.flow.blocked().is_some() {
            self.home();
        } else {
            self.launch();
        }
    }

    fn resume(&mut self) {
        if matches!(self.flow.step(), Step::Welcome | Step::Identity) {
            self.home();
        } else {
            self.drive();
        }
    }

    fn test(&mut self) {
        let outcome = self.manager.test();
        self.send(Event::TestResult(outcome));
    }

    fn remove(&mut self) {
        match self.manager.remove(true) {
            RemoveOutcome::Removed(status) => {
                self.flow.reset_after_removal();
                self.set_face(status.face);
                self.home();
            }
            RemoveOutcome::Failed(error) => self.send(Event::Failed(error.kind.into())),
            RemoveOutcome::NotConfirmed => {}
        }
    }

    fn drive(&mut self) {
        loop {
            self.emit_step();
            match self.flow.step() {
                Step::Identity => self.flow.confirm_identity(),
                Step::Capture if self.capture() => {}
                _ => return,
            }
            if self.stopped {
                return;
            }
        }
    }

    fn capture(&mut self) -> bool {
        let strings = *self.flow.strings();
        while self.flow.step() == Step::Capture {
            if self.interrupted() {
                return false;
            }
            let Some(update) = self.flow.tick() else { break };
            self.send(Event::Capture(CaptureView::new(update, &strings)));
        }
        self.flow.step() != Step::Capture
    }

    fn interrupted(&mut self) -> bool {
        match self.inbox.try_recv() {
            Ok(Command::Cancel) => {
                self.cancel();
                true
            }
            Ok(Command::Shutdown) | Err(TryRecvError::Disconnected) => {
                self.stop();
                true
            }
            Ok(_) | Err(TryRecvError::Empty) => false,
        }
    }

    fn emit_step(&mut self) {
        let event = match self.flow.step() {
            Step::Welcome => self.welcome(self.flow.blocked()),
            Step::Identity if self.begun => Event::Identity,
            Step::Identity => self.welcome(None),
            Step::Capture => Event::CaptureStarted,
            Step::Done => {
                self.set_face(true);
                Event::Done
            }
            Step::Error(cause) => Event::Failed(cause),
        };
        self.send(event);
    }

    fn welcome(&self, blocked: Option<FailureCause>) -> Event {
        Event::Welcome { blocked }
    }

    fn send(&mut self, event: Event) {
        if !(self.emit)(event) {
            self.stop();
        }
    }

    fn stop(&mut self) {
        self.stopped = true;
        self.flow.cancel();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc::RecvTimeoutError;
    use std::sync::Arc;

    use openhello_gui_core::{ClientError, ClientErrorKind, Frame, Progress, Status};

    use crate::demo::DemoClient;
    use crate::options::DemoMode;

    use super::*;

    const WAIT: Duration = Duration::from_secs(20);

    struct Harness {
        backend: Backend,
        events: Receiver<Event>,
    }

    fn harness(mode: DemoMode) -> Harness {
        let (sender, events) = mpsc::channel();
        let face = Arc::new(AtomicBool::new(mode.enrolled));
        let factory = move || Ok(DemoClient::paced(mode, face.clone(), Duration::ZERO));
        let emit = move |event| sender.send(event).is_ok();
        Harness { backend: spawn(factory, 1000, Language::English, emit), events }
    }

    impl Harness {
        fn send(&self, command: Command) {
            self.backend.sender().send(command).expect("the worker is alive");
        }

        fn next(&self) -> Result<Event, RecvTimeoutError> {
            self.events.recv_timeout(WAIT)
        }

        fn until(&self, done: impl Fn(&Event) -> bool) -> Vec<Event> {
            let mut seen = Vec::new();
            loop {
                let event = self.next().expect("an event arrives in time");
                let last = done(&event);
                seen.push(event);
                if last {
                    return seen;
                }
            }
        }
    }

    struct RefusedCamera(DemoClient);

    impl EnrollClient for RefusedCamera {
        fn check_ready(&mut self) -> ClientResult<()> {
            self.0.check_ready()
        }

        fn status(&mut self, uid: u32) -> ClientResult<Status> {
            EnrollClient::status(&mut self.0, uid)
        }

        fn enroll_begin(&mut self, _uid: u32) -> ClientResult<String> {
            Err(ClientError::new(ClientErrorKind::CameraBusy, "demo"))
        }

        fn enroll_capture(&mut self, handle: &str) -> ClientResult<Progress> {
            self.0.enroll_capture(handle)
        }

        fn enroll_frame(&mut self, handle: &str) -> ClientResult<Frame> {
            self.0.enroll_frame(handle)
        }

        fn enroll_commit(&mut self, handle: &str) -> ClientResult<()> {
            self.0.enroll_commit(handle)
        }

        fn enroll_discard(&mut self, handle: &str) -> ClientResult<()> {
            self.0.enroll_discard(handle)
        }

        fn provision(&mut self, uid: u32) -> ClientResult<String> {
            self.0.provision(uid)
        }
    }

    impl ManageClient for RefusedCamera {
        fn status(&mut self, uid: u32) -> ClientResult<Status> {
            ManageClient::status(&mut self.0, uid)
        }

        fn verify(&mut self, uid: u32) -> ClientResult<bool> {
            self.0.verify(uid)
        }

        fn purge(&mut self, uid: u32) -> ClientResult<()> {
            self.0.purge(uid)
        }
    }

    fn refused_camera_harness() -> Harness {
        let (sender, events) = mpsc::channel();
        let face = Arc::new(AtomicBool::new(false));
        let factory = move || Ok(RefusedCamera(DemoClient::paced(DemoMode::default(), face.clone(), Duration::ZERO)));
        let emit = move |event| sender.send(event).is_ok();
        Harness { backend: spawn(factory, 1000, Language::English, emit), events }
    }

    fn name(event: &Event) -> &'static str {
        match event {
            Event::Welcome { blocked: None } => "welcome",
            Event::Welcome { blocked: Some(_) } => "blocked",
            Event::Identity => "identity",
            Event::CaptureStarted => "capture",
            Event::Capture(_) => "frame",
            Event::Done => "done",
            Event::Failed(_) => "failed",
            Event::Manage { blocked: None } => "manage",
            Event::Manage { blocked: Some(_) } => "manage-blocked",
            Event::TestResult(TestOutcome::Recognized) => "recognized",
            Event::TestResult(TestOutcome::NotRecognized) => "not-recognized",
            Event::TestResult(TestOutcome::Failed(_)) => "test-failed",
        }
    }

    fn names(events: &[Event]) -> Vec<&'static str> {
        let mut names: Vec<&str> = events.iter().map(name).collect();
        names.dedup();
        names
    }

    // @spec:AC-058
    #[test]
    fn the_worker_walks_welcome_identity_capture_and_done() {
        let mut harness = harness(DemoMode::default());
        let mut seen = harness.until(|event| matches!(event, Event::Welcome { blocked: None, .. }));
        harness.send(Command::Start);
        seen.extend(harness.until(|event| matches!(event, Event::Done)));
        harness.backend.shutdown();
        assert_eq!(names(&seen), ["welcome", "identity", "capture", "frame", "done"]);
    }

    // @spec:AC-062
    #[test]
    fn cancel_during_capture_stops_the_frames_and_returns_to_welcome() {
        let mut harness = harness(DemoMode { hold: true, ..DemoMode::default() });
        harness.send(Command::Start);
        harness.until(|event| matches!(event, Event::Capture(_)));
        harness.send(Command::Cancel);
        let after = harness.until(|event| matches!(event, Event::Welcome { .. }));
        harness.backend.shutdown();
        assert!(matches!(after.last(), Some(Event::Welcome { blocked: None, .. })));
        assert!(harness.events.try_recv().is_err());
    }

    // @spec:AC-070
    #[test]
    fn a_blocked_computer_shows_the_cause_and_start_creates_no_capture() {
        let mut harness = harness(DemoMode { blocked: true, ..DemoMode::default() });
        let first = harness.until(|event| matches!(event, Event::Welcome { .. }));
        harness.send(Command::Start);
        let second = harness.until(|event| matches!(event, Event::Welcome { .. }));
        harness.send(Command::Retry);
        let third = harness.until(|event| matches!(event, Event::Welcome { .. }));
        harness.backend.shutdown();
        for events in [first, second, third] {
            assert_eq!(names(&events), ["blocked"]);
        }
        assert!(harness.events.try_recv().is_err());
    }

    // @spec:AC-065
    #[test]
    fn test_reports_recognized_for_an_enrolled_user() {
        let mut harness = harness(DemoMode { enrolled: true, ..DemoMode::default() });
        assert_eq!(names(&harness.until(|event| matches!(event, Event::Manage { .. }))), ["manage"]);
        harness.send(Command::Test);
        let result = harness.until(|event| matches!(event, Event::TestResult(_)));
        harness.backend.shutdown();
        assert_eq!(names(&result), ["recognized"]);
    }

    // @spec:AC-066
    #[test]
    fn remove_erases_the_face_and_returns_to_the_not_set_up_welcome() {
        let mut harness = harness(DemoMode { enrolled: true, ..DemoMode::default() });
        harness.until(|event| matches!(event, Event::Manage { .. }));
        harness.send(Command::Remove);
        let after = harness.until(|event| matches!(event, Event::Welcome { .. }));
        harness.backend.shutdown();
        assert_eq!(names(&after), ["welcome"]);
    }

    #[test]
    fn a_status_that_cannot_be_read_is_an_error_and_try_again_asks_again() {
        let mut harness = harness(DemoMode { fail: true, ..DemoMode::default() });
        let first = harness.until(|event| matches!(event, Event::Failed(_)));
        harness.send(Command::Retry);
        let second = harness.until(|event| matches!(event, Event::Failed(_)));
        harness.backend.shutdown();
        assert_eq!((names(&first), names(&second)), (vec!["failed"], vec!["failed"]));
    }

    // @spec:AC-066
    // @spec:AC-071
    #[test]
    fn removal_from_an_error_screen_returns_to_the_welcome_with_the_face_not_set_up() {
        let mut harness = refused_camera_harness();
        harness.until(|event| matches!(event, Event::Welcome { .. }));
        harness.send(Command::Start);
        let failed = harness.until(|event| matches!(event, Event::Failed(_)));
        harness.send(Command::Remove);
        let after = harness.until(|event| matches!(event, Event::Welcome { .. }));
        harness.backend.shutdown();
        assert_eq!(names(&failed), ["identity", "failed"]);
        assert_eq!(names(&after), ["welcome"]);
    }

    // @spec:AC-071
    // @spec:AC-073
    #[test]
    fn a_blocked_computer_with_a_face_shows_the_main_screen_with_the_cause_and_still_deletes() {
        let mut harness = harness(DemoMode { enrolled: true, blocked: true, ..DemoMode::default() });
        let first = harness.until(|event| matches!(event, Event::Manage { .. }));
        harness.send(Command::Remove);
        let after = harness.until(|event| matches!(event, Event::Welcome { .. }));
        harness.backend.shutdown();
        assert_eq!(names(&first), ["manage-blocked"]);
        assert_eq!(names(&after), ["blocked"]);
    }

    // @spec:AC-073
    #[test]
    fn the_main_screen_of_a_working_computer_is_not_blocked() {
        let mut harness = harness(DemoMode { enrolled: true, ..DemoMode::default() });
        let first = harness.until(|event| matches!(event, Event::Manage { .. }));
        harness.backend.shutdown();
        assert_eq!(names(&first), ["manage"]);
    }

    // @spec:AC-058
    #[test]
    fn set_up_again_from_the_main_screen_goes_straight_to_the_identity_step() {
        let mut harness = harness(DemoMode { enrolled: true, ..DemoMode::default() });
        harness.until(|event| matches!(event, Event::Manage { .. }));
        harness.send(Command::Start);
        let seen = harness.until(|event| matches!(event, Event::Done));
        harness.backend.shutdown();
        assert_eq!(names(&seen), ["identity", "capture", "frame", "done"]);
    }

    // @spec:AC-071
    #[test]
    fn a_status_that_cannot_be_read_shows_an_error_and_a_removal_that_cannot_finish_stays_there() {
        let mut harness = harness(DemoMode { fail: true, ..DemoMode::default() });
        harness.until(|event| matches!(event, Event::Failed(_)));
        harness.send(Command::Remove);
        let after = harness.until(|event| matches!(event, Event::Failed(_)));
        harness.backend.shutdown();
        assert_eq!(names(&after), ["failed"]);
    }

    fn cycling_harness(enrolled: bool) -> Harness {
        harness(DemoMode { enrolled, cycle_tests: true, ..DemoMode::default() })
    }

    fn test_once(harness: &Harness) -> Event {
        harness.send(Command::Test);
        harness.until(|event| matches!(event, Event::TestResult(_) | Event::Failed(_))).pop().expect("a result arrives")
    }

    // @spec:AC-065
    // @spec:AC-072
    #[test]
    fn the_final_screen_runs_the_test_and_shows_the_result_in_place() {
        let mut harness = cycling_harness(false);
        harness.until(|event| matches!(event, Event::Welcome { .. }));
        harness.send(Command::Start);
        harness.until(|event| matches!(event, Event::Done));
        let result = test_once(&harness);
        harness.backend.shutdown();
        assert_eq!(name(&result), "recognized");
        assert!(harness.events.try_recv().is_err());
    }

    // @spec:AC-074
    #[test]
    fn a_test_that_is_not_recognized_or_cannot_run_stays_on_the_page_and_can_be_repeated() {
        let mut harness = cycling_harness(true);
        harness.until(|event| matches!(event, Event::Manage { .. }));
        let results = [test_once(&harness), test_once(&harness), test_once(&harness), test_once(&harness)];
        harness.backend.shutdown();
        let seen: Vec<_> = results.iter().map(name).collect();
        assert_eq!(seen, ["recognized", "not-recognized", "test-failed", "recognized"]);
        assert!(matches!(&results[2], Event::TestResult(TestOutcome::Failed(error)) if error.kind == ClientErrorKind::CameraBusy));
        assert!(harness.events.try_recv().is_err());
    }

    // @spec:AC-074
    #[test]
    fn set_up_again_after_a_failed_test_on_the_final_screen_restarts_the_enrollment() {
        let mut harness = cycling_harness(false);
        harness.until(|event| matches!(event, Event::Welcome { .. }));
        harness.send(Command::Start);
        harness.until(|event| matches!(event, Event::Done));
        test_once(&harness);
        assert_eq!(name(&test_once(&harness)), "not-recognized");
        harness.send(Command::Start);
        let again = harness.until(|event| matches!(event, Event::Done));
        harness.backend.shutdown();
        assert_eq!(names(&again), ["identity", "capture", "frame", "done"]);
    }
}
