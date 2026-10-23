use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use async_channel::Sender as EventSender;
use openhello_gui_core::{
    CaptureUpdate, ClientResult, EnrollClient, EnrollmentFlow, Language, ManageClient, Manager, PinError, RemoveOutcome, Status, Step, TestOutcome,
};

const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
const JOIN_POLL: Duration = Duration::from_millis(20);

pub enum Command {
    Start,
    SubmitPin { pin: String, confirmation: String },
    AcknowledgeRecovery,
    Retry,
    Cancel,
    Test,
    Remove,
    Shutdown,
}

pub enum Event {
    Step(Step),
    Capture(CaptureUpdate),
    RecoveryCode(String),
    PinRejected(PinError),
    Status(Status),
    TestResult(bool),
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

pub fn spawn<C, F>(factory: F, uid: u32, language: Language, events: EventSender<Event>) -> Backend
where
    C: EnrollClient + ManageClient + 'static,
    F: Fn() -> ClientResult<C> + Send + 'static,
{
    let (commands, inbox) = mpsc::channel();
    let thread = thread::spawn(move || run(&factory, uid, language, &events, &inbox));
    Backend { commands, thread: Some(thread) }
}

fn run<C: EnrollClient + ManageClient>(factory: &impl Fn() -> ClientResult<C>, uid: u32, language: Language, events: &EventSender<Event>, inbox: &Receiver<Command>) {
    loop {
        match connect(factory, uid, language) {
            Ok((flow, manager)) => return Worker { flow, manager, events, inbox, stopped: false, launch_failed: false }.serve(),
            Err(error) => {
                let _ = events.send_blocking(Event::Step(Step::Error(error.kind.into())));
                if !wait_for_retry(inbox) {
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
            Ok(Command::Retry) => return true,
            Ok(Command::Shutdown) | Err(_) => return false,
            Ok(_) => {}
        }
    }
}

struct Worker<'a, C: EnrollClient + ManageClient> {
    flow: EnrollmentFlow<C>,
    manager: Manager<C>,
    events: &'a EventSender<Event>,
    inbox: &'a Receiver<Command>,
    stopped: bool,
    launch_failed: bool,
}

impl<C: EnrollClient + ManageClient> Worker<'_, C> {
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
            Command::Start => {
                self.flow.start();
                self.drive();
            }
            Command::SubmitPin { pin, confirmation } => self.submit_pin(&pin, &confirmation),
            Command::AcknowledgeRecovery => {
                self.flow.acknowledge_recovery_code();
                self.emit_step();
            }
            Command::Retry => self.retry(),
            Command::Cancel => {
                self.flow.cancel();
                self.emit_step();
            }
            Command::Test => self.test(),
            Command::Remove => self.remove(),
            Command::Shutdown => self.stop(),
        }
    }

    fn launch(&mut self) {
        match self.manager.status() {
            Ok(status) => {
                self.launch_failed = false;
                self.send(Event::Status(status));
            }
            Err(error) => {
                self.launch_failed = true;
                self.send(Event::Step(Step::Error(error.kind.into())));
            }
        }
    }

    fn retry(&mut self) {
        if self.launch_failed || !matches!(self.flow.step(), Step::Error(_)) {
            self.launch();
            return;
        }
        self.flow.retry();
        self.drive();
    }

    fn submit_pin(&mut self, pin: &str, confirmation: &str) {
        match self.flow.submit_pin(pin, confirmation) {
            Ok(()) => self.drive(),
            Err(PinError::Failed) => self.emit_step(),
            Err(rejected) => self.send(Event::PinRejected(rejected)),
        }
    }

    fn test(&mut self) {
        match self.manager.test() {
            TestOutcome::Recognized => self.send(Event::TestResult(true)),
            TestOutcome::NotRecognized => self.send(Event::TestResult(false)),
            TestOutcome::Failed(error) => self.send(Event::Step(Step::Error(error.kind.into()))),
        }
    }

    fn remove(&mut self) {
        match self.manager.remove(true) {
            RemoveOutcome::Removed(status) => self.send(Event::Status(status)),
            RemoveOutcome::Failed(error) => self.send(Event::Step(Step::Error(error.kind.into()))),
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
        while self.flow.step() == Step::Capture {
            if self.interrupted() {
                return false;
            }
            let Some(update) = self.flow.tick() else { break };
            self.send(Event::Capture(update));
        }
        self.flow.step() != Step::Capture
    }

    fn interrupted(&mut self) -> bool {
        match self.inbox.try_recv() {
            Ok(Command::Cancel) => {
                self.flow.cancel();
                self.emit_step();
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
        if let Some(code) = self.flow.recovery_code().map(String::from) {
            self.send(Event::RecoveryCode(code));
        }
        self.send(Event::Step(self.flow.step()));
    }

    fn send(&mut self, event: Event) {
        if self.events.send_blocking(event).is_err() {
            self.stop();
        }
    }

    fn stop(&mut self) {
        self.stopped = true;
        self.flow.cancel();
    }
}
