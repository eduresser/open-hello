mod backend;
mod capture;
mod demo;
mod options;
mod stats;
mod view;

use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use openhello_cli::Bus;
use openhello_gui_core::{DaemonClient, Language, Strings};
use slint::ComponentHandle;

use backend::{Backend, Command};
use options::{DemoMode, Options};

slint::include_modules!();

fn main() -> ExitCode {
    let options = Options::parse(std::env::args().skip(1));
    let window = match MainWindow::new() {
        Ok(window) => window,
        Err(error) => {
            eprintln!("cannot open the window: {error}");
            return ExitCode::FAILURE;
        }
    };
    let strings = Strings::new(Language::detect());
    view::init(&window, &strings);
    let mut backend = launch(&options, &window, strings);
    wire(&window, &backend.sender());
    let _stats = options.stats.then(|| stats::start(&window));
    let result = window.run();
    backend.shutdown();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("the window stopped with an error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn launch(options: &Options, window: &MainWindow, strings: Strings) -> Backend {
    let uid = unsafe { libc::getuid() };
    let language = strings.language();
    let weak = window.as_weak();
    let emit = move |event| weak.upgrade_in_event_loop(move |window| view::apply(&window, &strings, event)).is_ok();
    match options.demo {
        Some(mode) => backend::spawn(demo_factory(mode), uid, language, emit),
        None => backend::spawn(|| DaemonClient::connect(Bus::System), uid, language, emit),
    }
}

fn demo_factory(mode: DemoMode) -> impl Fn() -> Result<demo::DemoClient, openhello_gui_core::ClientError> + Send + 'static {
    let face = Arc::new(AtomicBool::new(mode.enrolled));
    move || Ok(demo::DemoClient::new(mode, face.clone()))
}

fn wire(window: &MainWindow, commands: &Sender<Command>) {
    window.on_get_started(sender(commands, || Command::Start));
    window.on_retry(sender(commands, || Command::Retry));
    window.on_cancel(sender(commands, || Command::Cancel));
    window.on_set_up_again(busy_sender(window, commands, false, || Command::Start));
    window.on_test(busy_sender(window, commands, true, || Command::Test));
    window.on_delete(busy_sender(window, commands, false, || Command::Remove));
}

fn sender(commands: &Sender<Command>, command: fn() -> Command) -> impl Fn() + 'static {
    let commands = commands.clone();
    move || {
        let _ = commands.send(command());
    }
}

fn busy_sender(window: &MainWindow, commands: &Sender<Command>, testing: bool, command: fn() -> Command) -> impl Fn() + 'static {
    let (weak, send) = (window.as_weak(), sender(commands, command));
    move || {
        let Some(window) = weak.upgrade() else { return };
        if window.get_busy() {
            return;
        }
        window.set_busy(true);
        window.set_testing(testing);
        send();
    }
}
