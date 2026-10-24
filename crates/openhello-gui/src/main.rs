mod backend;
mod capture;
mod demo;
mod options;
mod gate;
mod pointer;
mod stats;
mod trace;
mod view;

use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use openhello_cli::Bus;
use openhello_gui_core::{DaemonClient, Language, Strings};
use slint::winit_030::{winit, EventResult, WinitWindowAccessor};
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
    if let Err(error) = slint::set_xdg_app_id("openhello") {
        eprintln!("cannot set the application id: {error}");
    }
    if options.trace_input {
        trace::enable();
    }
    track_pointer(&window);
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
    window.on_get_started(busy_sender(window, commands, "set up", false, || Command::Start));
    window.on_retry(busy_sender(window, commands, "try again", false, || Command::Retry));
    window.on_cancel(busy_sender(window, commands, "cancel", false, || Command::Cancel));
    window.on_set_up_again(busy_sender(window, commands, "set up again", false, || Command::Start));
    window.on_test(busy_sender(window, commands, "test", true, || Command::Test));
    window.on_delete(busy_sender(window, commands, "delete", false, || Command::Remove));
    window.on_use_own_sudo(busy_sender(window, commands, "use my face for sudo", false, || Command::UseOwnSudo));
    window.on_restore_root_sudo(busy_sender(window, commands, "ask for the root password again", false, || Command::RestoreRootSudo));
}

impl gate::Flags for MainWindow {
    fn busy(&self) -> bool {
        self.get_busy()
    }

    fn set_busy(&self, busy: bool) {
        MainWindow::set_busy(self, busy);
    }

    fn set_testing(&self, testing: bool) {
        MainWindow::set_testing(self, testing);
    }
}

fn busy_sender(window: &MainWindow, commands: &Sender<Command>, button: &'static str, testing: bool, command: fn() -> Command) -> impl Fn() + 'static {
    let (weak, commands) = (window.as_weak(), commands.clone());
    move || {
        let Some(window) = weak.upgrade() else { return };
        if !gate::begin(&window, testing) {
            trace::log(format!("clicked {button}, ignored while busy"));
            return;
        }
        let command = command();
        trace::log(format!("clicked {button}, sending {}", command.name()));
        let _ = commands.send(command);
    }
}

fn track_pointer(window: &MainWindow) {
    window.window().on_winit_window_event(move |_, event| {
        match event {
            winit::event::WindowEvent::CursorMoved { position, .. } => pointer::with(|tracker| tracker.moved(position.x, position.y)),
            winit::event::WindowEvent::CursorEntered { .. } => {
                pointer::with(|tracker| tracker.entered());
                trace::log("pointer entered");
            }
            winit::event::WindowEvent::CursorLeft { .. } => {
                pointer::with(|tracker| tracker.left());
                trace::log("pointer left");
            }
            winit::event::WindowEvent::Focused(focused) => trace::log(format!("window focused={focused}")),
            winit::event::WindowEvent::MouseInput { state, button, .. } => {
                let (x, y) = pointer::with(|tracker| tracker.physical());
                trace::log(format!("pointer {state:?} {button:?} at {x:.0},{y:.0}"));
            }
            _ => {}
        }
        EventResult::Propagate
    });
}
