use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::Sender;

use adw::prelude::*;
use async_channel::Receiver;
use gtk::{gdk, glib};
use openhello_gui_core::{Step, Strings, Text};

use crate::backend::{Backend, Command, Event};
use crate::capture_view::CaptureView;
use crate::pages::error::ErrorPage;
use crate::pages::manage::ManagePage;
use crate::pages::pin::PinPage;
use crate::pages::recovery::RecoveryPage;
use crate::pages::simple;

const STYLE: &str = ".ring { color: @accent_bg_color; } .preview-frame { border-radius: 24px; background: black; }";
const DEFAULT_SIZE: (i32, i32) = (640, 720);

struct Ui {
    strings: Strings,
    stack: gtk::Stack,
    capture: CaptureView,
    pin: PinPage,
    recovery: RecoveryPage,
    error: ErrorPage,
    manage: ManagePage,
}

pub fn build(app: &adw::Application, strings: Strings, backend: Backend, events: Receiver<Event>) {
    install_style();
    let window = adw::ApplicationWindow::builder().application(app).title(strings.get(Text::ManageTitle)).default_width(DEFAULT_SIZE.0).default_height(DEFAULT_SIZE.1).build();
    let ui = Rc::new(build_ui(&window, strings, &backend.sender()));
    window.set_content(Some(&toolbar(&ui.stack)));
    close_with_backend(&window, backend);
    pump_events(&ui, events);
    window.present();
}

fn install_style() {
    let Some(display) = gdk::Display::default() else { return };
    let provider = gtk::CssProvider::new();
    provider.load_from_string(STYLE);
    gtk::style_context_add_provider_for_display(&display, &provider, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
}

fn toolbar(stack: &gtk::Stack) -> adw::ToolbarView {
    let view = adw::ToolbarView::new();
    view.add_top_bar(&adw::HeaderBar::new());
    view.set_content(Some(stack));
    view
}

fn build_ui(window: &adw::ApplicationWindow, strings: Strings, commands: &Sender<Command>) -> Ui {
    let stack = gtk::Stack::builder().transition_type(gtk::StackTransitionType::Crossfade).build();
    let send = |command: fn() -> Command| {
        let commands = commands.clone();
        move || {
            let _ = commands.send(command());
        }
    };
    let capture = CaptureView::new(&strings, send(|| Command::Cancel));
    let pin = PinPage::new(&strings, {
        let commands = commands.clone();
        move |pin, confirmation| {
            let _ = commands.send(Command::SubmitPin { pin, confirmation });
        }
    });
    let recovery = RecoveryPage::new(&strings, send(|| Command::AcknowledgeRecovery));
    let error = ErrorPage::new(&strings, send(|| Command::Retry));
    let manage = ManagePage::new(&strings, send(|| Command::Test), send(|| Command::Remove), send(|| Command::Start));
    let close = window.downgrade();
    add_pages(&stack, &[
        ("welcome", simple::welcome(&strings, send(|| Command::Start))),
        ("identity", simple::identity(&strings)),
        ("pin", pin.widget().clone()),
        ("capture", capture.widget().clone()),
        ("recovery", recovery.widget().clone()),
        ("done", simple::done(&strings, move || {
            if let Some(window) = close.upgrade() {
                window.close();
            }
        })),
        ("error", error.widget().clone()),
        ("manage", manage.widget().clone()),
    ]);
    Ui { strings, stack, capture, pin, recovery, error, manage }
}

fn add_pages(stack: &gtk::Stack, pages: &[(&str, gtk::Widget)]) {
    for (name, page) in pages {
        stack.add_named(page, Some(name));
    }
}

fn close_with_backend(window: &adw::ApplicationWindow, backend: Backend) {
    let backend = RefCell::new(backend);
    window.connect_close_request(move |_| {
        backend.borrow_mut().shutdown();
        glib::Propagation::Proceed
    });
}

fn pump_events(ui: &Rc<Ui>, events: Receiver<Event>) {
    let ui = Rc::clone(ui);
    glib::spawn_future_local(async move {
        while let Ok(event) = events.recv().await {
            ui.handle(event);
        }
    });
}

impl Ui {
    fn handle(&self, event: Event) {
        match event {
            Event::Step(step) => self.show_step(step),
            Event::Capture(update) => self.capture.update(&update),
            Event::RecoveryCode(code) => self.recovery.set_code(&code),
            Event::PinRejected(error) => self.pin.reject(error),
            Event::Status(status) => self.show_status(status.face),
            Event::TestResult(recognized) => self.manage.finish_test(recognized),
        }
    }

    fn show_status(&self, face: bool) {
        self.manage.reset();
        self.stack.set_visible_child_name(if face { "manage" } else { "welcome" });
    }

    fn show_step(&self, step: Step) {
        if step != Step::RecoveryCode {
            self.recovery.clear();
        }
        match step {
            Step::Welcome => self.stack.set_visible_child_name("welcome"),
            Step::Identity => self.stack.set_visible_child_name("identity"),
            Step::Pin => {
                self.pin.reset();
                self.stack.set_visible_child_name("pin");
            }
            Step::Capture => {
                self.capture.reset(&self.strings);
                self.stack.set_visible_child_name("capture");
            }
            Step::RecoveryCode => self.stack.set_visible_child_name("recovery"),
            Step::Done => self.stack.set_visible_child_name("done"),
            Step::Error(cause) => {
                self.error.show(cause);
                self.stack.set_visible_child_name("error");
            }
        }
    }
}
