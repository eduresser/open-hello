mod backend;
mod capture_view;
mod demo;
mod geometry;
mod pages;
mod window;

use adw::prelude::*;
use gtk::glib;
use openhello_cli::Bus;
use openhello_gui_core::client::DaemonClient;
use openhello_gui_core::{Language, Strings};

const APP_ID: &str = "io.openhello.Gui";

fn main() -> glib::ExitCode {
    let demo = std::env::args().any(|arg| arg == "--demo") || std::env::var("OPENHELLO_GUI_DEMO").is_ok_and(|value| value == "1");
    let enrolled = std::env::args().any(|arg| arg == "--demo-enrolled");
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(move |app| activate(app, demo, enrolled));
    app.run_with_args::<&str>(&[])
}

fn activate(app: &adw::Application, demo: bool, enrolled: bool) {
    if let Some(existing) = app.active_window() {
        existing.present();
        return;
    }
    let language = Language::detect();
    let uid = unsafe { libc::getuid() };
    let (sender, events) = async_channel::unbounded();
    let backend = if demo {
        backend::spawn(move || Ok(demo::DemoClient::new(enrolled)), uid, language, sender)
    } else {
        backend::spawn(|| DaemonClient::connect(Bus::System), uid, language, sender)
    };
    window::build(app, Strings::new(language), backend, events);
}
