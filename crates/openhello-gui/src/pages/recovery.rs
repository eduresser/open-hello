use gtk::prelude::*;
use openhello_gui_core::{Strings, Text};

use super::{pill_button, status_page};

pub struct RecoveryPage {
    page: adw::StatusPage,
    code: gtk::Label,
}

impl RecoveryPage {
    pub fn new(strings: &Strings, on_acknowledge: impl Fn() + 'static) -> Self {
        let page = status_page("dialog-password-symbolic", strings.get(Text::RecoveryTitle), strings.get(Text::RecoveryBody));
        let code = gtk::Label::builder().selectable(true).css_classes(["monospace", "title-2"]).build();
        let copy = copy_button(strings, &code);
        let acknowledge = pill_button(strings.get(Text::Done), "suggested-action", on_acknowledge);
        let column = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(18).halign(gtk::Align::Center).build();
        for child in [code.upcast_ref::<gtk::Widget>(), copy.upcast_ref(), acknowledge.upcast_ref()] {
            column.append(child);
        }
        page.set_child(Some(&column));
        Self { page, code }
    }

    pub fn widget(&self) -> &gtk::Widget {
        self.page.upcast_ref()
    }

    pub fn set_code(&self, code: &str) {
        self.code.set_label(code);
    }

    pub fn clear(&self) {
        self.code.set_label("");
    }
}

fn copy_button(strings: &Strings, code: &gtk::Label) -> gtk::Button {
    let code = code.clone();
    pill_button(strings.get(Text::CopyCode), "flat", move || {
        if let Some(display) = gtk::gdk::Display::default() {
            display.clipboard().set_text(&code.label());
        }
    })
}
