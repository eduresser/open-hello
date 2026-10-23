use adw::prelude::*;
use openhello_gui_core::{PinError, Strings, Text};

use super::pill;

pub struct PinPage {
    root: gtk::Widget,
    pin: adw::PasswordEntryRow,
    confirmation: adw::PasswordEntryRow,
    error: gtk::Label,
    next: gtk::Button,
    strings: Strings,
}

impl PinPage {
    pub fn new(strings: &Strings, on_submit: impl Fn(String, String) + 'static) -> Self {
        let pin = adw::PasswordEntryRow::builder().title(strings.get(Text::PinLabel)).build();
        let confirmation = adw::PasswordEntryRow::builder().title(strings.get(Text::PinConfirmLabel)).build();
        let error = gtk::Label::builder().wrap(true).xalign(0.0).css_classes(["error"]).build();
        let next = pill(strings.get(Text::Next), "suggested-action");
        let (entries, submit, button) = (pin.clone(), confirmation.clone(), next.clone());
        next.connect_clicked(move |_| {
            button.set_sensitive(false);
            on_submit(entries.text().into(), submit.text().into());
        });
        let root = layout(strings, &pin, &confirmation, &error, &next);
        let page = Self { root, pin, confirmation, error, next, strings: *strings };
        page.submit_on_enter();
        page
    }

    pub fn widget(&self) -> &gtk::Widget {
        &self.root
    }

    pub fn reset(&self) {
        self.pin.set_text("");
        self.confirmation.set_text("");
        self.error.set_label("");
        self.next.set_sensitive(true);
    }

    pub fn reject(&self, error: PinError) {
        self.error.set_label(self.strings.get(error.text()));
        self.next.set_sensitive(true);
    }

    fn submit_on_enter(&self) {
        let next = self.next.clone();
        self.confirmation.connect_entry_activated(move |_| next.emit_clicked());
    }
}

fn layout(strings: &Strings, pin: &adw::PasswordEntryRow, confirmation: &adw::PasswordEntryRow, error: &gtk::Label, next: &gtk::Button) -> gtk::Widget {
    let title = gtk::Label::builder().label(strings.get(Text::PinTitle)).wrap(true).css_classes(["title-1"]).build();
    let body = gtk::Label::builder().label(strings.get(Text::PinBody)).wrap(true).css_classes(["dim-label"]).build();
    let list = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).css_classes(["boxed-list"]).build();
    list.append(pin);
    list.append(confirmation);
    let column = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(18).margin_top(24).margin_bottom(24).margin_start(24).margin_end(24).valign(gtk::Align::Center).build();
    for child in [title.upcast_ref::<gtk::Widget>(), body.upcast_ref(), list.upcast_ref(), error.upcast_ref(), next.upcast_ref()] {
        column.append(child);
    }
    adw::Clamp::builder().maximum_size(480).child(&column).build().upcast()
}
