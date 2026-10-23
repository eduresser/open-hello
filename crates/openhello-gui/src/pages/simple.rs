use gtk::prelude::*;
use openhello_gui_core::{Strings, Text};

use super::{pill_button, status_page};

pub fn welcome(strings: &Strings, on_start: impl Fn() + 'static) -> gtk::Widget {
    let page = status_page("avatar-default-symbolic", strings.get(Text::WelcomeTitle), strings.get(Text::WelcomeBody));
    page.set_child(Some(&pill_button(strings.get(Text::GetStarted), "suggested-action", on_start)));
    page.upcast()
}

pub fn identity(strings: &Strings) -> gtk::Widget {
    let page = status_page("dialog-password-symbolic", strings.get(Text::IdentityTitle), strings.get(Text::IdentityBody));
    page.set_child(Some(&gtk::Spinner::builder().spinning(true).width_request(32).height_request(32).halign(gtk::Align::Center).build()));
    page.upcast()
}

pub fn done(strings: &Strings, on_close: impl Fn() + 'static) -> gtk::Widget {
    let page = status_page("emblem-ok-symbolic", strings.get(Text::DoneTitle), strings.get(Text::DoneBody));
    page.set_child(Some(&pill_button(strings.get(Text::Close), "suggested-action", on_close)));
    page.upcast()
}
