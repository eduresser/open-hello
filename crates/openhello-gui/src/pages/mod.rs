pub mod error;
pub mod manage;
pub mod pin;
pub mod recovery;
pub mod simple;

use gtk::prelude::*;

pub fn pill(label: &str, style: &str) -> gtk::Button {
    gtk::Button::builder().label(label).halign(gtk::Align::Center).css_classes(["pill", style]).build()
}

pub fn pill_button(label: &str, style: &str, on_click: impl Fn() + 'static) -> gtk::Button {
    let button = pill(label, style);
    button.connect_clicked(move |_| on_click());
    button
}

pub fn status_page(icon: &str, title: &str, body: &str) -> adw::StatusPage {
    adw::StatusPage::builder().icon_name(icon).title(title).description(body).build()
}
