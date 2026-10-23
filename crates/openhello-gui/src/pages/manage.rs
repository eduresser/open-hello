use adw::prelude::*;
use openhello_gui_core::{Strings, Text};

use super::{pill, status_page};

#[derive(Clone)]
struct Controls {
    spinner: gtk::Spinner,
    result: gtk::Label,
    buttons: [gtk::Button; 3],
}

impl Controls {
    fn busy(&self, text: &str) {
        self.spinner.start();
        self.result.set_label(text);
        self.set_sensitive(false);
    }

    fn idle(&self, text: &str) {
        self.spinner.stop();
        self.result.set_label(text);
        self.set_sensitive(true);
    }

    fn set_sensitive(&self, sensitive: bool) {
        for button in &self.buttons {
            button.set_sensitive(sensitive);
        }
    }
}

pub struct ManagePage {
    page: adw::StatusPage,
    controls: Controls,
    strings: Strings,
}

impl ManagePage {
    pub fn new(strings: &Strings, on_test: impl Fn() + 'static, on_remove: impl Fn() + 'static, on_setup: impl Fn() + 'static) -> Self {
        let page = status_page("avatar-default-symbolic", strings.get(Text::ManageTitle), strings.get(Text::ManageBody));
        let controls = Controls {
            spinner: gtk::Spinner::builder().halign(gtk::Align::Center).build(),
            result: gtk::Label::builder().css_classes(["title-3"]).build(),
            buttons: [pill(strings.get(Text::TestFace), "suggested-action"), pill(strings.get(Text::RemoveFace), "destructive-action"), pill(strings.get(Text::SetUpAgain), "flat")],
        };
        page.set_child(Some(&layout(&controls)));
        connect_test(strings, &controls, on_test);
        connect_remove(strings, &page, &controls, on_remove);
        controls.buttons[2].connect_clicked(move |_| on_setup());
        Self { page, controls, strings: *strings }
    }

    pub fn widget(&self) -> &gtk::Widget {
        self.page.upcast_ref()
    }

    pub fn reset(&self) {
        self.controls.idle("");
    }

    pub fn finish_test(&self, recognized: bool) {
        let text = if recognized { Text::Recognized } else { Text::NotRecognized };
        self.controls.idle(self.strings.get(text));
    }
}

fn layout(controls: &Controls) -> gtk::Box {
    let column = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(12).halign(gtk::Align::Center).build();
    column.append(&controls.spinner);
    column.append(&controls.result);
    for button in &controls.buttons {
        column.append(button);
    }
    column
}

fn connect_test(strings: &Strings, controls: &Controls, on_test: impl Fn() + 'static) {
    let (controls, testing) = (controls.clone(), strings.get(Text::Testing));
    controls.buttons[0].clone().connect_clicked(move |_| {
        controls.busy(testing);
        on_test();
    });
}

fn connect_remove(strings: &Strings, page: &adw::StatusPage, controls: &Controls, on_remove: impl Fn() + 'static) {
    let (strings, page_ref, controls) = (*strings, page.downgrade(), controls.clone());
    let on_remove = std::rc::Rc::new(on_remove);
    controls.buttons[1].clone().connect_clicked(move |_| {
        let Some(page) = page_ref.upgrade() else { return };
        let (controls, on_remove) = (controls.clone(), std::rc::Rc::clone(&on_remove));
        confirm_removal(&strings, &page, move || {
            controls.busy("");
            on_remove();
        });
    });
}

fn confirm_removal(strings: &Strings, parent: &impl IsA<gtk::Widget>, on_confirmed: impl Fn() + 'static) {
    let dialog = adw::AlertDialog::new(Some(strings.get(Text::RemoveConfirmTitle)), Some(strings.get(Text::RemoveConfirmBody)));
    dialog.add_responses(&[("cancel", strings.get(Text::Cancel)), ("remove", strings.get(Text::RemoveFace))]);
    dialog.set_response_appearance("remove", adw::ResponseAppearance::Destructive);
    dialog.set_default_response(Some("cancel"));
    dialog.set_close_response("cancel");
    dialog.choose(Some(parent), None::<&gtk::gio::Cancellable>, move |response| {
        if response == "remove" {
            on_confirmed();
        }
    });
}
