use gtk::prelude::*;
use openhello_gui_core::{FailureCause, Strings, Text};

use super::{pill_button, status_page};

pub struct ErrorPage {
    page: adw::StatusPage,
    strings: Strings,
}

impl ErrorPage {
    pub fn new(strings: &Strings, on_retry: impl Fn() + 'static) -> Self {
        let page = status_page("dialog-warning-symbolic", "", "");
        page.set_child(Some(&pill_button(strings.get(Text::TryAgain), "suggested-action", on_retry)));
        Self { page, strings: *strings }
    }

    pub fn widget(&self) -> &gtk::Widget {
        self.page.upcast_ref()
    }

    pub fn show(&self, cause: FailureCause) {
        self.page.set_title(self.strings.failure_title(cause));
        self.page.set_description(Some(self.strings.failure_explanation(cause)));
    }
}
