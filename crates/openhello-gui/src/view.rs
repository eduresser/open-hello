use openhello_gui_core::{FailureCause, Strings, TestOutcome, Text};
use slint::{ComponentHandle, Image, Rgb8Pixel, SharedPixelBuffer, SharedString};

use crate::backend::Event;
use crate::gate;
use crate::capture::CaptureView;
use crate::{trace, MainWindow, Page, T};

pub fn init(window: &MainWindow, strings: &Strings) {
    let texts = window.global::<T>();
    let get = |text: Text| SharedString::from(strings.get(text));
    texts.set_window_title(get(Text::ManageTitle));
    texts.set_welcome_title(get(Text::WelcomeTitle));
    texts.set_welcome_body(get(Text::WelcomeBody));
    texts.set_set_up(get(Text::SetUp));
    texts.set_cancel(get(Text::Cancel));
    texts.set_try_again(get(Text::TryAgain));
    texts.set_identity_title(get(Text::IdentityTitle));
    texts.set_identity_body(get(Text::IdentityBody));
    texts.set_capture_title(get(Text::CaptureTitle));
    texts.set_done_title(get(Text::DoneTitle));
    texts.set_done_body(get(Text::DoneBody));
    texts.set_manage_body(get(Text::ManageBody));
    texts.set_test(get(Text::TestFace));
    texts.set_testing(get(Text::Testing));
    texts.set_delete(get(Text::DeleteFace));
    texts.set_delete_data(get(Text::DeleteFaceData));
    texts.set_delete_confirm_title(get(Text::DeleteConfirmTitle));
    texts.set_delete_confirm_body(get(Text::DeleteConfirmBody));
    texts.set_set_up_again(get(Text::SetUpAgain));
}

pub fn apply(window: &MainWindow, strings: &Strings, event: Event) {
    let name = event.name();
    handle(window, strings, event);
    trace::log(format!("ui applied {name}, page {:?}", window.get_page()));
}

fn handle(window: &MainWindow, strings: &Strings, event: Event) {
    match event {
        Event::Welcome { blocked } => show_welcome(window, strings, blocked),
        Event::Identity => show(window, Page::Identity),
        Event::CaptureStarted => show_capture_start(window),
        Event::Capture(view) => show_capture(window, view),
        Event::Done => show(window, Page::Done),
        Event::Failed(cause) => show_failure(window, strings, cause),
        Event::Manage { blocked } => show_manage(window, strings, blocked),
        Event::TestResult(outcome) => show_test_result(window, strings, &outcome),
    }
}

fn show(window: &MainWindow, page: Page) {
    window.set_page(page);
    gate::settle(window);
    window.set_test_result(SharedString::new());
    window.set_confirming(false);
}

fn set_blocked(window: &MainWindow, strings: &Strings, cause: Option<FailureCause>) {
    window.set_blocked(cause.is_some());
    if let Some(cause) = cause {
        window.set_blocked_title(strings.blocked_title().into());
        window.set_blocked_body(strings.failure_explanation(cause).into());
    }
}

fn show_welcome(window: &MainWindow, strings: &Strings, cause: Option<FailureCause>) {
    set_blocked(window, strings, cause);
    show(window, Page::Welcome);
}

fn show_manage(window: &MainWindow, strings: &Strings, cause: Option<FailureCause>) {
    set_blocked(window, strings, cause);
    show(window, Page::Manage);
}

fn show_failure(window: &MainWindow, strings: &Strings, cause: FailureCause) {
    window.set_error_title(strings.failure_title(cause).into());
    window.set_error_body(strings.failure_explanation(cause).into());
    show(window, Page::Error);
}

fn show_capture_start(window: &MainWindow) {
    window.set_frame(Image::default());
    window.set_guidance(SharedString::new());
    window.set_progress(0.0);
    window.set_accepted(false);
    show(window, Page::Capture);
}

fn show_capture(window: &MainWindow, view: CaptureView) {
    window.set_guidance(view.guidance.into());
    window.set_accepted(view.accepted);
    window.set_progress(view.progress);
    if let Some(buffer) = view.frame {
        window.set_frame(image_of(buffer));
        crate::stats::count_preview();
    }
}

fn image_of(buffer: SharedPixelBuffer<Rgb8Pixel>) -> Image {
    Image::from_rgb8(buffer)
}

fn show_test_result(window: &MainWindow, strings: &Strings, outcome: &TestOutcome) {
    show_manage(window, strings, None);
    window.set_test_result(strings.test_message(outcome).into());
}
