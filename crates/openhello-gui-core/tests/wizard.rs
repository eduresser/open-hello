mod common;

use common::{error, fake, fresh, step, Calls};
use openhello_gui_core::{ClientErrorKind, EnrollmentFlow, FailureCause, Frame, Language, Status, Step};

fn open(status: Status, progress: Vec<openhello_gui_core::ClientResult<openhello_gui_core::Progress>>) -> (EnrollmentFlow<common::FakeClient>, std::rc::Rc<std::cell::RefCell<Calls>>) {
    let (client, calls) = fake(status, progress);
    (EnrollmentFlow::new(client, 1000, Language::English), calls)
}

fn reach_capture(flow: &mut EnrollmentFlow<common::FakeClient>) {
    flow.start();
    flow.confirm_identity();
}

// @spec:AC-058
#[test]
fn the_full_flow_visits_every_step_in_the_windows_hello_order() {
    let (mut flow, calls) = open(fresh(), vec![step("accepted", "in-progress", 3), step("accepted", "complete", 6)]);
    let mut visited = vec![flow.step()];
    flow.start();
    visited.push(flow.step());
    flow.confirm_identity();
    visited.push(flow.step());
    flow.tick();
    flow.tick();
    visited.push(flow.step());
    assert_eq!(flow.recovery_code(), Some("RECOVERY-CODE"));
    flow.acknowledge_recovery_code();
    visited.push(flow.step());
    assert_eq!(visited, [Step::Welcome, Step::Identity, Step::Capture, Step::RecoveryCode, Step::Done]);
    assert_eq!(calls.borrow().events, ["ready", "status", "begin", "commit", "provision"]);
    assert_eq!(flow.recovery_code(), None);
}

// @spec:AC-058
#[test]
fn provisioning_and_the_recovery_code_are_skipped_when_the_key_already_exists() {
    let (mut flow, calls) = open(Status { face: false, key: true }, vec![step("accepted", "complete", 6)]);
    reach_capture(&mut flow);
    flow.tick();
    assert_eq!(flow.step(), Step::Done);
    assert_eq!(calls.borrow().provisions, 0);
    assert_eq!(calls.borrow().commits, 1);
    assert_eq!(flow.recovery_code(), None);
}

// @spec:AC-059
#[test]
fn each_tick_returns_a_guidance_sentence_progress_text_and_a_frame_and_progress_grows() {
    let script = vec![step("move-left", "in-progress", 0), step("accepted", "in-progress", 1), step("accepted", "in-progress", 2)];
    let (mut flow, _calls) = open(Status { face: false, key: true }, script);
    reach_capture(&mut flow);
    let first = flow.tick().unwrap();
    let second = flow.tick().unwrap();
    let third = flow.tick().unwrap();
    assert_eq!(first.guidance, "Move a little to your left");
    assert_eq!(first.progress_text, "0 of 6");
    assert_eq!(second.guidance, "Hold still and look at the camera");
    assert_eq!(third.progress_text, "2 of 6");
    assert!(third.filled > second.filled && second.filled > first.filled);
    assert_eq!(third.frame, Some(Frame { width: 2, height: 2, pixels: vec![1, 2, 3, 4] }));
    assert_eq!(flow.step(), Step::Capture);
}

// @spec:AC-059
// @principle:P-010
#[test]
fn the_frame_debug_output_never_contains_the_pixels() {
    let frame = Frame { width: 640, height: 360, pixels: vec![171; 8] };
    let shown = format!("{frame:?} {:?}", Some(frame.clone()));
    assert!(shown.contains("640") && shown.contains("360") && shown.contains("len: 8"));
    assert!(!shown.contains("171"));
}

// @spec:AC-061
#[test]
fn the_twenty_second_window_ending_shows_a_timeout_error_without_commit_and_try_again_restarts() {
    let (mut flow, calls) = open(Status { face: false, key: true }, vec![step("no-face", "failed", 1)]);
    reach_capture(&mut flow);
    flow.tick();
    assert_eq!(flow.step(), Step::Error(FailureCause::Timeout));
    assert!(flow.strings().failure_explanation(FailureCause::Timeout).contains("20 seconds"));
    assert_eq!(calls.borrow().commits, 0);
    flow.retry();
    assert_eq!(flow.step(), Step::Welcome);
    assert_eq!(calls.borrow().commits, 0);
    assert_eq!(calls.borrow().provisions, 0);
}

// @spec:AC-061
#[test]
fn a_busy_camera_and_a_stuck_sensor_explain_what_to_do_and_never_commit() {
    for (kind, cause, expected) in [
        (ClientErrorKind::CameraBusy, FailureCause::CameraBusy, "Close it and try again"),
        (ClientErrorKind::SensorStuck, FailureCause::SensorStuck, "Shut the computer down completely"),
        (ClientErrorKind::NoCamera, FailureCause::NoCamera, "No infrared camera was detected"),
        (ClientErrorKind::TpmUnavailable, FailureCause::TpmUnavailable, "TPM"),
    ] {
        let (mut flow, calls) = open(Status { face: false, key: true }, vec![error(kind)]);
        reach_capture(&mut flow);
        assert!(flow.tick().is_none());
        assert_eq!(flow.step(), Step::Error(cause));
        assert!(flow.strings().failure_explanation(cause).contains(expected));
        assert_eq!(calls.borrow().commits, 0);
        flow.retry();
        assert_eq!(flow.step(), Step::Welcome);
    }
}

// @spec:AC-061
#[test]
fn a_camera_that_is_busy_when_the_session_starts_is_an_error_without_a_session_to_discard() {
    let (mut client, calls) = fake(fresh(), vec![]);
    client.begin_error = Some(ClientErrorKind::CameraBusy);
    let mut flow = EnrollmentFlow::new(client, 1000, Language::English);
    flow.start();
    flow.confirm_identity();
    assert_eq!(flow.step(), Step::Error(FailureCause::CameraBusy));
    assert!(flow.strings().failure_explanation(FailureCause::CameraBusy).contains("Close it"));
    drop(flow);
    assert_eq!(calls.borrow().discards, 0);
    assert_eq!(calls.borrow().commits, 0);
}

// @spec:AC-061
#[test]
fn a_provision_failure_after_the_commit_offers_to_repeat_only_the_provision() {
    let (mut client, calls) = fake(Status { face: false, key: false }, vec![step("accepted", "complete", 6)]);
    client.provision_failures = 1;
    let mut flow = EnrollmentFlow::new(client, 1000, Language::English);
    reach_capture(&mut flow);
    flow.tick();
    assert_eq!(flow.step(), Step::Error(FailureCause::KeyFailed));
    flow.retry();
    assert_eq!(flow.step(), Step::RecoveryCode);
    assert_eq!(flow.recovery_code(), Some("RECOVERY-CODE"));
    assert_eq!(calls.borrow().commits, 1);
    assert_eq!(calls.borrow().provisions, 2);
    assert_eq!(calls.borrow().discards, 0);
}

// @spec:AC-062
#[test]
fn cancel_during_capture_discards_exactly_once_even_when_the_flow_is_dropped_after() {
    let (mut flow, calls) = open(Status { face: false, key: true }, vec![step("accepted", "in-progress", 2)]);
    reach_capture(&mut flow);
    flow.tick();
    flow.cancel();
    flow.cancel();
    assert_eq!(calls.borrow().discards, 1);
    assert_eq!(flow.step(), Step::Welcome);
    drop(flow);
    assert_eq!(calls.borrow().discards, 1);
    assert_eq!(calls.borrow().commits, 0);
}

// @spec:AC-062
#[test]
fn dropping_an_active_flow_discards_exactly_once() {
    let (mut flow, calls) = open(Status { face: false, key: true }, vec![]);
    reach_capture(&mut flow);
    drop(flow);
    assert_eq!(calls.borrow().discards, 1);
    assert_eq!(calls.borrow().commits, 0);
}

// @spec:AC-062
#[test]
fn nothing_is_discarded_after_a_commit_or_when_no_session_was_started() {
    let (mut flow, calls) = open(Status { face: false, key: true }, vec![step("accepted", "complete", 6)]);
    reach_capture(&mut flow);
    flow.tick();
    flow.cancel();
    drop(flow);
    assert_eq!(calls.borrow().discards, 0);
    assert_eq!(calls.borrow().commits, 1);
    let (flow, calls) = open(fresh(), vec![]);
    drop(flow);
    assert_eq!(calls.borrow().discards, 0);
}

// @spec:AC-070
#[test]
fn an_unavailable_recognition_blocks_the_welcome_screen_with_the_cause_and_creates_no_session() {
    for (kind, cause) in [
        (ClientErrorKind::NoCamera, FailureCause::NoCamera),
        (ClientErrorKind::CameraBusy, FailureCause::CameraBusy),
        (ClientErrorKind::TpmUnavailable, FailureCause::TpmUnavailable),
        (ClientErrorKind::Other, FailureCause::Other),
    ] {
        let (mut flow, calls) = open(fresh(), vec![]);
        calls.borrow_mut().ready_error = Some(kind);
        flow.start();
        assert_eq!(flow.step(), Step::Welcome);
        assert_eq!(flow.blocked(), Some(cause));
        assert!(!flow.strings().failure_explanation(cause).is_empty());
        assert!(!flow.strings().blocked_title().is_empty());
        flow.confirm_identity();
        assert_eq!(flow.step(), Step::Welcome);
        assert_eq!(calls.borrow().begins, 0);
        assert_eq!(calls.borrow().events, ["ready"]);
        drop(flow);
        assert_eq!(calls.borrow().discards, 0);
    }
}

// @spec:AC-070
#[test]
fn a_ready_computer_is_not_blocked_and_the_flow_proceeds_after_the_check() {
    let (mut flow, calls) = open(fresh(), vec![]);
    flow.start();
    assert_eq!(flow.blocked(), None);
    assert_eq!(flow.step(), Step::Identity);
    flow.confirm_identity();
    assert_eq!(flow.step(), Step::Capture);
    assert_eq!(calls.borrow().events, ["ready", "status", "begin"]);
}

// @spec:AC-070
#[test]
fn a_status_that_cannot_be_read_blocks_with_the_generic_cause() {
    let (mut flow, calls) = open(fresh(), vec![]);
    calls.borrow_mut().status_error = true;
    flow.start();
    assert_eq!(flow.step(), Step::Welcome);
    assert_eq!(flow.blocked(), Some(FailureCause::Other));
    flow.confirm_identity();
    assert_eq!(calls.borrow().begins, 0);
}

// @spec:AC-070
#[test]
fn retry_rechecks_and_unblocks_once_the_cause_is_fixed() {
    let (mut flow, calls) = open(fresh(), vec![]);
    calls.borrow_mut().ready_error = Some(ClientErrorKind::CameraBusy);
    flow.start();
    flow.retry();
    assert_eq!(flow.blocked(), Some(FailureCause::CameraBusy));
    assert_eq!(calls.borrow().events, ["ready", "ready"]);
    calls.borrow_mut().ready_error = None;
    flow.retry();
    assert_eq!(flow.blocked(), None);
    assert_eq!(flow.step(), Step::Identity);
    assert_eq!(calls.borrow().begins, 0);
}
