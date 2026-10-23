mod common;

use common::{error, fake, fresh, step, Calls, RECOVERY_CODE};
use openhello_gui_core::{ClientErrorKind, EnrollmentFlow, FailureCause, Frame, Language, Manager, RemoveOutcome, Status, Step, Text};

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
fn the_full_flow_visits_welcome_identity_capture_and_done_and_provisions_after_the_commit() {
    let (mut flow, calls) = open(fresh(), vec![step("accepted", "in-progress", 3), step("accepted", "complete", 6)]);
    let mut visited = vec![flow.step()];
    flow.start();
    visited.push(flow.step());
    flow.confirm_identity();
    visited.push(flow.step());
    flow.tick();
    flow.tick();
    visited.push(flow.step());
    assert_eq!(visited, [Step::Welcome, Step::Identity, Step::Capture, Step::Done]);
    assert_eq!(calls.borrow().events, ["ready", "status", "begin", "commit", "provision"]);
}

// @spec:AC-058
#[test]
fn the_recovery_code_returned_by_the_key_service_appears_in_no_state_and_no_text() {
    let (mut flow, _calls) = open(fresh(), vec![step("accepted", "complete", 6)]);
    let mut shown = vec![format!("{:?}", flow.step())];
    flow.start();
    shown.push(format!("{:?}", flow.step()));
    flow.confirm_identity();
    shown.push(format!("{:?}", flow.step()));
    let update = flow.tick().unwrap();
    shown.push(format!("{:?} {:?}", flow.step(), update));
    shown.push(format!("{:?} {:?}", flow.blocked(), flow.strings().get(Text::DoneTitle)));
    shown.push(flow.strings().get(Text::DoneBody).to_string());
    shown.extend(Text::ALL.iter().map(|text| flow.strings().get(*text).to_string()));
    assert_eq!(flow.step(), Step::Done);
    assert!(shown.iter().all(|line| !line.contains(RECOVERY_CODE)));
    let words = |line: &String| line.to_lowercase().split(|c: char| !c.is_alphanumeric()).map(String::from).collect::<Vec<_>>();
    assert!(shown.iter().flat_map(words).all(|word| word != "recovery" && word != "pin"));
}

// @spec:AC-058
#[test]
fn provisioning_is_skipped_when_the_key_already_exists() {
    let (mut flow, calls) = open(Status { face: false, key: true }, vec![step("accepted", "complete", 6)]);
    reach_capture(&mut flow);
    flow.tick();
    assert_eq!(flow.step(), Step::Done);
    assert_eq!(calls.borrow().provisions, 0);
    assert_eq!(calls.borrow().commits, 1);
}

// @spec:AC-059
#[test]
fn each_tick_returns_a_guidance_sentence_and_a_frame_and_progress_grows() {
    let script = vec![step("move-left", "in-progress", 0), step("accepted", "in-progress", 1), step("accepted", "in-progress", 2)];
    let (mut flow, _calls) = open(Status { face: false, key: true }, script);
    reach_capture(&mut flow);
    let first = flow.tick().unwrap();
    let second = flow.tick().unwrap();
    let third = flow.tick().unwrap();
    assert_eq!(first.guidance, "Move a little to your left");
    assert_eq!(second.guidance, "Hold still and look at the camera");
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
fn the_thirty_second_window_ending_shows_a_timeout_error_without_commit_and_try_again_restarts() {
    let (mut flow, calls) = open(Status { face: false, key: true }, vec![step("no-face", "failed", 1)]);
    reach_capture(&mut flow);
    flow.tick();
    assert_eq!(flow.step(), Step::Error(FailureCause::Timeout));
    assert!(flow.strings().failure_explanation(FailureCause::Timeout).contains("30 seconds"));
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
    assert_eq!(flow.step(), Step::Done);
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

fn blocked_welcome(face: bool) -> (EnrollmentFlow<common::FakeClient>, std::rc::Rc<std::cell::RefCell<Calls>>) {
    let (mut flow, calls) = open(Status { face, key: face }, vec![]);
    calls.borrow_mut().ready_error = Some(ClientErrorKind::CameraBusy);
    flow.start();
    flow.set_face(face);
    (flow, calls)
}

fn failed_enrollment() -> (EnrollmentFlow<common::FakeClient>, Manager<common::FakeClient>, std::rc::Rc<std::cell::RefCell<Calls>>) {
    let (mut client, calls) = fake(Status { face: true, key: true }, vec![]);
    client.begin_error = Some(ClientErrorKind::CameraBusy);
    let manager = Manager::new(common::sibling(&calls, Status { face: true, key: true }), 1000);
    let mut flow = EnrollmentFlow::new(client, 1000, Language::English);
    reach_capture(&mut flow);
    (flow, manager, calls)
}

// @spec:AC-071
#[test]
fn the_welcome_screen_offers_removal_only_when_the_status_says_a_face_is_set_up() {
    let (flow, _) = blocked_welcome(true);
    assert_eq!((flow.step(), flow.face_enrolled(), flow.removal_offered()), (Step::Welcome, true, true));
    let (flow, _) = blocked_welcome(false);
    assert_eq!((flow.step(), flow.face_enrolled(), flow.removal_offered()), (Step::Welcome, false, false));
}

// @spec:AC-071
#[test]
fn the_status_read_while_starting_decides_whether_removal_is_offered() {
    let (mut flow, _) = open(Status { face: true, key: true }, vec![]);
    flow.start();
    assert!(flow.face_enrolled());
    assert!(!flow.removal_offered());
}

// @spec:AC-071
#[test]
fn removal_is_not_offered_during_identity_or_capture() {
    let (mut flow, _) = open(Status { face: true, key: true }, vec![]);
    flow.start();
    assert_eq!(flow.step(), Step::Identity);
    assert!(!flow.removal_offered());
    flow.confirm_identity();
    assert_eq!(flow.step(), Step::Capture);
    assert!(!flow.removal_offered());
}

// @spec:AC-071
#[test]
fn every_error_screen_offers_removal_even_without_a_face() {
    for kind in [ClientErrorKind::CameraBusy, ClientErrorKind::SensorStuck, ClientErrorKind::NoCamera, ClientErrorKind::TpmUnavailable, ClientErrorKind::AuthDenied, ClientErrorKind::Other] {
        let (mut client, _) = fake(fresh(), vec![]);
        client.begin_error = Some(kind);
        let mut flow = EnrollmentFlow::new(client, 1000, Language::English);
        reach_capture(&mut flow);
        assert!(matches!(flow.step(), Step::Error(_)));
        assert!(!flow.face_enrolled());
        assert!(flow.removal_offered());
    }
    let (mut flow, _) = open(fresh(), vec![error(ClientErrorKind::CameraBusy)]);
    reach_capture(&mut flow);
    flow.tick();
    assert!(flow.removal_offered());
}

// @spec:AC-066
// @spec:AC-071
#[test]
fn a_confirmed_removal_from_an_error_screen_purges_once_and_restarts_with_the_face_not_set_up() {
    let (mut flow, mut manager, calls) = failed_enrollment();
    assert_eq!(flow.step(), Step::Error(FailureCause::CameraBusy));
    assert!(flow.removal_offered());
    let RemoveOutcome::Removed(status) = manager.remove(true) else { panic!("expected Removed") };
    assert!(!status.face);
    flow.reset_after_removal();
    flow.start();
    assert_eq!((flow.step(), flow.face_enrolled(), flow.removal_offered()), (Step::Identity, false, false));
    assert_eq!(calls.borrow().purges, 1);
    assert_eq!(calls.borrow().events.last(), Some(&"status"));
}

// @spec:AC-071
#[test]
fn a_removal_that_is_not_confirmed_never_purges_and_the_error_screen_keeps_the_link() {
    let (flow, mut manager, calls) = failed_enrollment();
    assert_eq!(manager.remove(false), RemoveOutcome::NotConfirmed);
    assert_eq!(calls.borrow().purges, 0);
    assert!(flow.removal_offered());
}

// @spec:AC-071
#[test]
fn a_failed_purge_is_reported_and_the_error_screen_still_offers_removal() {
    let (flow, mut manager, calls) = failed_enrollment();
    calls.borrow_mut().purge_error = Some(ClientErrorKind::AuthDenied);
    assert!(matches!(manager.remove(true), RemoveOutcome::Failed(error) if error.kind == ClientErrorKind::AuthDenied));
    assert_eq!(calls.borrow().purges, 1);
    assert!(flow.removal_offered());
}
