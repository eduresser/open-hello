use std::cell::RefCell;
use std::rc::Rc;

use openhello_gui_core::{ClientError, ClientErrorKind, ClientResult, ManageClient, Manager, RemoveOutcome, Status, SudoAccess, TestOutcome};

#[derive(Default)]
struct Log {
    verifies: u32,
    purges: u32,
}

struct FakeManage {
    log: Rc<RefCell<Log>>,
    status: Status,
    verify: ClientResult<bool>,
    purge_error: Option<ClientError>,
}

fn enrolled() -> Status {
    Status { face: true, key: true }
}

fn manage(verify: ClientResult<bool>, purge_error: Option<ClientError>) -> (Manager<FakeManage>, Rc<RefCell<Log>>) {
    let log = Rc::new(RefCell::new(Log::default()));
    let client = FakeManage { log: log.clone(), status: enrolled(), verify, purge_error };
    (Manager::new(client, 1000), log)
}

impl ManageClient for FakeManage {
    fn status(&mut self, _: u32) -> ClientResult<Status> {
        Ok(self.status)
    }

    fn verify(&mut self, _: u32) -> ClientResult<bool> {
        self.log.borrow_mut().verifies += 1;
        self.verify.clone()
    }

    fn purge(&mut self, _: u32) -> ClientResult<()> {
        self.log.borrow_mut().purges += 1;
        match self.purge_error.clone() {
            Some(error) => Err(error),
            None => {
                self.status = Status { face: false, key: false };
                Ok(())
            }
        }
    }
}

// @spec:AC-065
#[test]
fn the_test_reports_recognized_when_the_daemon_matches_the_face() {
    let (mut manager, log) = manage(Ok(true), None);
    assert_eq!(manager.test(), TestOutcome::Recognized);
    assert_eq!(log.borrow().verifies, 1);
}

// @spec:AC-065
#[test]
fn the_test_reports_not_recognized_when_the_daemon_rejects_the_face() {
    let (mut manager, _) = manage(Ok(false), None);
    assert_eq!(manager.test(), TestOutcome::NotRecognized);
}

// @spec:AC-065
#[test]
fn the_test_reports_the_typed_failure_when_the_camera_cannot_be_used() {
    let error = ClientError::new(ClientErrorKind::CameraBusy, "camera is busy");
    let (mut manager, _) = manage(Err(error.clone()), None);
    assert_eq!(manager.test(), TestOutcome::Failed(error));
}

// @spec:AC-066
#[test]
fn removing_without_confirmation_does_not_touch_the_daemon() {
    let (mut manager, log) = manage(Ok(true), None);
    assert_eq!(manager.remove(false), RemoveOutcome::NotConfirmed);
    assert_eq!(log.borrow().purges, 0);
    assert_eq!(manager.status().unwrap(), enrolled());
}

// @spec:AC-066
#[test]
fn a_confirmed_removal_purges_once_and_reports_the_face_as_not_set_up() {
    let (mut manager, log) = manage(Ok(true), None);
    match manager.remove(true) {
        RemoveOutcome::Removed(status) => assert!(!status.face && !status.key),
        other => panic!("expected Removed, got {other:?}"),
    }
    assert_eq!(log.borrow().purges, 1);
    assert!(!manager.status().unwrap().face);
}

// @spec:AC-066
#[test]
fn a_denied_reauthentication_is_reported_as_a_failure_and_the_face_stays() {
    let error = ClientError::new(ClientErrorKind::AuthDenied, "not authorized");
    let (mut manager, log) = manage(Ok(true), Some(error.clone()));
    assert_eq!(manager.remove(true), RemoveOutcome::Failed(error));
    assert_eq!(log.borrow().purges, 1);
    assert!(manager.status().unwrap().face);
}

// @spec:AC-074
#[test]
fn testing_again_asks_the_daemon_again_each_time() {
    let (mut manager, log) = manage(Ok(false), None);
    assert_eq!(manager.test(), TestOutcome::NotRecognized);
    assert_eq!(manager.test(), TestOutcome::NotRecognized);
    assert_eq!(log.borrow().verifies, 2);
}

struct SudoOnly(ClientResult<SudoAccess>);

impl ManageClient for SudoOnly {
    fn status(&mut self, _: u32) -> ClientResult<Status> {
        Ok(enrolled())
    }

    fn verify(&mut self, _: u32) -> ClientResult<bool> {
        Ok(true)
    }

    fn purge(&mut self, _: u32) -> ClientResult<()> {
        Ok(())
    }

    fn sudo_access(&mut self, _: u32) -> ClientResult<SudoAccess> {
        self.0.clone()
    }
}

#[test]
fn daemon_policy_names_map_to_sudo_access_and_unknown_names_are_unavailable() {
    assert_eq!(SudoAccess::parse("own-password"), SudoAccess::OwnPassword);
    assert_eq!(SudoAccess::parse("root-password"), SudoAccess::RootPassword);
    assert_eq!(SudoAccess::parse("unavailable"), SudoAccess::Unavailable);
    assert_eq!(SudoAccess::parse("something-new"), SudoAccess::Unavailable);
}

#[test]
fn the_notice_is_due_only_when_sudo_asks_for_root_and_errors_hide_it() {
    let due = |answer| Manager::new(SudoOnly(answer), 1000).sudo_asks_root();
    assert!(due(Ok(SudoAccess::RootPassword)));
    assert!(!due(Ok(SudoAccess::OwnPassword)));
    assert!(!due(Ok(SudoAccess::Unavailable)));
    assert!(!due(Err(ClientError::new(ClientErrorKind::AuthDenied, "denied"))));
    let (mut legacy, _) = manage(Ok(true), None);
    assert!(!legacy.sudo_asks_root());
}
