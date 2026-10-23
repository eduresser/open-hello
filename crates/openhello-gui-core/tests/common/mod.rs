use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use openhello_gui_core::{ClientError, ClientErrorKind, ClientResult, EnrollClient, Frame, Progress, Status};

#[derive(Default)]
pub struct Calls {
    pub discards: u32,
    pub commits: u32,
    pub provisions: u32,
    pub events: Vec<&'static str>,
}

pub struct FakeClient {
    pub calls: Rc<RefCell<Calls>>,
    pub status: Status,
    pub progress: VecDeque<ClientResult<Progress>>,
    pub begin_error: Option<ClientErrorKind>,
    pub provision_failures: u32,
}

pub fn fake(status: Status, progress: Vec<ClientResult<Progress>>) -> (FakeClient, Rc<RefCell<Calls>>) {
    let calls = Rc::new(RefCell::new(Calls::default()));
    let client = FakeClient { calls: calls.clone(), status, progress: progress.into(), begin_error: None, provision_failures: 0 };
    (client, calls)
}

pub fn fresh() -> Status {
    Status { face: false, key: false }
}

pub fn step(verdict: &str, state: &str, filled: u32) -> ClientResult<Progress> {
    Ok(Progress { verdict: verdict.into(), state: state.into(), filled, required: 6 })
}

pub fn error(kind: ClientErrorKind) -> ClientResult<Progress> {
    Err(ClientError::new(kind, "detail"))
}

impl EnrollClient for FakeClient {
    fn status(&mut self, _uid: u32) -> ClientResult<Status> {
        self.calls.borrow_mut().events.push("status");
        Ok(self.status)
    }

    fn enroll_begin(&mut self, _uid: u32) -> ClientResult<String> {
        self.calls.borrow_mut().events.push("begin");
        match self.begin_error {
            Some(kind) => Err(ClientError::new(kind, "detail")),
            None => Ok("session-1".into()),
        }
    }

    fn enroll_capture(&mut self, _handle: &str) -> ClientResult<Progress> {
        self.progress.pop_front().unwrap_or_else(|| step("accepted", "in-progress", 0))
    }

    fn enroll_frame(&mut self, _handle: &str) -> ClientResult<Frame> {
        Ok(Frame { width: 2, height: 2, pixels: vec![1, 2, 3, 4] })
    }

    fn enroll_commit(&mut self, _handle: &str) -> ClientResult<()> {
        let mut calls = self.calls.borrow_mut();
        calls.commits += 1;
        calls.events.push("commit");
        Ok(())
    }

    fn enroll_discard(&mut self, _handle: &str) -> ClientResult<()> {
        self.calls.borrow_mut().discards += 1;
        Ok(())
    }

    fn provision(&mut self, _uid: u32) -> ClientResult<String> {
        let mut calls = self.calls.borrow_mut();
        calls.provisions += 1;
        calls.events.push("provision");
        if self.provision_failures > 0 {
            self.provision_failures -= 1;
            return Err(ClientError::new(ClientErrorKind::Other, "detail"));
        }
        Ok("RECOVERY-CODE".into())
    }
}
