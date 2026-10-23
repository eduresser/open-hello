use crate::wizard::{ClientError, ClientResult, Status};

pub trait ManageClient {
    fn status(&mut self, uid: u32) -> ClientResult<Status>;
    fn verify(&mut self, uid: u32) -> ClientResult<bool>;
    fn purge(&mut self, uid: u32) -> ClientResult<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestOutcome {
    Recognized,
    NotRecognized,
    Failed(ClientError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveOutcome {
    NotConfirmed,
    Removed(Status),
    Failed(ClientError),
}

pub struct Manager<C: ManageClient> {
    client: C,
    uid: u32,
}

impl<C: ManageClient> Manager<C> {
    pub fn new(client: C, uid: u32) -> Self {
        Self { client, uid }
    }

    pub fn status(&mut self) -> ClientResult<Status> {
        self.client.status(self.uid)
    }

    pub fn test(&mut self) -> TestOutcome {
        match self.client.verify(self.uid) {
            Ok(true) => TestOutcome::Recognized,
            Ok(false) => TestOutcome::NotRecognized,
            Err(error) => TestOutcome::Failed(error),
        }
    }

    pub fn remove(&mut self, confirmed: bool) -> RemoveOutcome {
        if !confirmed {
            return RemoveOutcome::NotConfirmed;
        }
        match self.client.purge(self.uid).and_then(|()| self.status()) {
            Ok(status) => RemoveOutcome::Removed(status),
            Err(error) => RemoveOutcome::Failed(error),
        }
    }
}
