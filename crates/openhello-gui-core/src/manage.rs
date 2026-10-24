use crate::wizard::{ClientError, ClientResult, Status};

pub trait ManageClient {
    fn status(&mut self, uid: u32) -> ClientResult<Status>;
    fn verify(&mut self, uid: u32) -> ClientResult<bool>;
    fn purge(&mut self, uid: u32) -> ClientResult<()>;

    fn sudo_access(&mut self, _uid: u32) -> ClientResult<SudoAccess> {
        Ok(SudoAccess::Unavailable)
    }

    fn use_own_password_for_sudo(&mut self, _uid: u32) -> ClientResult<SudoAccess> {
        Ok(SudoAccess::Unavailable)
    }

    fn restore_root_password_for_sudo(&mut self, _uid: u32) -> ClientResult<SudoAccess> {
        Ok(SudoAccess::Unavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudoAccess {
    OwnPassword,
    RootPassword,
    Switched,
    Unavailable,
}

impl SudoAccess {
    pub fn parse(policy: &str) -> Self {
        match policy {
            "own-password" => SudoAccess::OwnPassword,
            "root-password" => SudoAccess::RootPassword,
            "switched" => SudoAccess::Switched,
            _ => SudoAccess::Unavailable,
        }
    }
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

    pub fn sudo_access(&mut self) -> SudoAccess {
        self.client.sudo_access(self.uid).unwrap_or(SudoAccess::Unavailable)
    }

    pub fn use_own_password_for_sudo(&mut self) -> Result<SudoAccess, ClientError> {
        self.client.use_own_password_for_sudo(self.uid)
    }

    pub fn restore_root_password_for_sudo(&mut self) -> Result<SudoAccess, ClientError> {
        self.client.restore_root_password_for_sudo(self.uid)
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
