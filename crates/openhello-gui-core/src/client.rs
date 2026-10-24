use openhello_cli::dbus_client::DbusClient;
use openhello_cli::keyd_client::KeydClient;
use openhello_cli::{Bus, Refusal};

use crate::manage::{ManageClient, SudoAccess};
use crate::wizard::{ClientError, ClientErrorKind, ClientResult, EnrollClient, Frame, Progress, Status};

pub struct DaemonClient {
    biometrics: DbusClient,
    keys: KeydClient,
}

impl DaemonClient {
    pub fn connect(bus: Bus) -> ClientResult<Self> {
        Ok(Self { biometrics: DbusClient::connect(bus).map_err(local)?, keys: KeydClient::connect(bus).map_err(local)? })
    }

    pub fn on_address(address: &str) -> ClientResult<Self> {
        Ok(Self { biometrics: DbusClient::on_address(address).map_err(local)?, keys: KeydClient::on_address(address).map_err(local)? })
    }

    fn read_status(&self, uid: u32) -> ClientResult<Status> {
        let face: bool = self.biometrics.call("GetStatus", &(uid,)).map_err(classify)?;
        let (key, _): (bool, bool) = self.keys.call("GetStatus", &(uid,)).map_err(classify)?;
        Ok(Status { face, key })
    }
}

fn local(message: String) -> ClientError {
    ClientError::new(ClientErrorKind::Other, message)
}

pub fn classify(refusal: Refusal) -> ClientError {
    let kind = match refusal.error_name.as_deref() {
        Some("io.openhello.Error.CameraBusy") => ClientErrorKind::CameraBusy,
        Some("io.openhello.Error.SensorStuck") => ClientErrorKind::SensorStuck,
        Some("io.openhello.Error.NoCamera") => ClientErrorKind::NoCamera,
        Some("io.openhello.Error.TpmUnavailable") => ClientErrorKind::TpmUnavailable,
        Some("org.freedesktop.DBus.Error.AuthFailed") => ClientErrorKind::AuthDenied,
        _ => ClientErrorKind::Other,
    };
    ClientError::new(kind, refusal.message)
}

impl EnrollClient for DaemonClient {
    fn check_ready(&mut self) -> ClientResult<()> {
        self.biometrics.call::<_, ()>("CheckReady", &()).map_err(classify)
    }

    fn status(&mut self, uid: u32) -> ClientResult<Status> {
        self.read_status(uid)
    }

    fn enroll_begin(&mut self, uid: u32) -> ClientResult<String> {
        self.biometrics.call("EnrollBegin", &(uid,)).map_err(classify)
    }

    fn enroll_capture(&mut self, handle: &str) -> ClientResult<Progress> {
        let (verdict, state, filled, required): (String, String, u32, u32) = self.biometrics.call("EnrollCapture", &(handle,)).map_err(classify)?;
        Ok(Progress { verdict, state, filled, required })
    }

    fn enroll_frame(&mut self, handle: &str) -> ClientResult<Frame> {
        let (pixels, width, height) = self.biometrics.enroll_frame(handle).map_err(classify)?;
        Ok(Frame { width, height, pixels })
    }

    fn enroll_commit(&mut self, handle: &str) -> ClientResult<()> {
        self.biometrics.call::<_, bool>("EnrollCommit", &(handle,)).map(|_| ()).map_err(classify)
    }

    fn enroll_discard(&mut self, handle: &str) -> ClientResult<()> {
        self.biometrics.call::<_, ()>("EnrollDiscard", &(handle,)).map_err(classify)
    }

    fn provision(&mut self, uid: u32) -> ClientResult<String> {
        self.keys.call("Provision", &(uid,)).map_err(classify)
    }
}

impl ManageClient for DaemonClient {
    fn status(&mut self, uid: u32) -> ClientResult<Status> {
        self.read_status(uid)
    }

    fn verify(&mut self, uid: u32) -> ClientResult<bool> {
        self.biometrics.call("Verify", &(uid,)).map_err(classify)
    }

    fn purge(&mut self, uid: u32) -> ClientResult<()> {
        self.biometrics.call::<_, bool>("Purge", &(uid,)).map(|_| ()).map_err(classify)
    }

    fn sudo_access(&mut self, uid: u32) -> ClientResult<SudoAccess> {
        let policy: String = self.biometrics.call("GetSudoPolicy", &(uid,)).map_err(classify)?;
        Ok(SudoAccess::parse(&policy))
    }

    fn use_own_password_for_sudo(&mut self, uid: u32) -> ClientResult<SudoAccess> {
        let policy: String = self.biometrics.call("UseOwnPasswordForSudo", &(uid,)).map_err(classify)?;
        Ok(SudoAccess::parse(&policy))
    }

    fn restore_root_password_for_sudo(&mut self, uid: u32) -> ClientResult<SudoAccess> {
        let policy: String = self.biometrics.call("RestoreRootPasswordForSudo", &(uid,)).map_err(classify)?;
        Ok(SudoAccess::parse(&policy))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind_of(name: Option<&str>) -> ClientErrorKind {
        classify(Refusal { error_name: name.map(String::from), message: "short".into() }).kind
    }

    // @spec:AC-061
    #[test]
    fn daemon_error_names_map_to_typed_failure_kinds_and_keep_the_short_message() {
        assert_eq!(kind_of(Some("io.openhello.Error.CameraBusy")), ClientErrorKind::CameraBusy);
        assert_eq!(kind_of(Some("io.openhello.Error.SensorStuck")), ClientErrorKind::SensorStuck);
        assert_eq!(kind_of(Some("io.openhello.Error.NoCamera")), ClientErrorKind::NoCamera);
        assert_eq!(kind_of(Some("io.openhello.Error.TpmUnavailable")), ClientErrorKind::TpmUnavailable);
        assert_eq!(kind_of(Some("org.freedesktop.DBus.Error.AuthFailed")), ClientErrorKind::AuthDenied);
        assert_eq!(kind_of(Some("org.freedesktop.DBus.Error.Failed")), ClientErrorKind::Other);
        assert_eq!(kind_of(None), ClientErrorKind::Other);
        assert_eq!(classify(Refusal::local("short")).message, "short");
    }
}
