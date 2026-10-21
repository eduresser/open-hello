use zbus::blocking::{Connection, Proxy};

use crate::{BiometricsClient, Bus, Progress};

const BUS_NAME: &str = "io.openhello.Biometrics1";
const OBJECT_PATH: &str = "/io/openhello/Biometrics1";

pub struct DbusClient {
    connection: Connection,
}

impl DbusClient {
    pub fn connect(bus: Bus) -> Result<Self, String> {
        let connection = match bus {
            Bus::System => Connection::system(),
            Bus::Session => Connection::session(),
        }
        .map_err(|e| format!("cannot connect to the {bus:?} bus: {e}"))?;
        Ok(Self { connection })
    }

    pub fn on_address(address: &str) -> Result<Self, String> {
        let connection = zbus::blocking::connection::Builder::address(address)
            .and_then(|b| b.build())
            .map_err(|e| format!("cannot connect to bus at {address}: {e}"))?;
        Ok(Self { connection })
    }

    fn proxy(&self) -> Result<Proxy<'_>, String> {
        Proxy::new(&self.connection, BUS_NAME, OBJECT_PATH, BUS_NAME).map_err(|e| format!("cannot reach {BUS_NAME}: {e}"))
    }
}

fn describe(method: &str, error: zbus::Error) -> String {
    match error {
        zbus::Error::MethodError(name, detail, _) => {
            format!("{method} refused ({}): {}", name.as_str(), detail.as_deref().unwrap_or("no detail"))
        }
        other => format!("{method} failed: {other}"),
    }
}

impl BiometricsClient for DbusClient {
    fn enroll_begin(&mut self, uid: u32) -> Result<String, String> {
        self.proxy()?.call("EnrollBegin", &(uid,)).map_err(|e| describe("EnrollBegin", e))
    }

    fn enroll_capture(&mut self, handle: &str) -> Result<Progress, String> {
        let (verdict, state, filled, required): (String, String, u32, u32) =
            self.proxy()?.call("EnrollCapture", &(handle,)).map_err(|e| describe("EnrollCapture", e))?;
        Ok(Progress { verdict, state, filled, required })
    }

    fn enroll_commit(&mut self, handle: &str) -> Result<(), String> {
        self.proxy()?.call::<_, _, bool>("EnrollCommit", &(handle,)).map(|_| ()).map_err(|e| describe("EnrollCommit", e))
    }

    fn enroll_discard(&mut self, handle: &str) -> Result<(), String> {
        self.proxy()?.call::<_, _, ()>("EnrollDiscard", &(handle,)).map_err(|e| describe("EnrollDiscard", e))
    }

    fn verify(&mut self, uid: u32) -> Result<bool, String> {
        self.proxy()?.call("Verify", &(uid,)).map_err(|e| describe("Verify", e))
    }

    fn identify(&mut self) -> Result<Option<u32>, String> {
        let (found, uid): (bool, u32) = self.proxy()?.call("Identify", &()).map_err(|e| describe("Identify", e))?;
        Ok(found.then_some(uid))
    }

    fn purge(&mut self, uid: u32) -> Result<(), String> {
        self.proxy()?.call::<_, _, bool>("Purge", &(uid,)).map(|_| ()).map_err(|e| describe("Purge", e))
    }
}
