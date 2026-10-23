use zbus::blocking::{Connection, Proxy};

use zbus::zvariant::{DynamicDeserialize, DynamicType};

use crate::{Bus, KeyClient, KeyStatus, Refusal};

const BUS_NAME: &str = "io.openhello.Keyd1";
const OBJECT_PATH: &str = "/io/openhello/Keyd1";

pub struct KeydClient {
    connection: Connection,
}

impl KeydClient {
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
        Proxy::new(&self.connection, BUS_NAME, OBJECT_PATH, BUS_NAME)
            .map_err(|e| format!("cannot reach {BUS_NAME}: {e}"))
    }

    pub fn call<B, R>(&self, method: &str, body: &B) -> Result<R, Refusal>
    where
        B: serde::Serialize + DynamicType,
        R: for<'d> DynamicDeserialize<'d>,
    {
        self.proxy().map_err(Refusal::local)?.call(method, body).map_err(|e| refuse(method, e))
    }
}

fn refuse(method: &str, error: zbus::Error) -> Refusal {
    match error {
        zbus::Error::MethodError(name, _, _) => Refusal { error_name: Some(name.to_string()), message: format!("{method} refused ({})", name.as_str()) },
        other => Refusal::local(format!("{method} failed: {other}")),
    }
}

fn describe(method: &str, error: zbus::Error) -> String {
    refuse(method, error).message
}

impl KeyClient for KeydClient {
    fn provision(&mut self, uid: u32) -> Result<String, String> {
        self.proxy()?
            .call("Provision", &(uid,))
            .map_err(|e| describe("Provision", e))
    }

    fn set_pin(&mut self, uid: u32, pin: &str) -> Result<(), String> {
        self.proxy()?
            .call::<_, _, bool>("SetPin", &(uid, pin))
            .map(|_| ())
            .map_err(|e| describe("SetPin", e))
    }

    fn key_status(&mut self, uid: u32) -> Result<KeyStatus, String> {
        let (key, pin): (bool, bool) = self
            .proxy()?
            .call("GetStatus", &(uid,))
            .map_err(|e| describe("GetStatus", e))?;
        Ok(KeyStatus { key, pin })
    }
}
