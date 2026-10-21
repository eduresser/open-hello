#![allow(non_snake_case, clippy::missing_safety_doc)]

pub mod config;
pub mod proxy;

use std::time::Duration;

use cryptoki_sys::{CKR_ARGUMENTS_BAD, CKR_OK, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR_PTR, CK_RV};
use zbus::blocking::{Connection, Proxy};

pub use config::{Settings, CONFIG_ENV, PLACEHOLDER_PIN, TEST_BUS_ADDRESS_ENV, TOKEN_SOCKET_ENV};

// Face matching must finish inside the 5 s the PAM stack allows before falling through to the password.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(4);
const BUS_NAME: &str = "io.openhello.Biometrics1";
const OBJECT_PATH: &str = "/io/openhello/Biometrics1";

#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(out: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *out = proxy::function_list() as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST;
    CKR_OK
}

pub(crate) fn verify_face(uid: u32, bus_address: Option<&str>) -> Result<bool, ()> {
    let address = bus_address.map(str::to_string);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(call_verify(uid, address.as_deref()));
    });
    receiver.recv_timeout(VERIFY_TIMEOUT).map_err(|_| ())?
}

fn call_verify(uid: u32, bus_address: Option<&str>) -> Result<bool, ()> {
    let connection = connect_bus(bus_address).ok_or(())?;
    let proxy = Proxy::new(&connection, BUS_NAME, OBJECT_PATH, BUS_NAME).map_err(|_| ())?;
    proxy.call("Verify", &(uid,)).map_err(|_| ())
}

fn connect_bus(address: Option<&str>) -> Option<Connection> {
    if let Some(address) = address {
        return zbus::blocking::connection::Builder::address(address)
            .and_then(|builder| builder.build())
            .ok();
    }
    Connection::system().ok()
}
