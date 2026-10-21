#![allow(non_snake_case, clippy::missing_safety_doc)]

pub mod config;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use cryptoki_sys::{
    CK_C_GetFunctionList, CKR_BUFFER_TOO_SMALL, CKR_GENERAL_ERROR, CKR_OK, CKR_PIN_INCORRECT,
    CKR_USER_TYPE_INVALID, CKU_USER, CK_BBOOL, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR,
    CK_FUNCTION_LIST_PTR_PTR, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_SLOT_ID_PTR, CK_TOKEN_INFO,
    CK_ULONG, CK_ULONG_PTR, CK_USER_TYPE, CK_UTF8CHAR_PTR,
};
use libloading::Library;
use zbus::blocking::{Connection, Proxy};
use zeroize::Zeroizing;

pub use config::{
    Settings, CONFIG_ENV, PLACEHOLDER_PIN, REAL_MODULE_ENV, TEST_BUS_ADDRESS_ENV, UNLOCK_SOCKET_ENV,
};

const OP_TAKE_GRANT: u8 = 1;
const OP_UNLOCK_PIN: u8 = 2;
const OP_UNLOCK_FOR_UID: u8 = 4;
const TOKEN_LABEL_PREFIX: &str = "openhello-";
const TOKEN_LABEL_LEN: usize = 32;
// Face matching must finish inside the 5 s the PAM stack allows before falling through to the password.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(4);
const STATUS_ACCEPTED: u8 = 1;
const MAX_PIN_LEN: usize = 64;
const MAX_REPLY: usize = 128;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(15);
const BUS_NAME: &str = "io.openhello.Biometrics1";
const OBJECT_PATH: &str = "/io/openhello/Biometrics1";

type RealLogin =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV;

type RealSlotList = unsafe extern "C" fn(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR) -> CK_RV;
type RealTokenInfo = unsafe extern "C" fn(CK_SLOT_ID, *mut CK_TOKEN_INFO) -> CK_RV;

struct Module {
    _library: Library,
    table: CK_FUNCTION_LIST,
    login: RealLogin,
    get_slot_list: RealSlotList,
    get_token_info: RealTokenInfo,
    settings: Settings,
}

static MODULE: OnceLock<Option<Module>> = OnceLock::new();

fn module() -> Option<&'static Module> {
    MODULE.get_or_init(load_module).as_ref()
}

fn load_module() -> Option<Module> {
    let settings = config::current(&config::process_env, Path::new(config::DEFAULT_CONFIG)).ok()?;
    let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    if config::is_privileged(ruid, euid) {
        pin_token_store(&settings);
    }
    let library = unsafe { Library::new(settings.module.clone()?) }.ok()?;
    let mut table = unsafe {
        let get_list: libloading::Symbol<CK_C_GetFunctionList> =
            library.get(b"C_GetFunctionList\0").ok()?;
        let mut list: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
        if get_list.as_ref()?(&mut list) != CKR_OK || list.is_null() {
            return None;
        }
        *list
    };
    let login = table.C_Login?;
    let get_slot_list = table.C_GetSlotList?;
    let get_token_info = table.C_GetTokenInfo?;
    table.C_Login = Some(login_override);
    table.C_GetSlotList = Some(slot_list_override);
    Some(Module {
        _library: library,
        table,
        login,
        get_slot_list,
        get_token_info,
        settings,
    })
}

// tpm2-pkcs11 reads its store from the environment, which a setuid caller controls.
fn pin_token_store(settings: &Settings) {
    for name in [
        "TPM2_PKCS11_STORE",
        "TPM2_PKCS11_TCTI",
        "TPM2_PKCS11_BACKEND",
    ] {
        std::env::remove_var(name);
    }
    if let Some(store) = &settings.store_dir {
        std::env::set_var("TPM2_PKCS11_STORE", store);
        std::env::set_var("TPM2_PKCS11_BACKEND", "esysdb");
    }
    if let Some(tcti) = &settings.tcti {
        std::env::set_var("TPM2_PKCS11_TCTI", tcti);
    }
}

unsafe extern "C" fn slot_list_override(
    token_present: CK_BBOOL,
    slots: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    let Some(module) = module() else {
        return CKR_GENERAL_ERROR;
    };
    if count.is_null() {
        return CKR_GENERAL_ERROR;
    }
    let mut total: CK_ULONG = 0;
    let rv = (module.get_slot_list)(token_present, std::ptr::null_mut(), &mut total);
    if rv != CKR_OK {
        return rv;
    }
    let mut all: Vec<CK_SLOT_ID> = vec![0; total as usize];
    let rv = (module.get_slot_list)(token_present, all.as_mut_ptr(), &mut total);
    if rv != CKR_OK {
        return rv;
    }
    all.truncate(total as usize);
    let wanted = format!("{TOKEN_LABEL_PREFIX}{}", libc::getuid());
    all.retain(|slot| token_label(module, *slot).as_deref() == Some(wanted.as_str()));
    if slots.is_null() {
        *count = all.len() as CK_ULONG;
        return CKR_OK;
    }
    if (*count as usize) < all.len() {
        *count = all.len() as CK_ULONG;
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(all.as_ptr(), slots, all.len());
    *count = all.len() as CK_ULONG;
    CKR_OK
}

unsafe fn token_label(module: &Module, slot: CK_SLOT_ID) -> Option<String> {
    let mut info: CK_TOKEN_INFO = std::mem::zeroed();
    if (module.get_token_info)(slot, &mut info) != CKR_OK {
        return None;
    }
    let label: Vec<u8> = info.label[..TOKEN_LABEL_LEN].to_vec();
    String::from_utf8(label)
        .ok()
        .map(|l| l.trim_end().to_string())
}

#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(out: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if out.is_null() {
        return CKR_GENERAL_ERROR;
    }
    match module() {
        Some(module) => {
            *out = &module.table as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR;
            CKR_OK
        }
        None => CKR_GENERAL_ERROR,
    }
}

#[no_mangle]
pub unsafe extern "C" fn C_Login(
    session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    login_override(session, user_type, pin, pin_len)
}

unsafe extern "C" fn login_override(
    session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    let Some(module) = module() else {
        return CKR_GENERAL_ERROR;
    };
    if user_type != CKU_USER {
        return CKR_USER_TYPE_INVALID;
    }
    let pin_len = pin_len as usize;
    if pin.is_null() || pin_len == 0 || pin_len > MAX_PIN_LEN {
        return CKR_PIN_INCORRECT;
    }
    let typed = Zeroizing::new(std::slice::from_raw_parts(pin, pin_len).to_vec());
    let secret = match unlock_secret(&typed) {
        Ok(secret) => secret,
        Err(rv) => return rv,
    };
    (module.login)(
        session,
        CKU_USER,
        secret.as_ptr() as CK_UTF8CHAR_PTR,
        secret.len() as CK_ULONG,
    )
}

fn unlock_secret(typed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CK_RV> {
    let settings = &module().ok_or(CKR_GENERAL_ERROR)?.settings;
    let socket = settings.unlock_socket.as_deref().ok_or(CKR_GENERAL_ERROR)?;
    let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    let reply = if typed == PLACEHOLDER_PIN {
        match verify_face(ruid, settings.bus_address.as_deref()) {
            Ok(true) => request(socket, ruid, euid, OP_TAKE_GRANT, &[]),
            Ok(false) => return Err(CKR_PIN_INCORRECT),
            Err(()) => return Err(CKR_GENERAL_ERROR),
        }
    } else {
        std::str::from_utf8(typed).map_err(|_| CKR_PIN_INCORRECT)?;
        request(socket, ruid, euid, OP_UNLOCK_PIN, typed)
    };
    match reply {
        Ok(Some(secret)) if is_usable_secret(&secret) => Ok(secret),
        Ok(_) => Err(CKR_PIN_INCORRECT),
        Err(()) => Err(CKR_GENERAL_ERROR),
    }
}

fn is_usable_secret(secret: &[u8]) -> bool {
    !secret.is_empty()
        && secret.len() <= MAX_PIN_LEN
        && secret.iter().all(u8::is_ascii_alphanumeric)
}

// Under setuid sudo the unlock socket sees root, so the real caller is named explicitly.
pub fn wire_request(ruid: u32, euid: u32, op: u8, payload: &[u8]) -> (u8, Zeroizing<Vec<u8>>) {
    if euid == 0 && ruid != 0 {
        let mut named = Zeroizing::new(ruid.to_be_bytes().to_vec());
        named.push(op);
        named.extend_from_slice(payload);
        return (OP_UNLOCK_FOR_UID, named);
    }
    (op, Zeroizing::new(payload.to_vec()))
}

fn request(
    path: &Path,
    ruid: u32,
    euid: u32,
    op: u8,
    payload: &[u8],
) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
    let (op, payload) = wire_request(ruid, euid, op, payload);
    exchange(path, op, &payload)
}

fn verify_face(uid: u32, bus_address: Option<&str>) -> Result<bool, ()> {
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

fn exchange(path: &Path, op: u8, payload: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
    let mut stream = UnixStream::connect(path).map_err(|_| ())?;
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .map_err(|_| ())?;
    stream
        .set_write_timeout(Some(SOCKET_TIMEOUT))
        .map_err(|_| ())?;
    let mut frame = Zeroizing::new(vec![op]);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).map_err(|_| ())?;
    let mut header = [0u8; 3];
    stream.read_exact(&mut header).map_err(|_| ())?;
    let len = usize::from(u16::from_be_bytes([header[1], header[2]]));
    if len > MAX_REPLY {
        return Err(());
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    stream.read_exact(&mut body).map_err(|_| ())?;
    Ok((header[0] == STATUS_ACCEPTED).then_some(body))
}
