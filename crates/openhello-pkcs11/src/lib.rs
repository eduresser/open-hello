#![allow(non_snake_case, clippy::missing_safety_doc)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use cryptoki_sys::{
    CK_C_GetFunctionList, CKR_GENERAL_ERROR, CKR_OK, CKR_PIN_INCORRECT, CKR_USER_TYPE_INVALID,
    CKU_USER, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR, CK_FUNCTION_LIST_PTR_PTR, CK_RV,
    CK_SESSION_HANDLE, CK_ULONG, CK_USER_TYPE, CK_UTF8CHAR_PTR,
};
use libloading::Library;
use zbus::blocking::{Connection, Proxy};
use zeroize::Zeroizing;

// The PAM conversation answers this for the face flow because pam_pkcs11 rejects an empty PIN; it selects the flow and is no secret.
pub const PLACEHOLDER_PIN: &[u8] = b"openhello-face";

pub const REAL_MODULE_ENV: &str = "OPENHELLO_PKCS11_REAL_MODULE";
pub const UNLOCK_SOCKET_ENV: &str = "OPENHELLO_KEYD_UNLOCK_SOCKET";
// Honoured in debug builds only (tests); a release build always uses the system bus.
pub const TEST_BUS_ADDRESS_ENV: &str = "OPENHELLO_PKCS11_TEST_BUS_ADDRESS";

const OP_TAKE_GRANT: u8 = 1;
const OP_UNLOCK_PIN: u8 = 2;
const STATUS_ACCEPTED: u8 = 1;
const MAX_PIN_LEN: usize = 64;
const MAX_REPLY: usize = 128;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(15);
const BUS_NAME: &str = "io.openhello.Biometrics1";
const OBJECT_PATH: &str = "/io/openhello/Biometrics1";

type RealLogin =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV;

struct Module {
    _library: Library,
    table: CK_FUNCTION_LIST,
    login: RealLogin,
}

static MODULE: OnceLock<Option<Module>> = OnceLock::new();

fn module() -> Option<&'static Module> {
    MODULE.get_or_init(load_module).as_ref()
}

fn load_module() -> Option<Module> {
    let path = std::env::var_os(REAL_MODULE_ENV).filter(|p| !p.is_empty())?;
    let library = unsafe { Library::new(path) }.ok()?;
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
    table.C_Login = Some(login_override);
    Some(Module {
        _library: library,
        table,
        login,
    })
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
    let socket = unlock_socket_path().ok_or(CKR_GENERAL_ERROR)?;
    let reply = if typed == PLACEHOLDER_PIN {
        match verify_face(unsafe { libc::getuid() }) {
            Ok(true) => exchange(&socket, OP_TAKE_GRANT, &[]),
            Ok(false) => return Err(CKR_PIN_INCORRECT),
            Err(()) => return Err(CKR_GENERAL_ERROR),
        }
    } else {
        std::str::from_utf8(typed).map_err(|_| CKR_PIN_INCORRECT)?;
        exchange(&socket, OP_UNLOCK_PIN, typed)
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

fn unlock_socket_path() -> Option<PathBuf> {
    std::env::var_os(UNLOCK_SOCKET_ENV)
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
}

fn verify_face(uid: u32) -> Result<bool, ()> {
    let connection = connect_bus().ok_or(())?;
    let proxy = Proxy::new(&connection, BUS_NAME, OBJECT_PATH, BUS_NAME).map_err(|_| ())?;
    proxy.call("Verify", &(uid,)).map_err(|_| ())
}

fn connect_bus() -> Option<Connection> {
    #[cfg(debug_assertions)]
    if let Some(address) = std::env::var(TEST_BUS_ADDRESS_ENV)
        .ok()
        .filter(|a| !a.is_empty())
    {
        return zbus::blocking::connection::Builder::address(address.as_str())
            .and_then(|builder| builder.build())
            .ok();
    }
    Connection::system().ok()
}

fn exchange(
    path: &std::path::Path,
    op: u8,
    payload: &[u8],
) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
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
