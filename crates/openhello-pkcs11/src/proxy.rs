use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use cryptoki_sys::*;
use zeroize::Zeroizing;

use crate::config::{self, PLACEHOLDER_PIN};

pub const OP_TOKEN_HELLO: u8 = 1;
pub const OP_TOKEN_INFO: u8 = 2;
pub const OP_TOKEN_OPEN: u8 = 3;
pub const OP_TOKEN_CLOSE: u8 = 4;
pub const OP_TOKEN_LOGIN: u8 = 5;
pub const OP_TOKEN_LOGOUT: u8 = 6;
pub const OP_TOKEN_FIND: u8 = 7;
pub const OP_TOKEN_ATTRIBUTES: u8 = 8;
pub const OP_TOKEN_SIGN_CHECK: u8 = 9;
pub const OP_TOKEN_SIGN: u8 = 10;

pub const TOKEN_OK: u8 = 0;
pub const TOKEN_PIN_INCORRECT: u8 = 1;
pub const TOKEN_NO_TOKEN: u8 = 2;
pub const TOKEN_BAD_HANDLE: u8 = 3;
pub const TOKEN_BAD_REQUEST: u8 = 4;
pub const TOKEN_REFUSED: u8 = 5;
pub const TOKEN_FAILED: u8 = 6;
pub const TOKEN_BAD_MECHANISM: u8 = 7;

pub const ATTRIBUTE_INVALID: u8 = 0;
pub const ATTRIBUTE_SENSITIVE: u8 = 1;
pub const ATTRIBUTE_READ: u8 = 2;

pub const TOKEN_INFO_LEN: usize = 104;
pub const SIGNATURE_LEN: usize = 64;

const SLOT: CK_SLOT_ID = 0;
const MAX_SESSIONS: usize = 4;
const MAX_PIN_LEN: usize = 64;
const MAX_REPLY: usize = 8192;
const MAX_SIGN_INPUT: usize = 128;
const MAX_TEMPLATE: usize = 8;
const MAX_TEMPLATE_VALUE: usize = 512;
const MAX_ATTRIBUTES: usize = 16;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(15);
const DESCRIPTION: &[u8] = b"open-hello TPM token";
const MANUFACTURER: &[u8] = b"open-hello";

struct Client {
    stream: UnixStream,
    uid: u32,
    bus_address: Option<String>,
    token: Option<Zeroizing<Vec<u8>>>,
    sessions: Vec<VirtualSession>,
    next_session: CK_SESSION_HANDLE,
    logged_in: bool,
}

struct VirtualSession {
    handle: CK_SESSION_HANDLE,
    flags: CK_FLAGS,
    found: VecDeque<u64>,
    signing: Option<(u64, u64)>,
}

static STATE: Mutex<Option<Client>> = Mutex::new(None);

fn state() -> MutexGuard<'static, Option<Client>> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

fn with_client(body: impl FnOnce(&mut Client) -> Result<(), CK_RV>) -> CK_RV {
    match state().as_mut() {
        Some(client) => body(client).err().unwrap_or(CKR_OK),
        None => CKR_CRYPTOKI_NOT_INITIALIZED,
    }
}

fn failure_code(status: u8) -> CK_RV {
    match status {
        TOKEN_PIN_INCORRECT => CKR_PIN_INCORRECT,
        TOKEN_NO_TOKEN => CKR_TOKEN_NOT_PRESENT,
        TOKEN_BAD_HANDLE => CKR_OBJECT_HANDLE_INVALID,
        TOKEN_BAD_REQUEST => CKR_ARGUMENTS_BAD,
        TOKEN_REFUSED => CKR_ACTION_PROHIBITED,
        TOKEN_BAD_MECHANISM => CKR_MECHANISM_INVALID,
        _ => CKR_GENERAL_ERROR,
    }
}

impl Client {
    fn connect() -> Result<Self, CK_RV> {
        let settings = config::current(&config::process_env, Path::new(config::DEFAULT_CONFIG))
            .map_err(|_| CKR_GENERAL_ERROR)?;
        let socket = settings.token_socket.ok_or(CKR_GENERAL_ERROR)?;
        let stream = UnixStream::connect(socket).map_err(|_| CKR_GENERAL_ERROR)?;
        stream
            .set_read_timeout(Some(SOCKET_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(SOCKET_TIMEOUT)))
            .map_err(|_| CKR_GENERAL_ERROR)?;
        let uid = unsafe { libc::getuid() };
        let mut client = Self {
            stream,
            uid,
            bus_address: settings.bus_address,
            token: None,
            sessions: Vec::new(),
            next_session: 1,
            logged_in: false,
        };
        client.call(OP_TOKEN_HELLO, &uid.to_be_bytes())?;
        Ok(client)
    }

    fn call(&mut self, op: u8, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, CK_RV> {
        let (status, body) = self.exchange(op, payload)?;
        if status == TOKEN_OK {
            Ok(body)
        } else {
            Err(failure_code(status))
        }
    }

    fn exchange(&mut self, op: u8, payload: &[u8]) -> Result<(u8, Zeroizing<Vec<u8>>), CK_RV> {
        let mut frame = Zeroizing::new(vec![op]);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        self.stream
            .write_all(&frame)
            .map_err(|_| CKR_DEVICE_ERROR)?;
        let mut header = [0u8; 3];
        self.stream
            .read_exact(&mut header)
            .map_err(|_| CKR_DEVICE_ERROR)?;
        let len = usize::from(u16::from_be_bytes([header[1], header[2]]));
        if len > MAX_REPLY {
            return Err(CKR_DEVICE_ERROR);
        }
        let mut body = Zeroizing::new(vec![0u8; len]);
        self.stream
            .read_exact(&mut body)
            .map_err(|_| CKR_DEVICE_ERROR)?;
        Ok((header[0], body))
    }

    fn token_info(&mut self) -> Result<Option<&[u8]>, CK_RV> {
        if self.token.is_none() {
            match self.exchange(OP_TOKEN_INFO, &[])? {
                (TOKEN_OK, body) if body.len() == TOKEN_INFO_LEN => self.token = Some(body),
                (TOKEN_NO_TOKEN, _) => return Ok(None),
                (status, _) => return Err(failure_code(status)),
            }
        }
        Ok(self.token.as_deref().map(Vec::as_slice))
    }

    fn session(&mut self, handle: CK_SESSION_HANDLE) -> Result<&mut VirtualSession, CK_RV> {
        self.sessions
            .iter_mut()
            .find(|s| s.handle == handle)
            .ok_or(CKR_SESSION_HANDLE_INVALID)
    }

    fn release_token_session(&mut self) -> Result<(), CK_RV> {
        self.logged_in = false;
        self.call(OP_TOKEN_CLOSE, &[]).map(|_| ())
    }
}

unsafe extern "C" fn initialize(reserved: CK_VOID_PTR) -> CK_RV {
    let _ = reserved;
    let mut guard = state();
    if guard.is_some() {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    match Client::connect() {
        Ok(client) => {
            *guard = Some(client);
            CKR_OK
        }
        Err(rv) => rv,
    }
}

unsafe extern "C" fn finalize(reserved: CK_VOID_PTR) -> CK_RV {
    if !reserved.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    match state().take() {
        Some(_) => CKR_OK,
        None => CKR_CRYPTOKI_NOT_INITIALIZED,
    }
}

fn fill(target: &mut [u8], text: &[u8]) {
    target.fill(b' ');
    let len = text.len().min(target.len());
    target[..len].copy_from_slice(&text[..len]);
}

unsafe extern "C" fn get_info(info: CK_INFO_PTR) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut out: CK_INFO = std::mem::zeroed();
    out.cryptokiVersion = CK_VERSION {
        major: 2,
        minor: 40,
    };
    fill(&mut out.manufacturerID, MANUFACTURER);
    fill(&mut out.libraryDescription, DESCRIPTION);
    out.libraryVersion = CK_VERSION { major: 0, minor: 1 };
    *info = out;
    CKR_OK
}

unsafe fn return_list<T: Copy>(items: &[T], list: *mut T, count: CK_ULONG_PTR) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if list.is_null() {
        *count = items.len() as CK_ULONG;
        return CKR_OK;
    }
    let room = *count as usize;
    *count = items.len() as CK_ULONG;
    if room < items.len() {
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(items.as_ptr(), list, items.len());
    CKR_OK
}

unsafe extern "C" fn get_slot_list(
    token_present: CK_BBOOL,
    slots: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    with_client(|client| {
        let listed = token_present == CK_FALSE || client.token_info()?.is_some();
        let all: &[CK_SLOT_ID] = if listed { &[SLOT] } else { &[] };
        match return_list(all, slots, count) {
            CKR_OK => Ok(()),
            rv => Err(rv),
        }
    })
}

unsafe extern "C" fn get_slot_info(slot: CK_SLOT_ID, info: CK_SLOT_INFO_PTR) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if slot != SLOT {
        return CKR_SLOT_ID_INVALID;
    }
    with_client(|client| {
        let mut out: CK_SLOT_INFO = std::mem::zeroed();
        fill(&mut out.slotDescription, DESCRIPTION);
        fill(&mut out.manufacturerID, MANUFACTURER);
        if client.token_info()?.is_some() {
            out.flags = CKF_TOKEN_PRESENT;
        }
        out.hardwareVersion = CK_VERSION { major: 1, minor: 0 };
        out.firmwareVersion = CK_VERSION { major: 1, minor: 0 };
        *info = out;
        Ok(())
    })
}

unsafe extern "C" fn get_token_info(slot: CK_SLOT_ID, info: CK_TOKEN_INFO_PTR) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if slot != SLOT {
        return CKR_SLOT_ID_INVALID;
    }
    with_client(|client| {
        let raw = client.token_info()?.ok_or(CKR_TOKEN_NOT_PRESENT)?;
        let mut out: CK_TOKEN_INFO = std::mem::zeroed();
        out.label.copy_from_slice(&raw[..32]);
        out.manufacturerID.copy_from_slice(&raw[32..64]);
        out.model.copy_from_slice(&raw[64..80]);
        out.serialNumber.copy_from_slice(&raw[80..96]);
        out.flags = u64::from_be_bytes(raw[96..104].try_into().map_err(|_| CKR_GENERAL_ERROR)?);
        out.ulMaxSessionCount = 1;
        out.ulSessionCount = CK_UNAVAILABLE_INFORMATION;
        out.ulMaxRwSessionCount = 0;
        out.ulRwSessionCount = 0;
        out.ulMaxPinLen = MAX_PIN_LEN as CK_ULONG;
        out.ulMinPinLen = 6;
        out.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
        out.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
        out.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
        out.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
        out.hardwareVersion = CK_VERSION { major: 1, minor: 0 };
        out.firmwareVersion = CK_VERSION { major: 1, minor: 0 };
        out.utcTime.fill(b' ');
        *info = out;
        Ok(())
    })
}

unsafe extern "C" fn get_mechanism_list(
    slot: CK_SLOT_ID,
    list: CK_MECHANISM_TYPE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if slot != SLOT {
        return CKR_SLOT_ID_INVALID;
    }
    return_list(&[CKM_ECDSA as CK_MECHANISM_TYPE], list, count)
}

unsafe extern "C" fn get_mechanism_info(
    slot: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if slot != SLOT {
        return CKR_SLOT_ID_INVALID;
    }
    if mechanism != CKM_ECDSA as CK_MECHANISM_TYPE {
        return CKR_MECHANISM_INVALID;
    }
    *info = CK_MECHANISM_INFO {
        ulMinKeySize: 256,
        ulMaxKeySize: 256,
        flags: CKF_SIGN,
    };
    CKR_OK
}

unsafe extern "C" fn open_session(
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if slot != SLOT {
        return CKR_SLOT_ID_INVALID;
    }
    if flags & CKF_SERIAL_SESSION == 0 {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }
    with_client(|client| {
        if client.sessions.len() >= MAX_SESSIONS {
            return Err(CKR_SESSION_COUNT);
        }
        if client.sessions.is_empty() {
            client.call(OP_TOKEN_OPEN, &[])?;
        }
        let handle = client.next_session;
        client.next_session += 1;
        client.sessions.push(VirtualSession {
            handle,
            flags,
            found: VecDeque::new(),
            signing: None,
        });
        *session = handle;
        Ok(())
    })
}

unsafe extern "C" fn close_session(session: CK_SESSION_HANDLE) -> CK_RV {
    with_client(|client| {
        client.session(session)?;
        client.sessions.retain(|s| s.handle != session);
        if client.sessions.is_empty() {
            client.release_token_session()?;
        }
        Ok(())
    })
}

unsafe extern "C" fn close_all_sessions(slot: CK_SLOT_ID) -> CK_RV {
    if slot != SLOT {
        return CKR_SLOT_ID_INVALID;
    }
    with_client(|client| {
        if client.sessions.is_empty() {
            return Ok(());
        }
        client.sessions.clear();
        client.release_token_session()
    })
}

unsafe extern "C" fn get_session_info(
    session: CK_SESSION_HANDLE,
    info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_client(|client| {
        let logged_in = client.logged_in;
        let flags = client.session(session)?.flags;
        *info = CK_SESSION_INFO {
            slotID: SLOT,
            state: match (flags & CKF_RW_SESSION != 0, logged_in) {
                (false, false) => CKS_RO_PUBLIC_SESSION,
                (false, true) => CKS_RO_USER_FUNCTIONS,
                (true, false) => CKS_RW_PUBLIC_SESSION,
                (true, true) => CKS_RW_USER_FUNCTIONS,
            },
            flags,
            ulDeviceError: 0,
        };
        Ok(())
    })
}

unsafe extern "C" fn login(
    session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    if user_type != CKU_USER {
        return CKR_USER_TYPE_INVALID;
    }
    let pin_len = pin_len as usize;
    if pin.is_null() || pin_len == 0 || pin_len > MAX_PIN_LEN {
        return CKR_PIN_INCORRECT;
    }
    let typed = Zeroizing::new(std::slice::from_raw_parts(pin, pin_len).to_vec());
    with_client(|client| {
        client.session(session)?;
        if client.logged_in {
            return Err(CKR_USER_ALREADY_LOGGED_IN);
        }
        if typed.as_slice() == PLACEHOLDER_PIN {
            match crate::verify_face(client.uid, client.bus_address.as_deref()) {
                Ok(true) => {}
                Ok(false) => return Err(CKR_PIN_INCORRECT),
                Err(()) => return Err(CKR_GENERAL_ERROR),
            }
        }
        client.call(OP_TOKEN_LOGIN, &typed)?;
        client.logged_in = true;
        Ok(())
    })
}

unsafe extern "C" fn logout(session: CK_SESSION_HANDLE) -> CK_RV {
    with_client(|client| {
        client.session(session)?;
        if !client.logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN);
        }
        client.call(OP_TOKEN_LOGOUT, &[])?;
        client.logged_in = false;
        for open in &mut client.sessions {
            open.signing = None;
        }
        Ok(())
    })
}

unsafe extern "C" fn find_objects_init(
    session: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    let count = count as usize;
    if count > MAX_TEMPLATE || (template.is_null() && count > 0) {
        return CKR_ARGUMENTS_BAD;
    }
    let mut payload = vec![count as u8];
    for attribute in (0..count).map(|i| *template.add(i)) {
        if attribute.pValue.is_null() || attribute.ulValueLen as usize > MAX_TEMPLATE_VALUE {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        let value = std::slice::from_raw_parts(
            attribute.pValue as *const u8,
            attribute.ulValueLen as usize,
        );
        payload.extend_from_slice(&attribute.type_.to_be_bytes());
        payload.extend_from_slice(&(value.len() as u16).to_be_bytes());
        payload.extend_from_slice(value);
    }
    with_client(|client| {
        client.session(session)?;
        let reply = client.call(OP_TOKEN_FIND, &payload)?;
        if reply.len() % 8 != 0 {
            return Err(CKR_DEVICE_ERROR);
        }
        let found = reply
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_be_bytes(*chunk))
            .collect();
        client.session(session)?.found = found;
        Ok(())
    })
}

unsafe extern "C" fn find_objects(
    session: CK_SESSION_HANDLE,
    objects: CK_OBJECT_HANDLE_PTR,
    max: CK_ULONG,
    found: CK_ULONG_PTR,
) -> CK_RV {
    if objects.is_null() || found.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_client(|client| {
        let queue = &mut client.session(session)?.found;
        let take = queue.len().min(max as usize);
        for (slot, handle) in queue.drain(..take).enumerate() {
            *objects.add(slot) = handle as CK_OBJECT_HANDLE;
        }
        *found = take as CK_ULONG;
        Ok(())
    })
}

unsafe extern "C" fn find_objects_final(session: CK_SESSION_HANDLE) -> CK_RV {
    with_client(|client| {
        client.session(session)?.found.clear();
        Ok(())
    })
}

unsafe extern "C" fn get_attribute_value(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    let count = count as usize;
    if template.is_null() || count == 0 || count > MAX_ATTRIBUTES {
        return CKR_ARGUMENTS_BAD;
    }
    let mut payload = object.to_be_bytes().to_vec();
    payload.push(count as u8);
    for i in 0..count {
        payload.extend_from_slice(&(*template.add(i)).type_.to_be_bytes());
    }
    with_client(|client| {
        client.session(session)?;
        let reply = client.call(OP_TOKEN_ATTRIBUTES, &payload)?;
        let mut rest: &[u8] = &reply;
        let mut outcome = CKR_OK;
        for i in 0..count {
            let header = rest.get(..11).ok_or(CKR_DEVICE_ERROR)?;
            let state = header[8];
            let len = usize::from(u16::from_be_bytes([header[9], header[10]]));
            let value = rest.get(11..11 + len).ok_or(CKR_DEVICE_ERROR)?;
            rest = &rest[11 + len..];
            let slot = &mut *template.add(i);
            let rv = match state {
                ATTRIBUTE_READ => copy_value(slot, value),
                ATTRIBUTE_SENSITIVE => CKR_ATTRIBUTE_SENSITIVE,
                _ => CKR_ATTRIBUTE_TYPE_INVALID,
            };
            if rv != CKR_OK {
                if rv != CKR_BUFFER_TOO_SMALL || outcome == CKR_OK {
                    outcome = rv;
                }
                if rv != CKR_BUFFER_TOO_SMALL {
                    slot.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                }
            }
        }
        match outcome {
            CKR_OK => Ok(()),
            rv => Err(rv),
        }
    })
}

unsafe fn copy_value(slot: &mut CK_ATTRIBUTE, value: &[u8]) -> CK_RV {
    if slot.pValue.is_null() {
        slot.ulValueLen = value.len() as CK_ULONG;
        return CKR_OK;
    }
    if (slot.ulValueLen as usize) < value.len() {
        slot.ulValueLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(value.as_ptr(), slot.pValue as *mut u8, value.len());
    slot.ulValueLen = value.len() as CK_ULONG;
    CKR_OK
}

unsafe extern "C" fn sign_init(
    session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let kind = (*mechanism).mechanism;
    if (*mechanism).ulParameterLen != 0 {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    let mut payload = kind.to_be_bytes().to_vec();
    payload.extend_from_slice(&key.to_be_bytes());
    with_client(|client| {
        client.session(session)?;
        client.call(OP_TOKEN_SIGN_CHECK, &payload)?;
        client.session(session)?.signing = Some((kind, key));
        Ok(())
    })
}

unsafe extern "C" fn sign(
    session: CK_SESSION_HANDLE,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    signature: CK_BYTE_PTR,
    signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if signature_len.is_null() || data.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let data_len = data_len as usize;
    with_client(|client| {
        let (kind, key) = client
            .session(session)?
            .signing
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if signature.is_null() {
            *signature_len = SIGNATURE_LEN as CK_ULONG;
            return Ok(());
        }
        if (*signature_len as usize) < SIGNATURE_LEN {
            *signature_len = SIGNATURE_LEN as CK_ULONG;
            return Err(CKR_BUFFER_TOO_SMALL);
        }
        client.session(session)?.signing = None;
        if data_len == 0 || data_len > MAX_SIGN_INPUT {
            return Err(CKR_DATA_LEN_RANGE);
        }
        let mut payload = kind.to_be_bytes().to_vec();
        payload.extend_from_slice(&key.to_be_bytes());
        payload.extend_from_slice(std::slice::from_raw_parts(data, data_len));
        let reply = client.call(OP_TOKEN_SIGN, &payload)?;
        if reply.len() > SIGNATURE_LEN {
            return Err(CKR_DEVICE_ERROR);
        }
        std::ptr::copy_nonoverlapping(reply.as_ptr(), signature, reply.len());
        *signature_len = reply.len() as CK_ULONG;
        Ok(())
    })
}

macro_rules! unsupported {
    ($table:ident: $($name:ident),* $(,)?) => {$({
        unsafe extern "C" fn stub() -> CK_RV {
            CKR_FUNCTION_NOT_SUPPORTED
        }
        // Every entry only returns an error code, so a caller's extra arguments are harmless on the C ABI.
        $table.$name = Some(std::mem::transmute(stub as unsafe extern "C" fn() -> CK_RV));
    })*};
}

#[allow(clippy::missing_transmute_annotations)]
pub(crate) fn function_list() -> &'static CK_FUNCTION_LIST {
    static TABLE: OnceLock<CK_FUNCTION_LIST> = OnceLock::new();
    TABLE.get_or_init(|| unsafe {
        let mut table: CK_FUNCTION_LIST = std::mem::zeroed();
        table.version = CK_VERSION {
            major: 2,
            minor: 40,
        };
        table.C_Initialize = Some(initialize);
        table.C_Finalize = Some(finalize);
        table.C_GetInfo = Some(get_info);
        table.C_GetFunctionList = Some(crate::C_GetFunctionList);
        table.C_GetSlotList = Some(get_slot_list);
        table.C_GetSlotInfo = Some(get_slot_info);
        table.C_GetTokenInfo = Some(get_token_info);
        table.C_GetMechanismList = Some(get_mechanism_list);
        table.C_GetMechanismInfo = Some(get_mechanism_info);
        table.C_OpenSession = Some(open_session);
        table.C_CloseSession = Some(close_session);
        table.C_CloseAllSessions = Some(close_all_sessions);
        table.C_GetSessionInfo = Some(get_session_info);
        table.C_Login = Some(login);
        table.C_Logout = Some(logout);
        table.C_FindObjectsInit = Some(find_objects_init);
        table.C_FindObjects = Some(find_objects);
        table.C_FindObjectsFinal = Some(find_objects_final);
        table.C_GetAttributeValue = Some(get_attribute_value);
        table.C_SignInit = Some(sign_init);
        table.C_Sign = Some(sign);
        unsupported!(table:
            C_InitToken, C_InitPIN, C_SetPIN, C_GetOperationState,
            C_SetOperationState, C_CreateObject, C_CopyObject, C_DestroyObject, C_GetObjectSize,
            C_SetAttributeValue, C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal,
            C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal, C_DigestInit, C_Digest,
            C_DigestUpdate, C_DigestKey, C_DigestFinal, C_SignUpdate, C_SignFinal,
            C_SignRecoverInit, C_SignRecover, C_VerifyInit, C_Verify, C_VerifyUpdate,
            C_VerifyFinal, C_VerifyRecoverInit, C_VerifyRecover, C_DigestEncryptUpdate,
            C_DecryptDigestUpdate, C_SignEncryptUpdate, C_DecryptVerifyUpdate, C_GenerateKey,
            C_GenerateKeyPair, C_WrapKey, C_UnwrapKey, C_DeriveKey, C_SeedRandom,
            C_GenerateRandom, C_GetFunctionStatus, C_CancelFunction, C_WaitForSlotEvent,
        );
        table
    })
}
