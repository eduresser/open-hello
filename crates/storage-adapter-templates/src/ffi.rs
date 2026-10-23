use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;

use openhello_plugin_abi::{Status, StorageHandle, StorageInterface, ABI_VERSION};

use crate::{StorageError, TemplateStore, TpmConfig};

const TCTI_ENV: &str = "OPENHELLO_TPM_TCTI";

fn status_of(error: &StorageError) -> Status {
    match error {
        StorageError::NotFound => Status::NotFound,
        StorageError::AuthenticationFailed => Status::AuthenticationFailed,
        StorageError::InvalidUid(_) => Status::InvalidArgument,
        StorageError::Tpm(_) => Status::TpmUnavailable,
        StorageError::Io(_) => Status::Internal,
    }
}

unsafe fn store<'a>(handle: StorageHandle) -> Option<&'a TemplateStore> {
    (handle as *const TemplateStore).as_ref()
}

unsafe extern "C" fn storage_open(root_dir: *const c_char, out: *mut StorageHandle) -> Status {
    if root_dir.is_null() || out.is_null() {
        return Status::InvalidArgument;
    }
    let Ok(root) = CStr::from_ptr(root_dir).to_str() else {
        return Status::InvalidArgument;
    };
    let tpm = TpmConfig { tcti: std::env::var(TCTI_ENV).ok() };
    match TemplateStore::open(Path::new(root), tpm) {
        Ok(opened) => {
            *out = Box::into_raw(Box::new(opened)) as StorageHandle;
            Status::Ok
        }
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn storage_put(handle: StorageHandle, uid: u32, data: *const u8, len: usize) -> Status {
    let (Some(store), false) = (store(handle), data.is_null()) else {
        return Status::InvalidArgument;
    };
    match store.put(uid, std::slice::from_raw_parts(data, len)) {
        Ok(()) => Status::Ok,
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn storage_get(
    handle: StorageHandle,
    uid: u32,
    out: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
) -> Status {
    let (Some(store), false, false) = (store(handle), out.is_null(), out_len.is_null()) else {
        return Status::InvalidArgument;
    };
    match store.get(uid) {
        Ok(template) => {
            *out_len = template.len();
            if template.len() > out_capacity {
                return Status::BufferTooSmall;
            }
            std::ptr::copy_nonoverlapping(template.as_ptr(), out, template.len());
            Status::Ok
        }
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn storage_list_uids(
    handle: StorageHandle,
    out: *mut u32,
    out_capacity: usize,
    out_count: *mut usize,
) -> Status {
    let (Some(store), false) = (store(handle), out_count.is_null()) else {
        return Status::InvalidArgument;
    };
    match store.enrolled_uids() {
        Ok(uids) => {
            *out_count = uids.len();
            if uids.len() > out_capacity {
                return Status::BufferTooSmall;
            }
            if !uids.is_empty() {
                std::ptr::copy_nonoverlapping(uids.as_ptr(), out, uids.len());
            }
            Status::Ok
        }
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn storage_purge(handle: StorageHandle, uid: u32) -> Status {
    let Some(store) = store(handle) else {
        return Status::InvalidArgument;
    };
    match store.purge(uid) {
        Ok(()) => Status::Ok,
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn storage_probe(handle: StorageHandle) -> Status {
    let Some(store) = store(handle) else {
        return Status::InvalidArgument;
    };
    match store.probe() {
        Ok(()) => Status::Ok,
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn storage_close(handle: StorageHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle as *mut TemplateStore));
    }
}

static STORAGE_INTERFACE: StorageInterface = StorageInterface {
    abi_version: ABI_VERSION,
    open: storage_open,
    put_template: storage_put,
    get_template: storage_get,
    list_uids: storage_list_uids,
    purge: storage_purge,
    close: storage_close,
    probe: storage_probe,
};

#[no_mangle]
pub extern "C" fn openhello_storage_interface() -> *const StorageInterface {
    &STORAGE_INTERFACE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_failures_have_their_own_status_and_io_stays_internal() {
        assert_eq!(status_of(&StorageError::Tpm("x".into())), Status::TpmUnavailable);
        assert_eq!(status_of(&StorageError::Io("x".into())), Status::Internal);
    }
}
