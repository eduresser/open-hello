use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

// The PAM conversation answers this for the face flow because pam_pkcs11 rejects an empty PIN; it selects the flow and is no secret.
pub const PLACEHOLDER_PIN: &[u8] = b"openhello-face";
pub const DEFAULT_CONFIG: &str = "/etc/openhello/pkcs11.conf";
pub const CONFIG_ENV: &str = "OPENHELLO_PKCS11_CONFIG";
pub const REAL_MODULE_ENV: &str = "OPENHELLO_PKCS11_REAL_MODULE";
pub const UNLOCK_SOCKET_ENV: &str = "OPENHELLO_KEYD_UNLOCK_SOCKET";
// Honoured in debug builds only (tests); a release build always uses the system bus.
pub const TEST_BUS_ADDRESS_ENV: &str = "OPENHELLO_PKCS11_TEST_BUS_ADDRESS";

const ROOT_UID: u32 = 0;
const GROUP_OR_OTHER_WRITE: u32 = 0o022;
const MAX_CONFIG_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    pub module: Option<PathBuf>,
    pub unlock_socket: Option<PathBuf>,
    pub store_dir: Option<PathBuf>,
    pub tcti: Option<String>,
    pub bus_address: Option<String>,
}

// setuid sudo runs with euid 0 and the caller's environment: only a root-owned file may name the module and sockets there.
pub fn is_privileged(ruid: u32, euid: u32) -> bool {
    euid == ROOT_UID || euid != ruid
}

pub fn resolve(
    ruid: u32,
    euid: u32,
    env: &dyn Fn(&str) -> Option<String>,
    system_config: &Path,
    trusted_owner: u32,
) -> Result<Settings, String> {
    let get = |name: &str| env(name).filter(|v| !v.is_empty());
    let mut settings = if is_privileged(ruid, euid) {
        parse(&read_trusted(system_config, trusted_owner)?)?
    } else {
        let explicit = get(CONFIG_ENV).map(PathBuf::from);
        let path = explicit.as_deref().unwrap_or(system_config);
        match std::fs::read_to_string(path) {
            Ok(text) => parse(&text)?,
            Err(e) if explicit.is_none() && e.kind() == std::io::ErrorKind::NotFound => {
                Settings::default()
            }
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        }
    };
    if !is_privileged(ruid, euid) {
        settings.module = get(REAL_MODULE_ENV).map(PathBuf::from).or(settings.module);
        settings.unlock_socket = get(UNLOCK_SOCKET_ENV)
            .map(PathBuf::from)
            .or(settings.unlock_socket);
        settings.bus_address = get(TEST_BUS_ADDRESS_ENV).or(settings.bus_address);
    }
    #[cfg(not(debug_assertions))]
    {
        settings.bus_address = None;
    }
    Ok(settings)
}

fn read_trusted(path: &Path, owner: u32) -> Result<String, String> {
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if !meta.is_file() || meta.uid() != owner || meta.mode() & GROUP_OR_OTHER_WRITE != 0 {
        return Err(format!(
            "{} must be a regular file owned by uid {owner} and not writable by group or others",
            path.display()
        ));
    }
    let mut text = String::new();
    file.by_ref()
        .take(MAX_CONFIG_BYTES)
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(text)
}

fn parse(text: &str) -> Result<Settings, String> {
    let mut settings = Settings::default();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .map(|(k, v)| (k.trim(), v.trim()))
            .filter(|(_, v)| !v.is_empty())
            .ok_or_else(|| format!("line {}: expected `key = value`", number + 1))?;
        match key {
            "module" => settings.module = Some(value.into()),
            "unlock_socket" => settings.unlock_socket = Some(value.into()),
            "store_dir" => settings.store_dir = Some(value.into()),
            "tcti" => settings.tcti = Some(value.to_string()),
            "bus_address" => settings.bus_address = Some(value.to_string()),
            other => return Err(format!("line {}: unknown key `{other}`", number + 1)),
        }
    }
    Ok(settings)
}

pub fn current(
    env: &dyn Fn(&str) -> Option<String>,
    system_config: &Path,
) -> Result<Settings, String> {
    let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    resolve(ruid, euid, env, system_config, ROOT_UID)
}

pub fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}
