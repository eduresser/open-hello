use std::cell::RefCell;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as P11Error, RvError};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;

use crate::{KeydError, Secret};

const MODULE_FILE: &str = "libtpm2_pkcs11.so";
const PKCS11_SUBPATH: &str = "usr/lib64/pkcs11/libtpm2_pkcs11.so";
const DATABASE_FILE: &str = "tpm2_pkcs11.sqlite3";

// Secrets arrive on stdin, not argv; `addkey` is patched to create signing-only keys (stock also allows decryption).
const PTOOL_ENTRY: &str = "
import sys
from tpm2_pkcs11 import tpm2
create = tpm2.Tpm2.create
def sign_only(self, phandle, pauth=None, objauth=None, objattrs=None, seal=None, alg=None):
    if seal is None and objattrs is None and alg == 'ecc256':
        objattrs = 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign'
    return create(self, phandle, pauth, objauth, objattrs, seal, alg)
tpm2.Tpm2.create = sign_only
from tpm2_pkcs11.tpm2_ptool import main
sys.argv = ['tpm2_ptool'] + sys.stdin.read().split('\\0')[:-1]
main()
";

const INSPECT_ENTRY: &str = "
import sqlite3, sys, yaml
from tpm2_pkcs11.pkcs11t import CKA_TPM2_PUB_BLOB
CLASS, ID, SENSITIVE, EXTRACTABLE = 0x0, 0x102, 0x103, 0x162
store, label = sys.argv[1], sys.argv[2]
con = sqlite3.connect('file:%s/%s?mode=ro' % (store, sys.argv[3]), uri=True)
token = con.execute('select id from tokens where label=?', (label,)).fetchone()
if token is None:
    print('token absent')
    sys.exit(0)
print('token present')
for (raw,) in con.execute('select attrs from tobjects where tokid=? order by id', (token[0],)):
    a = yaml.safe_load(raw)
    print('object', a.get(CLASS), a.get(ID, ''), int(bool(a.get(EXTRACTABLE))), int(bool(a.get(SENSITIVE))), a.get(CKA_TPM2_PUB_BLOB, '-'))
";

const LIST_ENTRY: &str = "
import sqlite3, sys
con = sqlite3.connect('file:%s/%s?mode=ro' % (sys.argv[1], sys.argv[2]), uri=True)
for (label,) in con.execute('select label from tokens order by id'):
    print(label)
";

/// tpm2-pkcs11 reads its store and TCTI from the process environment and keeps a TPM connection per
/// initialization, so the module is loaded once per process and every use is serialized.
static MODULE: Mutex<Option<Loaded>> = Mutex::new(None);

struct Loaded {
    context: Pkcs11,
    store_dir: PathBuf,
    tcti: Option<String>,
}

pub(crate) struct Guard {
    loaded: RefCell<MutexGuard<'static, Option<Loaded>>>,
}

pub(crate) fn lock() -> Guard {
    Guard {
        loaded: RefCell::new(MODULE.lock().unwrap_or_else(PoisonError::into_inner)),
    }
}

impl Guard {
    pub(crate) fn reset_module(&self) {
        **self.loaded.borrow_mut() = None;
    }
}

#[derive(Debug, Clone)]
pub struct KeydConfig {
    pub store_dir: PathBuf,
    pub tcti: Option<String>,
    pub prefix: Option<PathBuf>,
    pub module: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    pub mapfile: PathBuf,
    pub auth_dir: PathBuf,
    pub user_name: Option<fn(u32) -> Option<String>>,
    pub shadow_file: PathBuf,
    pub pending_password_ttl: Duration,
}

impl KeydConfig {
    pub fn new(store_dir: impl Into<PathBuf>) -> Self {
        Self {
            store_dir: store_dir.into(),
            tcti: None,
            prefix: None,
            module: None,
            env: Vec::new(),
            mapfile: PathBuf::from(crate::certificate::DEFAULT_MAPFILE),
            auth_dir: PathBuf::from(crate::auth_keys::DEFAULT_AUTH_DIR),
            user_name: None,
            shadow_file: PathBuf::from(crate::login_secret::SHADOW_FILE),
            pending_password_ttl: crate::login_secret::PENDING_PASSWORD_TTL,
        }
    }

    pub fn from_env() -> Result<Self, KeydError> {
        let store = std::env::var_os("OPENHELLO_KEYD_STORE_DIR")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                KeydError::Config(
                    "OPENHELLO_KEYD_STORE_DIR must name the token store directory".into(),
                )
            })?;
        let mut config = Self::new(PathBuf::from(store));
        config.tcti = std::env::var("OPENHELLO_KEYD_TCTI")
            .ok()
            .filter(|v| !v.is_empty());
        if let Some(mapfile) = std::env::var_os("OPENHELLO_KEYD_MAPFILE").filter(|v| !v.is_empty())
        {
            config.mapfile = PathBuf::from(mapfile);
        }
        if let Some(dir) = std::env::var_os("OPENHELLO_KEYD_AUTH_DIR").filter(|v| !v.is_empty()) {
            config.auth_dir = PathBuf::from(dir);
        }
        config.prefix = std::env::var_os("OPENHELLO_TPM2_PKCS11_PREFIX")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        config.module = std::env::var_os("OPENHELLO_TPM2_PKCS11_MODULE")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        Ok(config)
    }

    fn module_path(&self) -> Result<PathBuf, KeydError> {
        resolve_module(
            self.module.as_deref(),
            self.prefix.as_deref(),
            p11_kit_list_modules,
            |name| unsafe { libloading::Library::new(name) }.is_ok(),
        )
    }

    fn tool_env(&self) -> Vec<(OsString, OsString)> {
        let mut env: Vec<(OsString, OsString)> = vec![
            (
                "TPM2_PKCS11_STORE".into(),
                self.store_dir.clone().into_os_string(),
            ),
            ("TPM2_PKCS11_BACKEND".into(), "esysdb".into()),
            ("PYTHONWARNINGS".into(), "ignore".into()),
        ];
        if let Some(tcti) = &self.tcti {
            env.push(("TPM2TOOLS_TCTI".into(), tcti.into()));
            env.push(("TPM2_PKCS11_TCTI".into(), tcti.into()));
        }
        if let Some(prefix) = &self.prefix {
            let lib64 = prefix.join("usr/lib64");
            let mut library_path = lib64.clone().into_os_string();
            if let Some(existing) = std::env::var_os("LD_LIBRARY_PATH") {
                library_path.push(":");
                library_path.push(existing);
            }
            env.push(("LD_LIBRARY_PATH".into(), library_path));
            let mut python_path = OsString::new();
            for base in [prefix.join("usr/lib"), lib64] {
                for entry in std::fs::read_dir(base).into_iter().flatten().flatten() {
                    if entry.file_name().to_string_lossy().starts_with("python3") {
                        python_path.push(entry.path().join("site-packages"));
                        python_path.push(":");
                    }
                }
            }
            env.push(("PYTHONPATH".into(), python_path));
        }
        env.extend(self.env.iter().map(|(k, v)| (k.into(), v.into())));
        env
    }

    pub(crate) fn ensure_store_dir(&self) -> Result<(), KeydError> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(&self.store_dir)
            .and_then(|_| {
                std::fs::set_permissions(&self.store_dir, std::fs::Permissions::from_mode(0o700))
            })
            .map_err(|e| failure("preparing the store directory", &e.to_string(), &[]))
    }

    pub(crate) fn ptool(
        &self,
        _guard: &Guard,
        args: &[&str],
        secrets: &[&str],
    ) -> Result<String, KeydError> {
        let mut stdin = Vec::new();
        for arg in args {
            stdin.extend_from_slice(arg.as_bytes());
            stdin.push(0);
        }
        self.python(PTOOL_ENTRY, &[], &stdin, secrets)
    }

    pub(crate) fn inspect(&self, _guard: &Guard, label: &str) -> Result<TokenDump, KeydError> {
        let store = self.store_dir.to_string_lossy().into_owned();
        let out = self.python(INSPECT_ENTRY, &[&store, label, DATABASE_FILE], &[], &[])?;
        TokenDump::parse(&out).ok_or_else(|| {
            failure(
                "reading the token store",
                "unparseable inspector output",
                &[],
            )
        })
    }

    pub(crate) fn token_labels(&self, _guard: &Guard) -> Result<Vec<String>, KeydError> {
        if !store_file(&self.store_dir).exists() {
            return Ok(Vec::new());
        }
        let store = self.store_dir.to_string_lossy().into_owned();
        let out = self.python(LIST_ENTRY, &[&store, DATABASE_FILE], &[], &[])?;
        Ok(out.lines().map(str::to_string).collect())
    }

    fn python(
        &self,
        code: &str,
        args: &[&str],
        stdin: &[u8],
        secrets: &[&str],
    ) -> Result<String, KeydError> {
        let mut child = Command::new("python3")
            .args(["-c", code])
            .args(args)
            .current_dir("/")
            .envs(self.tool_env())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| failure("starting python3", &e.to_string(), secrets))?;
        if let Some(mut pipe) = child.stdin.take() {
            pipe.write_all(stdin)
                .map_err(|e| failure("writing to python3", &e.to_string(), secrets))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|e| failure("waiting for python3", &e.to_string(), secrets))?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            let last = detail
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("no diagnostic output");
            return Err(failure("tpm2_ptool", last, secrets));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// tpm2-pkcs11 reads its token list once per initialization, so a token added by `tpm2_ptool`
    /// after that is only visible after one re-initialization.
    pub(crate) fn open_token(&self, guard: &Guard, label: &str) -> Result<Token, KeydError> {
        let mut loaded = guard.loaded.borrow_mut();
        for refreshed in [false, true] {
            if refreshed {
                **loaded = None;
            }
            if loaded.is_none() {
                **loaded = Some(self.load_module()?);
            }
            let module = loaded.as_ref().expect("module loaded above");
            if module.store_dir != self.store_dir || module.tcti != self.tcti {
                return Err(KeydError::Config(
                    "the PKCS#11 module is already bound to another store or TCTI in this process"
                        .into(),
                ));
            }
            let slots = module
                .context
                .get_slots_with_token()
                .map_err(|e| p11_failure("listing token slots", &e))?;
            for slot in slots {
                let info = module
                    .context
                    .get_token_info(slot)
                    .map_err(|e| p11_failure("reading token info", &e))?;
                if info.label().trim_end() == label {
                    let session = module
                        .context
                        .open_ro_session(slot)
                        .map_err(|e| p11_failure("opening a session", &e))?;
                    return Ok(Token { session });
                }
            }
        }
        Err(KeydError::NotProvisioned)
    }

    fn load_module(&self) -> Result<Loaded, KeydError> {
        for (key, value) in self.tool_env() {
            if [
                "TPM2_PKCS11_STORE",
                "TPM2_PKCS11_TCTI",
                "TPM2_PKCS11_BACKEND",
                "DBUS_SESSION_BUS_ADDRESS",
            ]
            .iter()
            .any(|name| key == *name)
            {
                std::env::set_var(key, value);
            }
        }
        let context = Pkcs11::new(self.module_path()?)
            .map_err(|e| p11_failure("loading the PKCS#11 module", &e))?;
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| p11_failure("initializing the PKCS#11 module", &e))?;
        Ok(Loaded {
            context,
            store_dir: self.store_dir.clone(),
            tcti: self.tcti.clone(),
        })
    }
}

fn p11_kit_list_modules() -> Option<String> {
    let output = Command::new("p11-kit")
        .arg("list-modules")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn module_from_p11_kit(listing: &str) -> Option<PathBuf> {
    listing
        .lines()
        .filter_map(|line| line.trim().strip_prefix("path:"))
        .map(|path| path.trim())
        .find(|path| path.ends_with(MODULE_FILE))
        .map(PathBuf::from)
}

pub fn resolve_module(
    explicit: Option<&Path>,
    prefix: Option<&Path>,
    p11_kit_listing: impl FnOnce() -> Option<String>,
    loads_by_name: impl FnOnce(&str) -> bool,
) -> Result<PathBuf, KeydError> {
    if let Some(module) = explicit {
        return Ok(module.to_path_buf());
    }
    if let Some(prefix) = prefix {
        return Ok(prefix.join(PKCS11_SUBPATH));
    }
    if let Some(found) = p11_kit_listing().as_deref().and_then(module_from_p11_kit) {
        return Ok(found);
    }
    if loads_by_name(MODULE_FILE) {
        return Ok(PathBuf::from(MODULE_FILE));
    }
    crate::logging::log(
        crate::logging::Level::Error,
        "tpm2-pkcs11-module-not-found",
        &[(
            "tried",
            crate::logging::Value::Reason(
                "OPENHELLO_TPM2_PKCS11_MODULE, OPENHELLO_TPM2_PKCS11_PREFIX, p11-kit list-modules, loader cache by name".into(),
            ),
        )],
    );
    Err(KeydError::Config(
        "the tpm2-pkcs11 module was not found; install the tpm2-pkcs11 package or set OPENHELLO_TPM2_PKCS11_MODULE".into(),
    ))
}

pub(crate) struct Token {
    pub session: Session,
}

impl Token {
    pub fn login(&self, secret: &Secret) -> Result<(), KeydError> {
        let pin = AuthPin::from(secret.expose().to_string());
        self.session
            .login(UserType::User, Some(&pin))
            .map_err(|e| match e {
                P11Error::Pkcs11(
                    RvError::PinIncorrect | RvError::PinLocked | RvError::PinLenRange,
                    _,
                ) => KeydError::AuthenticationFailed,
                other => p11_failure("logging in to the token", &other),
            })
    }
}

#[derive(Debug, Default)]
pub(crate) struct TokenDump {
    pub present: bool,
    pub objects: Vec<DumpedObject>,
}

#[derive(Debug)]
pub(crate) struct DumpedObject {
    pub class: u64,
    pub id: String,
    pub extractable: bool,
    pub sensitive: bool,
    pub tpm_public: Option<Vec<u8>>,
}

impl TokenDump {
    fn parse(text: &str) -> Option<Self> {
        let mut dump = Self::default();
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                ["token", "present"] => dump.present = true,
                ["token", "absent"] => {}
                ["object", class, id, extractable, sensitive, blob] => {
                    dump.objects.push(DumpedObject {
                        class: class.parse().ok()?,
                        id: (*id).to_string(),
                        extractable: *extractable == "1",
                        sensitive: *sensitive == "1",
                        tpm_public: if *blob == "-" { None } else { decode_hex(blob) },
                    })
                }
                _ => return None,
            }
        }
        Some(dump)
    }
}

pub(crate) fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

pub(crate) fn store_file(dir: &Path) -> PathBuf {
    dir.join(DATABASE_FILE)
}

pub(crate) fn failure(context: &str, detail: &str, secrets: &[&str]) -> KeydError {
    let mut detail = detail.to_string();
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        detail = detail.replace(secret, "[redacted]");
    }
    crate::logging::log(
        crate::logging::Level::Error,
        "tpm-failure",
        &[
            (
                "context",
                crate::logging::Value::Reason(context.to_string()),
            ),
            ("detail", crate::logging::Value::Reason(detail)),
        ],
    );
    KeydError::Tpm
}

pub(crate) fn p11_failure(context: &str, error: &P11Error) -> KeydError {
    failure(context, &error.to_string(), &[])
}
