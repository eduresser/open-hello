#[path = "../../openhello-keyd/tests/support/mod.rs"]
mod support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use openhello_keyd::{
    KeyInfo, Protectors, TicketSocket, TicketSocketConfig, TokenSocket, TokenSocketConfig,
    OP_TICKET, OP_TICKET_KEY, STATUS_ACCEPTED,
};
use openhello_ticket::{Issuer, TicketKey, KEY_LEN};
use support::{rig, Rig};

const PIN: &str = "482916";
const OTHER_UID: u32 = 2999;
const SERVICE: &str = "sudo";
const INCLUDED: &str = "sudo-openhello";
const BUS_NAME: &str = "io.openhello.Biometrics1";
const OBJECT_PATH: &str = "/io/openhello/Biometrics1";
const STACK: &str = include_str!("../../../packaging/pam/sudo-openhello");
const PAM_PKCS11_CONF: &str = include_str!("../../../packaging/pam/pam_pkcs11.conf");
const WITHIN_BUDGET: Duration = Duration::from_secs(5);
const STRICT_CLEAR: &str = "[ignore=ignore default=die]";

const CLIENT_C: &str = r#"
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
  struct pam_response *r = calloc(n, sizeof *r);
  (void)data;
  for (int i = 0; i < n; i++) {
    printf("PROMPT %d %s\n", msg[i]->msg_style, msg[i]->msg);
    fflush(stdout);
    if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
      const char *pin = getenv("PAMTEST_PIN");
      r[i].resp = strdup(pin ? pin : "");
    }
  }
  *resp = r;
  return PAM_SUCCESS;
}

int main(int argc, char **argv) {
  struct pam_conv c = {conv, NULL};
  pam_handle_t *h;
  if (argc < 3) return 2;
  int rc = pam_start(argv[1], argv[2], &c, &h);
  if (rc != PAM_SUCCESS) return 2;
  pam_fail_delay(h, 0);
  rc = pam_authenticate(h, 0);
  printf("RESULT %d\n", rc);
  pam_end(h, rc);
  return 0;
}
"#;

const RECORDER_C: &str = r#"
#include <security/pam_modules.h>
#include <stdio.h>
#include <string.h>

int pam_sm_authenticate(pam_handle_t *h, int flags, int argc, const char **argv) {
  const void *token = NULL;
  (void)flags;
  for (int i = 0; i < argc; i++) {
    if (strncmp(argv[i], "path=", 5) == 0) {
      pam_get_item(h, PAM_AUTHTOK, &token);
      FILE *f = fopen(argv[i] + 5, "a");
      if (f) {
        fprintf(f, "authtok=%s\n", token ? "set" : "unset");
        fclose(f);
      }
    }
  }
  return PAM_AUTH_ERR;
}

int pam_sm_setcred(pam_handle_t *h, int flags, int argc, const char **argv) {
  (void)h; (void)flags; (void)argc; (void)argv;
  return PAM_SUCCESS;
}
"#;

#[derive(Clone, Copy, PartialEq)]
enum Verify {
    Matches,
    NoMatch,
    Hangs,
}

struct VerifyState {
    ticket_socket: PathBuf,
    mode: Verify,
    calls: u32,
}

static VERIFY: Mutex<Option<VerifyState>> = Mutex::new(None);

struct FakeBiometrics;

#[zbus::interface(name = "io.openhello.Biometrics1")]
impl FakeBiometrics {
    async fn verify(&self, uid: u32) -> bool {
        let (mode, socket) = {
            let mut guard = VERIFY.lock().unwrap_or_else(PoisonError::into_inner);
            let state = guard.as_mut().expect("verify state set by the test");
            state.calls += 1;
            (state.mode, state.ticket_socket.clone())
        };
        match mode {
            Verify::NoMatch => false,
            Verify::Hangs => {
                async_io::Timer::after(Duration::from_secs(15)).await;
                false
            }
            Verify::Matches => deliver_ticket(&socket, uid),
        }
    }
}

fn deliver_ticket(socket: &Path, uid: u32) -> bool {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let reply = frame_exchange(&mut stream, OP_TICKET_KEY, &[], 1 + KEY_LEN);
    assert_eq!(reply[0], STATUS_ACCEPTED);
    let key = TicketKey::from_bytes(reply[1..].try_into().unwrap());
    let ticket = Issuer::new(key).issue(uid).unwrap().encode();
    frame_exchange(&mut stream, OP_TICKET, &ticket, 1)[0] == STATUS_ACCEPTED
}

fn frame_exchange(stream: &mut UnixStream, op: u8, payload: &[u8], reply_len: usize) -> Vec<u8> {
    let mut frame = vec![op];
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).unwrap();
    let mut reply = vec![0u8; reply_len];
    stream.read_exact(&mut reply).unwrap();
    reply
}

fn serve_fake_biometrics(address: &str) {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let address = address.to_string();
        let (ready, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            async_io::block_on(async move {
                let _connection = zbus::connection::Builder::address(address.as_str())
                    .unwrap()
                    .name(BUS_NAME)
                    .unwrap()
                    .serve_at(OBJECT_PATH, FakeBiometrics)
                    .unwrap()
                    .build()
                    .await
                    .unwrap();
                ready.send(()).unwrap();
                std::future::pending::<()>().await;
            })
        });
        wait.recv_timeout(Duration::from_secs(10))
            .expect("fake io.openhello.Biometrics1 did not start on the rig bus");
    });
}

fn uid() -> u32 {
    let uid = unsafe { libc::getuid() };
    assert!(
        uid <= 0xFFFF,
        "uid {uid} is outside the range keyd supports (0..=65535); run the tests as a regular user"
    );
    uid
}

fn linux_user_name(uid: u32) -> Option<String> {
    let mut buffer = vec![0u8; 4096];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if rc != 0 || found.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }
        .to_str()
        .ok()
        .map(str::to_string)
}

fn user_name_for(requested: u32) -> Option<String> {
    if requested == unsafe { libc::getuid() } {
        linux_user_name(requested)
    } else {
        Some(format!("user{requested}"))
    }
}

fn run_tool(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{program} must be installed to run the PAM tests: {e}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn libpam() -> &'static str {
    [
        "/usr/lib64/libpam.so.0",
        "/lib64/libpam.so.0",
        "/usr/lib/libpam.so.0",
        "/usr/lib/x86_64-linux-gnu/libpam.so.0",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists())
    .expect("libpam.so.0 not found; install the PAM runtime to run the PAM tests")
}

fn compile(rig: &Rig, dir: &Path, name: &str, source: &str, shared: bool) -> PathBuf {
    let source_file = dir.join(format!("{name}.c"));
    std::fs::write(&source_file, source).unwrap();
    let output = dir.join(if shared {
        format!("{name}.so")
    } else {
        name.to_string()
    });
    let include = format!("-I{}", rig.prefix.join("usr/include").display());
    let mut args = vec!["-Wall", "-o", output.to_str().unwrap(), &include];
    if shared {
        args.extend(["-shared", "-fPIC"]);
    }
    args.push(source_file.to_str().unwrap());
    if !shared {
        args.push(libpam());
    }
    run_tool("gcc", &args);
    output
}

fn wrapper_library() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| library("openhello-pkcs11", "libopenhello_pkcs11.so"))
        .clone()
}

fn pam_module() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| library("openhello-pam", "libpam_openhello.so"))
        .clone()
}

fn library(package: &str, file: &str) -> PathBuf {
    let profile_dir = std::env::current_exe()
        .unwrap()
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let path = profile_dir.join(file);
    let mut build = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    build.args(["build", "-p", package]);
    if profile_dir.ends_with("release") {
        build.arg("--release");
    }
    let status = build
        .status()
        .expect("cargo must be available to build the PAM libraries");
    assert!(status.success(), "cargo build -p {package} failed");
    assert!(path.exists(), "{} was not built", path.display());
    path
}

struct Fixture {
    dir: tempfile::TempDir,
    config: openhello_keyd::KeydConfig,
    protectors: Arc<Protectors>,
    key: KeyInfo,
    client: PathBuf,
    recorder: PathBuf,
    pkcs11_conf: PathBuf,
}

static FIXTURE: Mutex<Option<Fixture>> = Mutex::new(None);

extern "C" fn drop_fixture() {
    FIXTURE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
}

impl Fixture {
    fn etc(&self) -> PathBuf {
        self.dir.path().join("etc")
    }
}

fn with_fixture<R>(rig: &Rig, body: impl FnOnce(&Fixture) -> R) -> R {
    let mut guard = FIXTURE.lock().unwrap_or_else(PoisonError::into_inner);
    if guard.is_none() {
        *guard = Some(build_fixture(rig));
        unsafe { libc::atexit(drop_fixture) };
    }
    body(guard.as_ref().unwrap())
}

fn build_fixture(rig: &Rig) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path().join("etc");
    for sub in ["cacerts", "crls"] {
        std::fs::create_dir_all(etc.join(sub)).unwrap();
    }
    let mut config = rig.config.clone();
    config.nss_dir = Some(etc.join("nssdb"));
    config.mapfile = etc.join("pkcs11-subject-map");
    config.user_name = Some(user_name_for);
    let protectors = Arc::new(Protectors::new(config.clone()).unwrap());
    protectors.provision_protectors(OTHER_UID).unwrap();
    protectors.provision_protectors(uid()).unwrap();
    protectors.set_pin(uid(), PIN).unwrap();
    let key = protectors.keyd().key(uid()).unwrap();

    let client = compile(rig, dir.path(), "pamtest", CLIENT_C, false);
    let recorder = compile(rig, dir.path(), "recorder", RECORDER_C, true);
    let pkcs11_conf = etc.join("pam_pkcs11.conf");
    let text = PAM_PKCS11_CONF
        .replace(
            "/usr/lib/openhello/libopenhello_pkcs11.so",
            wrapper_library().to_str().unwrap(),
        )
        .replace(
            "/usr/lib64/pam_pkcs11",
            rig.prefix.join("usr/lib64/pam_pkcs11").to_str().unwrap(),
        )
        .replace("/etc/openhello", etc.to_str().unwrap());
    std::fs::write(&pkcs11_conf, text).unwrap();
    Fixture {
        dir,
        config,
        protectors,
        key,
        client,
        recorder,
        pkcs11_conf,
    }
}

struct Stack {
    verify: Verify,
    pin_prompt: bool,
    typed: &'static str,
    token_socket: Option<PathBuf>,
    bus: Option<String>,
}

impl Stack {
    fn face(verify: Verify) -> Self {
        Self {
            verify,
            pin_prompt: false,
            typed: "",
            token_socket: None,
            bus: None,
        }
    }
}

struct Outcome {
    result: i32,
    reached: Vec<String>,
    prompts: Vec<(i32, String)>,
    elapsed: Duration,
    verify_calls: u32,
}

impl Outcome {
    fn granted(&self) -> bool {
        self.result == 0
    }

    fn password_prompts(&self) -> usize {
        self.prompts
            .iter()
            .filter(|(style, _)| *style == 1 || *style == 2)
            .count()
    }

    fn said_looking_for_your_face(&self) -> bool {
        self.prompts
            .iter()
            .any(|(style, text)| *style == 4 && text == "Looking for your face...")
    }
}

fn service_text(rig: &Rig, stack: &Stack, pkcs11_conf: &Path, hooks_conf: &Path) -> String {
    let mut lines = Vec::new();
    for line in STACK.lines() {
        let line = match line.strip_prefix("#auth") {
            Some(rest) if stack.pin_prompt => format!("auth{rest}"),
            _ => line.to_string(),
        };
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() != Some(&"auth") {
            continue;
        }
        let at = fields
            .iter()
            .position(|f| f.starts_with("pam_"))
            .expect("every stack line names a module");
        let (control, module_name, rest) = (
            fields[1..at].join(" "),
            fields[at],
            fields[at + 1..].join(" "),
        );
        let control = match (module_name, rest.as_str()) {
            ("pam_openhello.so", "clear") => STRICT_CLEAR.to_string(),
            ("pam_openhello.so", _) => control.replace("default=ignore", "default=die"),
            _ => control,
        };
        let module = match module_name {
            "pam_openhello.so" => {
                format!("{} config={}", pam_module().display(), hooks_conf.display())
            }
            _ => pam_pkcs11_module(rig),
        };
        let rest = rest.replace(
            "/etc/openhello/pam_pkcs11.conf",
            pkcs11_conf.to_str().unwrap(),
        );
        lines.push(format!("auth {control} {module} {rest}"));
    }
    lines.join("\n") + "\n"
}

fn pam_pkcs11_module(rig: &Rig) -> String {
    let module = rig.prefix.join("usr/lib64/security/pam_pkcs11.so");
    assert!(
        module.exists(),
        "{} not found: the prefix built by scripts/spike-pkcs11.sh must hold pam_pkcs11",
        module.display()
    );
    module.display().to_string()
}

fn run_stack(rig: &Rig, fixture: &Fixture, stack: &Stack) -> Outcome {
    rig.clear_lockout();
    let bus = stack
        .bus
        .clone()
        .unwrap_or_else(|| rig.config.env[0].1.clone());
    let token = stack
        .token_socket
        .clone()
        .expect("every scenario names its token socket");
    let etc = fixture.etc();
    let hooks_conf = etc.join("pkcs11.conf");
    std::fs::write(
        &hooks_conf,
        format!(
            "token_socket = {}\nbus_address = {bus}\n",
            token.display()
        ),
    )
    .unwrap();
    let services = fixture.dir.path().join("services");
    std::fs::create_dir_all(&services).unwrap();
    std::fs::write(
        services.join(INCLUDED),
        service_text(rig, stack, &fixture.pkcs11_conf, &hooks_conf),
    )
    .unwrap();
    std::fs::write(
        services.join(SERVICE),
        format!(
            "auth include {INCLUDED}\nauth required {} path={}\n",
            fixture.recorder.display(),
            fixture.dir.path().join("reached").display()
        ),
    )
    .unwrap();
    let reached_file = fixture.dir.path().join("reached");
    let _ = std::fs::remove_file(&reached_file);
    set_verify(stack.verify, 0);

    let lib64 = rig.prefix.join("usr/lib64");
    let started = Instant::now();
    let output = Command::new(&fixture.client)
        .args([SERVICE, &linux_user_name(uid()).unwrap()])
        .env("PAM_WRAPPER", "1")
        .env("PAM_WRAPPER_SERVICE_DIR", &services)
        .env("LD_PRELOAD", lib64.join("libpam_wrapper.so"))
        .env("LD_LIBRARY_PATH", &lib64)
        .env(openhello_pkcs11::CONFIG_ENV, &hooks_conf)
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("TPM2_PKCS11_STORE")
        .env_remove("TPM2_PKCS11_TCTI")
        .env_remove("TPM2_PKCS11_BACKEND")
        .env_remove("TPM2TOOLS_TCTI")
        .env("PAMTEST_PIN", stack.typed)
        .output()
        .expect("the compiled PAM client must run");
    let elapsed = started.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let result = stdout
        .lines()
        .find_map(|l| l.strip_prefix("RESULT "))
        .unwrap_or_else(|| {
            panic!(
                "the PAM client ended with {:?} and printed no result: {stdout}{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .parse()
        .unwrap();
    let prompts = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("PROMPT "))
        .filter_map(|l| l.split_once(' '))
        .map(|(style, text)| (style.parse().unwrap(), text.to_string()))
        .collect();
    Outcome {
        result,
        reached: std::fs::read_to_string(&reached_file)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect(),
        prompts,
        elapsed,
        verify_calls: verify_calls(),
    }
}

fn set_verify(mode: Verify, calls: u32) {
    let mut guard = VERIFY.lock().unwrap_or_else(PoisonError::into_inner);
    let state = guard
        .as_mut()
        .expect("fixture binds the ticket socket first");
    state.mode = mode;
    state.calls = calls;
}

fn verify_calls() -> u32 {
    VERIFY
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .unwrap()
        .calls
}

struct Services {
    token_path: PathBuf,
    _ticket: TicketSocket,
    _token: TokenSocket,
    _dir: tempfile::TempDir,
}

fn services(rig: &Rig, fixture: &Fixture) -> Services {
    let dir = tempfile::tempdir().unwrap();
    let ticket_path = dir.path().join("ticket.sock");
    let token_path = dir.path().join("token.sock");
    let ticket = TicketSocket::bind(
        fixture.protectors.clone(),
        TicketSocketConfig {
            path: ticket_path.clone(),
            allowed_uid: uid(),
            expected_exe: None,
        },
    )
    .unwrap();
    let token = TokenSocket::bind(
        fixture.protectors.clone(),
        TokenSocketConfig {
            path: token_path.clone(),
        },
    )
    .unwrap();
    serve_fake_biometrics(&rig.config.env[0].1);
    *VERIFY.lock().unwrap_or_else(PoisonError::into_inner) = Some(VerifyState {
        ticket_socket: ticket_path,
        mode: Verify::NoMatch,
        calls: 0,
    });
    Services {
        token_path,
        _ticket: ticket,
        _token: token,
        _dir: dir,
    }
}

fn scenario(rig: &Rig, fixture: &Fixture, services: &Services, mut stack: Stack) -> Outcome {
    stack
        .token_socket
        .get_or_insert(services.token_path.clone());
    run_stack(rig, fixture, &stack)
}

struct PrivateBus {
    child: Child,
    address: String,
}

impl PrivateBus {
    fn start() -> Self {
        use std::io::{BufRead, BufReader};
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("dbus-daemon must be installed to run the PAM tests");
        let mut address = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        Self {
            child,
            address: address.trim().to_string(),
        }
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// @spec:AC-027
#[test]
fn a_matching_face_authenticates_the_service_without_a_password_prompt() {
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);
        let before = rig.lockout_counter();

        let outcome = scenario(&rig, fixture, &services, Stack::face(Verify::Matches));

        assert!(
            outcome.granted(),
            "a matching face must authenticate (prompts: {:?})",
            outcome.prompts
        );
        assert!(
            outcome.reached.is_empty(),
            "the password module must not run"
        );
        assert_eq!(outcome.password_prompts(), 0, "{:?}", outcome.prompts);
        assert!(outcome.said_looking_for_your_face());
        assert_eq!(outcome.verify_calls, 1);
        assert_eq!(rig.lockout_counter(), before);
    });
}

// @spec:AC-029
#[test]
fn a_different_face_or_another_key_under_the_same_subject_is_not_accepted_and_the_stack_continues()
{
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);

        let other_face = scenario(&rig, fixture, &services, Stack::face(Verify::NoMatch));
        assert!(!other_face.granted());
        assert_eq!(other_face.reached, ["authtok=unset"]);
        assert_eq!(other_face.verify_calls, 1);
        assert_eq!(other_face.password_prompts(), 0);

        let rogue = RogueCertificate::install(&rig, fixture);
        let other_key = scenario(&rig, fixture, &services, Stack::face(Verify::Matches));
        drop(rogue);
        assert!(
            !other_key.granted(),
            "a certificate for another key must fail the signed challenge"
        );
        assert_eq!(other_key.reached, ["authtok=unset"]);
        assert_eq!(other_key.verify_calls, 1);

        let again = scenario(&rig, fixture, &services, Stack::face(Verify::Matches));
        assert!(again.granted(), "the genuine certificate works again");
    });
}

// @spec:AC-030
#[test]
fn a_missing_keyd_or_openhellod_or_a_silent_camera_falls_through_within_five_seconds() {
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);

        let no_keyd = scenario(
            &rig,
            fixture,
            &services,
            Stack {
                token_socket: Some(fixture.dir.path().join("absent.sock")),
                ..Stack::face(Verify::Matches)
            },
        );
        let empty_bus = PrivateBus::start();
        let no_openhellod = scenario(
            &rig,
            fixture,
            &services,
            Stack {
                bus: Some(empty_bus.address.clone()),
                ..Stack::face(Verify::Matches)
            },
        );
        drop(empty_bus);
        for outcome in [&no_keyd, &no_openhellod] {
            assert!(!outcome.granted());
            assert_eq!(outcome.reached, ["authtok=unset"]);
            assert_eq!(
                outcome.verify_calls, 0,
                "no face match without the services"
            );
            assert_eq!(outcome.password_prompts(), 0);
            assert!(!outcome.said_looking_for_your_face());
            assert!(outcome.elapsed < WITHIN_BUDGET, "{:?}", outcome.elapsed);
        }

        let silent = scenario(&rig, fixture, &services, Stack::face(Verify::Hangs));
        assert!(!silent.granted());
        assert_eq!(silent.reached, ["authtok=unset"]);
        assert_eq!(silent.verify_calls, 1);
        assert!(silent.said_looking_for_your_face());
        assert!(
            silent.elapsed < WITHIN_BUDGET,
            "the camera wait took {:?}",
            silent.elapsed
        );
    });
}

#[test]
fn the_optional_pin_line_accepts_the_pin_after_a_face_miss_and_a_wrong_pin_falls_through() {
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);

        let correct = scenario(
            &rig,
            fixture,
            &services,
            Stack {
                pin_prompt: true,
                typed: PIN,
                ..Stack::face(Verify::NoMatch)
            },
        );
        assert!(correct.granted(), "{:?}", correct.prompts);
        assert_eq!(correct.password_prompts(), 1);
        assert!(correct.reached.is_empty());
        assert_eq!(correct.verify_calls, 1);

        let wrong = scenario(
            &rig,
            fixture,
            &services,
            Stack {
                pin_prompt: true,
                typed: "000000",
                ..Stack::face(Verify::NoMatch)
            },
        );
        assert!(!wrong.granted());
        assert_eq!(wrong.reached, ["authtok=unset"]);
        assert_eq!(rig.lockout_counter(), 1);
        rig.clear_lockout();
    });
}

struct RogueCertificate<'a> {
    rig: &'a Rig,
    fixture: &'a Fixture,
    genuine_pem: String,
}

impl<'a> RogueCertificate<'a> {
    fn install(rig: &'a Rig, fixture: &'a Fixture) -> Self {
        let genuine_der = fixture.protectors.keyd().certificate(uid()).unwrap();
        let work = fixture.dir.path();
        let key = work.join("rogue.key");
        let pem = work.join("rogue.pem");
        let genuine = work.join("genuine.pem");
        let conf = work.join("rogue.cnf");
        std::fs::write(
            &conf,
            "[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=plain\n[dn]\nCN=x\n[plain]\nsubjectKeyIdentifier=none\nauthorityKeyIdentifier=none\n",
        )
        .unwrap();
        run_tool(
            "openssl",
            &[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                key.to_str().unwrap(),
            ],
        );
        let subject = format!("/CN=openhello-uid-{}", uid());
        run_tool(
            "openssl",
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                key.to_str().unwrap(),
                "-subj",
                &subject,
                "-days",
                "3650",
                "-config",
                conf.to_str().unwrap(),
                "-out",
                pem.to_str().unwrap(),
            ],
        );
        let genuine_pem = pem_of(&genuine_der);
        std::fs::write(&genuine, &genuine_pem).unwrap();

        let spec = format!("sql:{}", fixture.config.nss_dir.as_ref().unwrap().display());
        let certutil = rig.prefix.join("usr/bin/certutil");
        let lib64 = rig.prefix.join("usr/lib64");
        let status = Command::new(&certutil)
            .args(["-A", "-d", &spec, "-n", "rogue", "-t", "CT,C,C", "-i"])
            .arg(&pem)
            .env("LD_LIBRARY_PATH", &lib64)
            .status()
            .expect("certutil from the prefix must run");
        assert!(status.success(), "importing the rogue certificate failed");

        let rogue = Self {
            rig,
            fixture,
            genuine_pem,
        };
        rogue.swap_token_certificate(&pem);
        rogue
    }

    fn ptool(&self, args: &[&str]) -> String {
        let site: Vec<String> = ["usr/lib", "usr/lib64"]
            .iter()
            .map(|d| format!("{}/{d}/python3.13/site-packages", self.rig.prefix.display()))
            .collect();
        run_env(
            Command::new("python3")
                .arg(self.rig.prefix.join("usr/bin/tpm2_ptool"))
                .args(args)
                .env("PYTHONPATH", site.join(":"))
                .env("PYTHONWARNINGS", "ignore")
                .env("LD_LIBRARY_PATH", self.rig.prefix.join("usr/lib64"))
                .env("TPM2_PKCS11_STORE", &self.fixture.config.store_dir)
                .env("TPM2TOOLS_TCTI", self.fixture.config.tcti.as_ref().unwrap())
                .env("DBUS_SESSION_BUS_ADDRESS", &self.rig.config.env[0].1),
        )
    }

    fn certificate_object(&self) -> String {
        let label = format!("openhello-{}", uid());
        let listing = self.ptool(&["listobjects", "--label", &label]);
        let mut in_certificate = false;
        for line in listing.lines() {
            let line = line.trim().trim_start_matches("- ");
            if line.starts_with("CKA_CLASS:") {
                in_certificate = line.contains("CKO_CERTIFICATE");
            }
            if in_certificate {
                if let Some(id) = line.strip_prefix("id: ") {
                    return id.trim().to_string();
                }
            }
        }
        panic!("no certificate object in the token listing:\n{listing}");
    }

    fn swap_token_certificate(&self, pem: &Path) {
        let object = self.certificate_object();
        self.ptool(&["objdel", &object]);
        self.ptool(&[
            "addcert",
            "--label",
            &format!("openhello-{}", uid()),
            "--key-id",
            &self.fixture_key().handle,
            pem.to_str().unwrap(),
        ]);
    }

    fn fixture_key(&self) -> &KeyInfo {
        &self.fixture.key
    }
}

impl Drop for RogueCertificate<'_> {
    fn drop(&mut self) {
        let genuine = self.fixture.dir.path().join("genuine.pem");
        std::fs::write(&genuine, &self.genuine_pem).unwrap();
        self.swap_token_certificate(&genuine);
        let spec = format!(
            "sql:{}",
            self.fixture.config.nss_dir.as_ref().unwrap().display()
        );
        let _ = Command::new(self.rig.prefix.join("usr/bin/certutil"))
            .args(["-D", "-d", &spec, "-n", "rogue"])
            .env("LD_LIBRARY_PATH", self.rig.prefix.join("usr/lib64"))
            .status();
    }
}

fn run_env(command: &mut Command) -> String {
    let output = command.output().expect("python3 must be installed");
    assert!(
        output.status.success(),
        "tool failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn pem_of(der: &[u8]) -> String {
    let mut child = Command::new("openssl")
        .args(["x509", "-inform", "DER", "-outform", "PEM"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("openssl must be installed to run the PAM tests");
    child.stdin.take().unwrap().write_all(der).unwrap();
    String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap()
}
