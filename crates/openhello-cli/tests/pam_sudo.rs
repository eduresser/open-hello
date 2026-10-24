#[path = "../../openhello-keyd/tests/support/mod.rs"]
mod support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use openhello_keyd::{
    Protectors, TicketSocket, TicketSocketConfig, TokenSocket, TokenSocketConfig, OP_TICKET,
    OP_TICKET_KEY, STATUS_ACCEPTED,
};
use openhello_ticket::{Issuer, TicketKey, KEY_LEN};
use support::{rig, Rig};

const OTHER_UID: u32 = 2999;
const SERVICE: &str = "sudo";
const INCLUDED: &str = "sudo-openhello";
const BUS_NAME: &str = "io.openhello.Biometrics1";
const OBJECT_PATH: &str = "/io/openhello/Biometrics1";
const STACK: &str = include_str!("../../../packaging/pam/sudo-openhello");
const INTERACTIVE_SERVICE: &str = "openhello-interactive";
const COMMON_STACK: &str = "auth sufficient pam_openhello.so\n";
const INTERACTIVE_STACK: &str = "auth sufficient pam_openhello.so\nauth required pam_deny.so\n";
const DENIED_SERVICES: [&str; 13] = [
    "login",
    "su",
    "su-l",
    "sshd",
    "cron",
    "crond",
    "atd",
    "passwd",
    "chsh",
    "chfn",
    "runuser",
    "runuser-l",
    "other",
];
const WITHIN_BUDGET: Duration = Duration::from_secs(5);
const SLOW_VERIFY: Duration = Duration::from_secs(6);
const MODULE_BUDGET: Duration = Duration::from_secs(30);
const STRICT_CONTROL: &str = "[success=done ignore=ignore default=die]";
const PAM_AUTH_ERR: i32 = 7;
const AUTH_OP: u8 = 11;

const CLIENT_C: &str = r#"
#include <security/pam_appl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t interrupted;
static void on_interrupt(int signal) { (void)signal; interrupted = 1; }

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
  const char *tty = getenv("PAMTEST_TTY");
  const char *rhost = getenv("PAMTEST_RHOST");
  pam_set_item(h, PAM_TTY, tty ? tty : "/dev/pts/0");
  if (rhost) pam_set_item(h, PAM_RHOST, rhost);
  pam_fail_delay(h, 0);
  sigset_t only_int;
  sigemptyset(&only_int);
  sigaddset(&only_int, SIGINT);
  if (getenv("PAMTEST_CATCH_SIGINT")) signal(SIGINT, on_interrupt);
  if (getenv("PAMTEST_BLOCK_SIGINT")) sigprocmask(SIG_BLOCK, &only_int, NULL);
  rc = pam_authenticate(h, 0);
  sigprocmask(SIG_UNBLOCK, &only_int, NULL);
  printf("RESULT %d\n", rc);
  printf("SIGINT %d\n", (int)interrupted);
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
    NoTicket,
    Slow,
    Hangs,
    AlreadyDecided,
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.openhello.Error")]
enum FakeError {
    AlreadyDecided(String),
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
    async fn verify_for_sign_in(&self, uid: u32) -> Result<bool, FakeError> {
        let (mode, socket) = {
            let mut guard = VERIFY.lock().unwrap_or_else(PoisonError::into_inner);
            let state = guard.as_mut().expect("verify state set by the test");
            state.calls += 1;
            (state.mode, state.ticket_socket.clone())
        };
        Ok(match mode {
            Verify::NoMatch => false,
            Verify::NoTicket => true,
            Verify::Slow => {
                async_io::Timer::after(SLOW_VERIFY).await;
                deliver_ticket(&socket, uid)
            }
            Verify::Hangs => {
                async_io::Timer::after(Duration::from_secs(40)).await;
                false
            }
            Verify::Matches => deliver_ticket(&socket, uid),
            Verify::AlreadyDecided => return Err(FakeError::AlreadyDecided("face already checked".into())),
        })
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
    client: PathBuf,
    recorder: PathBuf,
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

    fn public_key_file(&self) -> PathBuf {
        self.config.auth_dir.join(format!("{}.pub", uid()))
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
    std::fs::create_dir_all(dir.path().join("etc")).unwrap();
    let mut config = rig.config.clone();
    config.user_name = Some(user_name_for);
    let protectors = Arc::new(Protectors::new(config.clone()).unwrap());
    protectors.provision_protectors(OTHER_UID).unwrap();
    protectors.provision_protectors(uid()).unwrap();

    let client = compile(rig, dir.path(), "pamtest", CLIENT_C, false);
    let recorder = compile(rig, dir.path(), "recorder", RECORDER_C, true);
    Fixture {
        dir,
        config,
        protectors,
        client,
        recorder,
    }
}

struct Stack {
    verify: Verify,
    strict: bool,
    root_owned_keys_only: bool,
    token_socket: Option<PathBuf>,
    bus: Option<String>,
    direct: Option<&'static str>,
    common: bool,
    rhost: Option<&'static str>,
    user: Option<&'static str>,
    interrupt_after: Option<Duration>,
    block_sigint: bool,
}

impl Stack {
    fn face(verify: Verify) -> Self {
        Self {
            verify,
            strict: true,
            root_owned_keys_only: false,
            token_socket: None,
            bus: None,
            direct: None,
            common: false,
            rhost: None,
            user: None,
            interrupt_after: None,
            block_sigint: false,
        }
    }

    fn blocking_sigint(self) -> Self {
        Self {
            block_sigint: true,
            ..self
        }
    }

    fn interrupted_after(self, after: Duration) -> Self {
        Self {
            interrupt_after: Some(after),
            ..self
        }
    }

    fn common(verify: Verify, service: &'static str) -> Self {
        Self {
            common: true,
            direct: Some(service),
            ..Self::face(verify)
        }
    }

    fn lenient(self) -> Self {
        Self {
            strict: false,
            ..self
        }
    }

    fn interactive(verify: Verify) -> Self {
        Self {
            direct: Some(INTERACTIVE_SERVICE),
            ..Self::face(verify)
        }
    }
}

struct Outcome {
    result: i32,
    reached: Vec<String>,
    prompts: Vec<(i32, String)>,
    elapsed: Duration,
    verify_calls: u32,
    sigint_seen: bool,
}

impl Outcome {
    fn granted(&self) -> bool {
        self.result == 0
    }

    fn refused_outright(&self) -> bool {
        self.result == PAM_AUTH_ERR && self.reached.is_empty()
    }

    fn password_prompts(&self) -> usize {
        self.prompts
            .iter()
            .filter(|(style, _)| *style == 1 || *style == 2)
            .count()
    }

    fn showed_no_message(&self) -> bool {
        self.prompts.iter().all(|(style, _)| *style != 4)
    }
}

fn service_text(stack: &Stack, hooks_conf: &Path, auth_dir: &Path, etc: &Path) -> String {
    let text = match (stack.direct, stack.common) {
        (_, true) => COMMON_STACK,
        (Some(_), _) => INTERACTIVE_STACK,
        _ => STACK,
    };
    let trust = if stack.root_owned_keys_only {
        String::new()
    } else {
        format!(" trusted_uid={}", unsafe { libc::geteuid() })
    };
    let mut lines = Vec::new();
    for line in text.lines() {
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
        let rest = rest.replace("/etc/openhello", etc.to_str().unwrap());
        let line = match module_name {
            "pam_openhello.so" => {
                let control = if stack.strict {
                    STRICT_CONTROL
                } else {
                    &control
                };
                format!(
                    "auth {control} {} config={} authdir={}{trust} {rest}",
                    pam_module().display(),
                    hooks_conf.display(),
                    auth_dir.display()
                )
            }
            "pam_deny.so" => format!("auth {control} {} {rest}", system_module("pam_deny.so")),
            other => panic!("unexpected module {other} in a packaged stack"),
        };
        lines.push(line);
    }
    lines.join("\n") + "\n"
}

fn system_module(name: &str) -> String {
    [
        "/usr/lib64/security",
        "/lib64/security",
        "/usr/lib/security",
        "/usr/lib/x86_64-linux-gnu/security",
    ]
    .into_iter()
    .map(|dir| Path::new(dir).join(name))
    .find(|p| p.exists())
    .unwrap_or_else(|| panic!("{name} not found: install the PAM modules to run the PAM tests"))
    .display()
    .to_string()
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
        format!("token_socket = {}\nbus_address = {bus}\n", token.display()),
    )
    .unwrap();
    let services = fixture.dir.path().join("services");
    std::fs::create_dir_all(&services).unwrap();
    let stack_text = service_text(stack, &hooks_conf, &fixture.config.auth_dir, &etc);
    let recorder = format!(
        "auth required {} path={}\n",
        fixture.recorder.display(),
        fixture.dir.path().join("reached").display()
    );
    let service = if let Some(name) = stack.direct {
        std::fs::write(services.join(name), stack_text + &recorder).unwrap();
        name
    } else {
        std::fs::write(services.join(INCLUDED), stack_text).unwrap();
        std::fs::write(
            services.join(SERVICE),
            format!("auth include {INCLUDED}\n{recorder}"),
        )
        .unwrap();
        SERVICE
    };
    let reached_file = fixture.dir.path().join("reached");
    let _ = std::fs::remove_file(&reached_file);
    set_verify(stack.verify, 0);

    let lib64 = rig.prefix.join("usr/lib64");
    let started = Instant::now();
    let mut client = Command::new(&fixture.client);
    if let Some(host) = stack.rhost {
        client.env("PAMTEST_RHOST", host);
    }
    if stack.interrupt_after.is_some() {
        client.env("PAMTEST_CATCH_SIGINT", "1");
    }
    if stack.block_sigint {
        client.env("PAMTEST_BLOCK_SIGINT", "1");
    }
    let child = client
        .args([
            service,
            &stack
                .user
                .map(str::to_string)
                .unwrap_or_else(|| linux_user_name(uid()).unwrap()),
        ])
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the compiled PAM client must run");
    if let Some(after) = stack.interrupt_after {
        let pid = child.id() as libc::pid_t;
        std::thread::spawn(move || {
            std::thread::sleep(after);
            unsafe { libc::kill(pid, libc::SIGINT) };
        });
    }
    let output = child
        .wait_with_output()
        .expect("the compiled PAM client must finish");
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
        sigint_seen: stdout.lines().any(|l| l == "SIGINT 1"),
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
        assert!(outcome.showed_no_message());
        assert_eq!(outcome.verify_calls, 1);
        assert_eq!(rig.lockout_counter(), before);
    });
}

// @spec:AC-029
#[test]
fn a_different_face_or_another_key_in_the_public_key_file_is_not_accepted_and_the_stack_continues()
{
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);

        let other_face = scenario(
            &rig,
            fixture,
            &services,
            Stack::face(Verify::NoMatch).lenient(),
        );
        assert!(!other_face.granted());
        assert_eq!(other_face.reached, ["authtok=unset"]);
        assert_eq!(other_face.verify_calls, 1);
        assert_eq!(other_face.password_prompts(), 0);
        let refused = scenario(&rig, fixture, &services, Stack::face(Verify::NoMatch));
        assert!(
            refused.refused_outright(),
            "a wrong face is a denial, not an ignore"
        );

        let genuine = PublicKeyFile::replace_with_key(fixture, 7);
        let other_key = scenario(
            &rig,
            fixture,
            &services,
            Stack::face(Verify::Matches).lenient(),
        );
        let strict = scenario(&rig, fixture, &services, Stack::face(Verify::Matches));
        drop(genuine);
        assert!(
            !other_key.granted(),
            "a public key that is not the token's must fail the signed challenge"
        );
        assert_eq!(other_key.reached, ["authtok=unset"]);
        assert_eq!(other_key.verify_calls, 1);
        assert!(strict.refused_outright());

        let again = scenario(&rig, fixture, &services, Stack::face(Verify::Matches));
        assert!(again.granted(), "the genuine public key works again");
    });
}

// @spec:AC-030
#[test]
fn a_missing_keyd_or_openhellod_falls_through_within_five_seconds() {
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
            assert!(outcome.showed_no_message());
            assert!(outcome.elapsed < WITHIN_BUDGET, "{:?}", outcome.elapsed);
        }
    });
}

// @spec:AC-041
#[test]
fn the_module_waits_for_the_daemon_attempt_budget_and_gives_up_only_within_its_own_budget() {
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);

        let slow = scenario(&rig, fixture, &services, Stack::face(Verify::Slow));
        assert!(
            slow.granted(),
            "a verdict inside the attempt budget must be waited for"
        );
        assert!(slow.elapsed >= SLOW_VERIFY && slow.elapsed < MODULE_BUDGET);
        assert!(slow.reached.is_empty() && slow.password_prompts() == 0);

        let silent = scenario(&rig, fixture, &services, Stack::face(Verify::Hangs));
        assert!(!silent.granted());
        assert_eq!(silent.reached, ["authtok=unset"]);
        assert_eq!(silent.verify_calls, 1);
        assert!(silent.showed_no_message());
        assert!(
            silent.elapsed >= openhello_auth_proto::FACE_ATTEMPT_BUDGET + openhello_auth_proto::FACE_DECISION_BUDGET,
            "the module gave up before the daemon's budget: {:?}",
            silent.elapsed
        );
        assert!(
            silent.elapsed < MODULE_BUDGET,
            "the camera wait took {:?}",
            silent.elapsed
        );
    });
}

// @covers:AC-030-no-credential
#[test]
fn a_user_without_a_registered_public_key_is_ignored_silently_before_any_message_or_socket() {
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);

        let unknown_user = scenario(
            &rig,
            fixture,
            &services,
            Stack {
                user: Some("nobody-enrolled"),
                ..Stack::face(Verify::Matches)
            },
        );
        let no_key_file = scenario(
            &rig,
            fixture,
            &services,
            Stack {
                user: Some("root"),
                ..Stack::face(Verify::Matches)
            },
        );
        for stranger in [&unknown_user, &no_key_file] {
            assert!(!stranger.granted());
            assert_eq!(stranger.reached, ["authtok=unset"]);
            assert!(stranger.prompts.is_empty(), "{:?}", stranger.prompts);
            assert_eq!(stranger.verify_calls, 0);
        }

        let enrolled = scenario(&rig, fixture, &services, Stack::face(Verify::Matches));
        assert!(enrolled.granted());
    });
}

// @covers:AC-030-untrusted-public-key
#[test]
fn a_public_key_file_not_owned_by_root_or_tampered_with_is_ignored_before_the_camera() {
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);

        let not_root = scenario(
            &rig,
            fixture,
            &services,
            Stack {
                root_owned_keys_only: true,
                ..Stack::face(Verify::Matches)
            },
        );
        let genuine = PublicKeyFile::corrupt(fixture);
        let tampered = scenario(&rig, fixture, &services, Stack::face(Verify::Matches));
        drop(genuine);
        for ignored in [&not_root, &tampered] {
            assert!(!ignored.granted());
            assert_eq!(ignored.reached, ["authtok=unset"]);
            assert!(ignored.prompts.is_empty(), "{:?}", ignored.prompts);
            assert_eq!(ignored.verify_calls, 0, "the camera must not be touched");
        }

        let restored = scenario(&rig, fixture, &services, Stack::face(Verify::Matches));
        assert!(restored.granted());
    });
}

// @covers:AC-029-signature-binding
#[test]
fn a_valid_signature_of_another_challenge_or_service_or_session_is_not_accepted() {
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);
        let relay = TokenRelay::start(&services.token_path);
        let through = |mode: Relay| {
            relay.set(mode);
            scenario(
                &rig,
                fixture,
                &services,
                Stack {
                    token_socket: Some(relay.path.clone()),
                    ..Stack::face(Verify::Matches)
                },
            )
        };

        let relayed = through(Relay::Pass);
        assert!(relayed.granted(), "the relay alone must not break signing");
        for forged in [
            through(Relay::Replay),
            through(Relay::OtherService("su")),
            through(Relay::FlippedChallenge),
        ] {
            assert!(
                forged.refused_outright(),
                "{:?} {:?}",
                forged.result,
                forged.reached
            );
            assert_eq!(forged.verify_calls, 1);
        }
        assert!(through(Relay::Pass).granted());
    });
}

// @covers:AC-029-no-grant
#[test]
fn a_face_match_without_a_grant_at_keyd_is_refused_even_if_openhellod_says_yes() {
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);

        let outcome = scenario(&rig, fixture, &services, Stack::face(Verify::NoTicket));

        assert!(outcome.refused_outright(), "{:?}", outcome.reached);
        assert_eq!(outcome.verify_calls, 1);
    });
}

// @covers:AC-028-pam-local-session
#[test]
fn the_built_module_declares_libpam_as_a_needed_library() {
    let dynamic = run_tool("readelf", &["-d", pam_module().to_str().unwrap()]);
    assert!(
        dynamic
            .lines()
            .any(|l| l.contains("(NEEDED)") && l.contains("[libpam.so.0]")),
        "libpam.so.0 missing from NEEDED:\n{dynamic}"
    );
}

// @spec:AC-028
#[test]
fn a_local_interactive_service_authenticates_a_face_without_privilege_and_falls_back_on_a_miss() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run as the regular user: an interactive service runs unprivileged"
    );
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);

        let granted = scenario(
            &rig,
            fixture,
            &services,
            Stack::interactive(Verify::Matches),
        );
        assert!(granted.granted(), "{:?}", granted.prompts);
        assert!(granted.reached.is_empty() && granted.password_prompts() == 0);
        assert!(granted.showed_no_message());
        assert_eq!(granted.verify_calls, 1);

        let miss = scenario(
            &rig,
            fixture,
            &services,
            Stack::interactive(Verify::NoMatch).lenient(),
        );
        assert!(!miss.granted());
        assert_eq!(miss.reached, ["authtok=unset"]);
        assert_eq!(miss.password_prompts(), 0, "{:?}", miss.prompts);

        let no_keyd = scenario(
            &rig,
            fixture,
            &services,
            Stack {
                token_socket: Some(fixture.dir.path().join("absent.sock")),
                ..Stack::interactive(Verify::Matches)
            },
        );
        assert!(!no_keyd.granted());
        assert_eq!(no_keyd.reached, ["authtok=unset"]);
        assert_eq!(no_keyd.verify_calls, 0);
        assert!(no_keyd.elapsed < WITHIN_BUDGET, "{:?}", no_keyd.elapsed);
    });
}

// @covers:AC-028-pam-path
#[test]
fn the_common_stack_placement_acts_on_local_services_and_ignores_the_denylist_remote_and_root() {
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);

        for service in ["sudo", "polkit-1", INTERACTIVE_SERVICE] {
            let acted = scenario(
                &rig,
                fixture,
                &services,
                Stack::common(Verify::Matches, service),
            );
            assert!(acted.granted(), "{service}: {:?}", acted.prompts);
            assert_eq!(acted.verify_calls, 1, "{service}");
            assert!(acted.showed_no_message(), "{service}");
        }

        let mut ignored = Vec::new();
        for service in DENIED_SERVICES {
            ignored.push((
                service,
                scenario(
                    &rig,
                    fixture,
                    &services,
                    Stack::common(Verify::Matches, service),
                ),
            ));
        }
        ignored.push((
            "remote",
            scenario(
                &rig,
                fixture,
                &services,
                Stack {
                    rhost: Some("203.0.113.9"),
                    ..Stack::common(Verify::Matches, "sudo")
                },
            ),
        ));
        ignored.push((
            "root",
            scenario(
                &rig,
                fixture,
                &services,
                Stack {
                    user: Some("root"),
                    ..Stack::common(Verify::Matches, "sudo")
                },
            ),
        ));
        for (label, outcome) in &ignored {
            assert!(!outcome.granted(), "{label}");
            assert!(
                !outcome.reached.is_empty() && outcome.reached.iter().all(|r| r == "authtok=unset"),
                "{label}: {:?}",
                outcome.reached
            );
            assert_eq!(
                outcome.verify_calls, 0,
                "{label}: the camera must not be touched"
            );
            assert!(outcome.showed_no_message(), "{label}");
            assert!(
                outcome.elapsed < WITHIN_BUDGET,
                "{label}: {:?}",
                outcome.elapsed
            );
        }
    });
}

struct PublicKeyFile {
    path: PathBuf,
    genuine: String,
}

impl PublicKeyFile {
    fn replace_with_key(fixture: &Fixture, seed: u8) -> Self {
        let key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        Self::overwrite(
            fixture,
            &openhello_auth_proto::encode_public_key(point.as_bytes()).unwrap(),
        )
    }

    fn corrupt(fixture: &Fixture) -> Self {
        let path = fixture.public_key_file();
        let mut text = std::fs::read_to_string(&path).unwrap();
        let last = text.trim_end().len() - 1;
        let flipped = if text.as_bytes()[last] == b'0' {
            "1"
        } else {
            "0"
        };
        text.replace_range(last..=last, flipped);
        Self::overwrite(fixture, &text)
    }

    fn overwrite(fixture: &Fixture, text: &str) -> Self {
        let path = fixture.public_key_file();
        let genuine = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text).unwrap();
        Self { path, genuine }
    }
}

impl Drop for PublicKeyFile {
    fn drop(&mut self) {
        std::fs::write(&self.path, &self.genuine).unwrap();
    }
}

#[derive(Clone)]
enum Relay {
    Pass,
    Replay,
    OtherService(&'static str),
    FlippedChallenge,
}

struct TokenRelay {
    path: PathBuf,
    mode: Arc<Mutex<Relay>>,
    _dir: tempfile::TempDir,
}

impl TokenRelay {
    fn start(keyd: &Path) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let mode = Arc::new(Mutex::new(Relay::Pass));
        let recorded = Arc::new(Mutex::new(None::<Vec<u8>>));
        let (keyd, shared_mode) = (keyd.to_path_buf(), mode.clone());
        std::thread::spawn(move || {
            for client in listener.incoming().flatten() {
                relay_connection(client, &keyd, &shared_mode, &recorded);
            }
        });
        Self {
            path,
            mode,
            _dir: dir,
        }
    }

    fn set(&self, mode: Relay) {
        *self.mode.lock().unwrap_or_else(PoisonError::into_inner) = mode;
    }
}

fn relay_connection(
    mut client: UnixStream,
    keyd: &Path,
    mode: &Mutex<Relay>,
    recorded: &Mutex<Option<Vec<u8>>>,
) {
    let Ok(mut upstream) = UnixStream::connect(keyd) else {
        return;
    };
    while let Some((op, mut payload)) = read_frame(&mut client) {
        let mode = mode.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if op == AUTH_OP {
            mutate(&mode, &mut payload);
        }
        if write_frame(&mut upstream, op, &payload).is_err() {
            return;
        }
        let Some((status, mut body)) = read_frame(&mut upstream) else {
            return;
        };
        if op == AUTH_OP && status == 0 {
            let mut recorded = recorded.lock().unwrap_or_else(PoisonError::into_inner);
            match (&mode, recorded.as_ref()) {
                (Relay::Replay, Some(old)) => body = old.clone(),
                _ => *recorded = Some(body.clone()),
            }
        }
        if write_frame(&mut client, status, &body).is_err() {
            return;
        }
    }
}

fn mutate(mode: &Relay, payload: &mut Vec<u8>) {
    match mode {
        Relay::OtherService(service) => {
            let challenge: [u8; 32] = payload[payload.len() - 32..].try_into().unwrap();
            *payload = openhello_auth_proto::request_payload(service, &challenge).unwrap();
        }
        Relay::FlippedChallenge => *payload.last_mut().unwrap() ^= 1,
        Relay::Pass | Relay::Replay => {}
    }
}

fn read_frame(stream: &mut UnixStream) -> Option<(u8, Vec<u8>)> {
    let mut header = [0u8; 3];
    stream.read_exact(&mut header).ok()?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes([header[1], header[2]]))];
    stream.read_exact(&mut body).ok()?;
    Some((header[0], body))
}

fn write_frame(stream: &mut UnixStream, tag: u8, body: &[u8]) -> std::io::Result<()> {
    let mut frame = vec![tag];
    frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
    frame.extend_from_slice(body);
    stream.write_all(&frame)
}

// @spec:AC-041
#[test]
fn an_interrupt_while_the_camera_waits_ends_the_module_at_once_and_hands_the_signal_back_to_the_caller() {
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);

        let interrupted = scenario(
            &rig,
            fixture,
            &services,
            Stack::face(Verify::Hangs).interrupted_after(Duration::from_secs(1)),
        );
        assert!(!interrupted.granted());
        assert_eq!(interrupted.verify_calls, 1);
        assert!(
            interrupted.elapsed < Duration::from_secs(5),
            "the interrupt waited for the camera: {:?}",
            interrupted.elapsed
        );
        assert!(interrupted.sigint_seen, "the caller never saw its SIGINT");
        assert!(interrupted.showed_no_message());

        let blocked = scenario(
            &rig,
            fixture,
            &services,
            Stack::face(Verify::Hangs)
                .interrupted_after(Duration::from_secs(1))
                .blocking_sigint(),
        );
        assert!(
            blocked.elapsed < Duration::from_secs(5),
            "a signal the caller blocks was not served: {:?}",
            blocked.elapsed
        );
        assert!(blocked.sigint_seen, "the caller never saw its SIGINT");
    });
}

#[test]
fn a_face_already_decided_for_this_process_falls_through_to_the_password_without_a_message() {
    let rig = rig();
    with_fixture(&rig, |fixture| {
        let services = services(&rig, fixture);
        let outcome = scenario(&rig, fixture, &services, Stack::face(Verify::AlreadyDecided));
        assert!(!outcome.granted());
        assert_eq!(outcome.reached, ["authtok=unset"]);
        assert_eq!(outcome.verify_calls, 1);
        assert!(outcome.showed_no_message());
        assert!(outcome.elapsed < WITHIN_BUDGET, "{:?}", outcome.elapsed);
    });
}
