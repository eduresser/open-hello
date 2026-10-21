use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct SwTpm {
    child: Child,
    _state: tempfile::TempDir,
    pub tcti: String,
}

fn free_port_pair() -> (u16, u16) {
    loop {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = first.local_addr().unwrap().port();
        if port < u16::MAX && TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
            return (port, port + 1);
        }
    }
}

impl SwTpm {
    pub fn start() -> Self {
        let state = tempfile::tempdir().expect("swtpm state dir");
        let (server, control) = free_port_pair();
        let child = Command::new("swtpm")
            .args(["socket", "--tpm2", "--tpmstate"])
            .arg(format!("dir={}", state.path().display()))
            .arg("--server")
            .arg(format!("type=tcp,port={server}"))
            .arg("--ctrl")
            .arg(format!("type=tcp,port={control}"))
            .args(["--flags", "not-need-init,startup-clear"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("swtpm binary must be installed to run storage tests");
        let library = std::env::var("OPENHELLO_SWTPM_TCTI_LIB").unwrap_or_else(|_| "swtpm".into());
        let tpm = Self { child, _state: state, tcti: format!("{library}:port={server}") };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let probe = tpm.tpm2("tpm2_getcap", &["properties-fixed"]);
            if probe.status.success() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "swtpm never answered via TCTI `{}`: {}",
                tpm.tcti,
                String::from_utf8_lossy(&probe.stderr)
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        tpm
    }

    pub fn tpm2(&self, tool: &str, args: &[&str]) -> std::process::Output {
        Command::new(tool).args(args).env("TPM2TOOLS_TCTI", &self.tcti).output().expect("tpm2-tools must be installed")
    }
}

impl Drop for SwTpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
