use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use openhello_keyd::config::{AuthMode, BusKind, DaemonConfig};
use openhello_keyd::dbus_service::{
    Authorizer, RootOnlyAuthorizer, Service, BUS_NAME, OBJECT_PATH,
};
use openhello_keyd::polkit::{DbusPolkit, PolkitAuthorizer};
use openhello_keyd::{LockoutPolicy, Protectors, TicketSocket, TokenSocket, UnlockSocket};

const STOP_POLL: Duration = Duration::from_millis(200);

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn run(config: DaemonConfig) -> Result<(), String> {
    openhello_keyd::logging::set_level(config.log_level);
    let protectors = Arc::new(Protectors::new(config.keyd).map_err(|e| e.to_string())?);
    protectors
        .apply_lockout_policy(&LockoutPolicy::RECOMMENDED)
        .map_err(|e| format!("cannot apply the TPM lockout policy: {e}"))?;
    protectors.keyd().backfill_auth_keys();
    let _ticket_socket =
        TicketSocket::bind(protectors.clone(), config.ticket).map_err(|e| e.to_string())?;
    let _unlock_socket =
        UnlockSocket::bind(protectors.clone(), config.unlock).map_err(|e| e.to_string())?;
    let _token_socket =
        TokenSocket::bind(protectors.clone(), config.token).map_err(|e| e.to_string())?;
    let authorizer: Arc<dyn Authorizer> = match config.auth {
        AuthMode::Polkit => Arc::new(PolkitAuthorizer::new(Arc::new(DbusPolkit))),
        AuthMode::RootOnly => Arc::new(RootOnlyAuthorizer),
    };
    let service = Service::new(protectors, authorizer);

    unsafe {
        libc::signal(
            libc::SIGTERM,
            request_stop as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            request_stop as *const () as libc::sighandler_t,
        );
    }
    async_io::block_on(async {
        let builder = match config.bus {
            BusKind::System => zbus::connection::Builder::system(),
            BusKind::Session => zbus::connection::Builder::session(),
        };
        let _connection = builder
            .and_then(|b| b.name(BUS_NAME))
            .and_then(|b| b.serve_at(OBJECT_PATH, service))
            .map_err(|e| format!("cannot configure D-Bus: {e}"))?
            .build()
            .await
            .map_err(|e| format!("cannot claim {BUS_NAME}: {e}"))?;
        while !STOP.load(Ordering::SeqCst) {
            async_io::Timer::after(STOP_POLL).await;
        }
        Ok(())
    })
}

fn main() -> ExitCode {
    let config = match DaemonConfig::from_env() {
        Ok(config) => config,
        Err(problem) => {
            eprintln!("openhello-keyd: {problem}");
            return ExitCode::from(2);
        }
    };
    match run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => {
            eprintln!("openhello-keyd: {problem}");
            ExitCode::FAILURE
        }
    }
}
