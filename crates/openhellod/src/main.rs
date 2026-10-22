use std::process::ExitCode;
use std::sync::Arc;

use openhellod::config::{AuthMode, BusKind, Config};
use openhellod::core::Biometrics;
use openhellod::fingerprint::{FprintdBus, FprintdEnroller, FprintdMatcher};
use openhellod::keyd_client::KeydClient;
use openhellod::logging::Logger;
use openhellod::dbus_service::{Authorizer, RootOnlyAuthorizer, Service, BUS_NAME, OBJECT_PATH};
use openhellod::plugin_loader::{EnginePlugin, SensorPlugin, StoragePlugin};
use openhellod::polkit::{DbusPolkit, PolkitAuthorizer};
use openhellod::ticket_client::TicketClient;

const USAGE: &str = "usage: openhellod --sensor-lib PATH --engine-lib PATH --storage-lib PATH --device /dev/videoN \
--state-dir DIR --engine-config FILE.json [--bus system|session] [--auth polkit|root-only] [--log-level error|warn|info|debug|trace] [--target-far 1e-5]";

fn run(config: Config) -> Result<(), String> {
    let engine_json = std::fs::read_to_string(&config.engine_config)
        .map_err(|e| format!("cannot read engine config {}: {e}", config.engine_config.display()))?;
    let state_dir = config.state_dir.to_str().ok_or("--state-dir must be valid UTF-8")?;
    let sensor = SensorPlugin::load(&config.sensor_lib, &config.device).map_err(|e| e.to_string())?;
    let engine = EnginePlugin::load(&config.engine_lib, &engine_json).map_err(|e| e.to_string())?;
    let storage = StoragePlugin::load(&config.storage_lib, state_dir).map_err(|e| e.to_string())?;
    let core = Biometrics::new(Box::new(sensor), Box::new(engine), Box::new(storage), config.target_far)
        .with_logger(Logger::stderr(config.log_level))
        .with_ticket_client(TicketClient::from_env())
        .with_keyd_client(KeydClient::from_env())
        .with_fingerprint(Some(Box::new(FprintdMatcher::new(FprintdBus::System, Logger::stderr(config.log_level)))));
    let authorizer: Arc<dyn Authorizer> = match config.auth {
        AuthMode::Polkit => Arc::new(PolkitAuthorizer::new(Arc::new(DbusPolkit))),
        AuthMode::RootOnly => Arc::new(RootOnlyAuthorizer),
    };
    let service = Service::new(core, authorizer)
        .with_finger_enroller(Arc::new(FprintdEnroller::new(FprintdBus::System, Logger::stderr(config.log_level))));

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
        std::future::pending::<()>().await;
        Ok(())
    })
}

const TARGET_FAR_ENV: &str = "OPENHELLO_TARGET_FAR";

fn command_line() -> Vec<String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if let Ok(far) = std::env::var(TARGET_FAR_ENV) {
        if !args.iter().any(|a| a == "--target-far") {
            args.extend(["--target-far".to_string(), far]);
        }
    }
    args
}

fn main() -> ExitCode {
    let config = match Config::parse(command_line()) {
        Ok(config) => config,
        Err(problem) => {
            eprintln!("openhellod: {problem}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => {
            eprintln!("openhellod: {problem}");
            ExitCode::FAILURE
        }
    }
}
