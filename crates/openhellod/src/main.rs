use std::process::ExitCode;
use std::sync::Arc;

use openhellod::config::{BusKind, Config};
use openhellod::core::Biometrics;
use openhellod::dbus_service::{RootOnlyAuthorizer, Service, BUS_NAME, OBJECT_PATH};
use openhellod::plugin_loader::{EnginePlugin, SensorPlugin, StoragePlugin};

const USAGE: &str = "usage: openhellod --sensor-lib PATH --engine-lib PATH --storage-lib PATH --device /dev/videoN \
--state-dir DIR --engine-config FILE.json [--bus system|session] [--target-far 1e-5]";

fn run(config: Config) -> Result<(), String> {
    let engine_json = std::fs::read_to_string(&config.engine_config)
        .map_err(|e| format!("cannot read engine config {}: {e}", config.engine_config.display()))?;
    let state_dir = config.state_dir.to_str().ok_or("--state-dir must be valid UTF-8")?;
    let sensor = SensorPlugin::load(&config.sensor_lib, &config.device).map_err(|e| e.to_string())?;
    let engine = EnginePlugin::load(&config.engine_lib, &engine_json).map_err(|e| e.to_string())?;
    let storage = StoragePlugin::load(&config.storage_lib, state_dir).map_err(|e| e.to_string())?;
    let core = Biometrics::new(Box::new(sensor), Box::new(engine), Box::new(storage), config.target_far);
    let service = Service::new(core, Arc::new(RootOnlyAuthorizer));

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

fn main() -> ExitCode {
    let config = match Config::parse(std::env::args().skip(1)) {
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
