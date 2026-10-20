use std::path::PathBuf;

use crate::core::DEFAULT_TARGET_FAR;
use crate::logging::Level;

#[derive(Debug, PartialEq)]
pub enum AuthMode {
    Polkit,
    RootOnly,
}

#[derive(Debug, PartialEq)]
pub enum BusKind {
    System,
    Session,
}

#[derive(Debug)]
pub struct Config {
    pub sensor_lib: PathBuf,
    pub engine_lib: PathBuf,
    pub storage_lib: PathBuf,
    pub device: String,
    pub state_dir: PathBuf,
    pub engine_config: PathBuf,
    pub bus: BusKind,
    pub auth: AuthMode,
    pub log_level: Level,
    pub target_far: f64,
}

impl Config {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut values = std::collections::HashMap::new();
        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            let name = flag.strip_prefix("--").ok_or_else(|| format!("unexpected argument `{flag}`"))?.to_string();
            let value = args.next().ok_or_else(|| format!("--{name} needs a value"))?;
            values.insert(name, value);
        }
        let mut take = |name: &str| values.remove(name).ok_or_else(|| format!("--{name} is required"));
        let sensor_lib = PathBuf::from(take("sensor-lib")?);
        let engine_lib = PathBuf::from(take("engine-lib")?);
        let storage_lib = PathBuf::from(take("storage-lib")?);
        let device = take("device")?;
        let state_dir = PathBuf::from(take("state-dir")?);
        let engine_config = PathBuf::from(take("engine-config")?);
        let bus = match values.remove("bus").as_deref() {
            None | Some("system") => BusKind::System,
            Some("session") => BusKind::Session,
            Some(other) => return Err(format!("--bus must be `system` or `session`, got `{other}`")),
        };
        let auth = match values.remove("auth").as_deref() {
            None | Some("polkit") => AuthMode::Polkit,
            Some("root-only") => AuthMode::RootOnly,
            Some(other) => return Err(format!("--auth must be `polkit` or `root-only`, got `{other}`")),
        };
        let log_level = match values.remove("log-level") {
            None => Level::Info,
            Some(text) => Level::parse(&text).ok_or_else(|| format!("--log-level must be error|warn|info|debug|trace, got `{text}`"))?,
        };
        let target_far = match values.remove("target-far") {
            None => DEFAULT_TARGET_FAR,
            Some(text) => text.parse::<f64>().map_err(|_| format!("--target-far must be a number in (0, 1), got `{text}`"))?,
        };
        if !(target_far > 0.0 && target_far < 1.0) {
            return Err(format!("--target-far must be in (0, 1), got {target_far}"));
        }
        if let Some(unknown) = values.keys().next() {
            return Err(format!("unknown option --{unknown}"));
        }
        for (label, path) in [("sensor-lib", &sensor_lib), ("engine-lib", &engine_lib), ("storage-lib", &storage_lib), ("engine-config", &engine_config)] {
            if !path.is_file() {
                return Err(format!("--{label} {} is not a file", path.display()));
            }
        }
        Ok(Self { sensor_lib, engine_lib, storage_lib, device, state_dir, engine_config, bus, auth, log_level, target_far })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str], dir: &std::path::Path) -> Vec<String> {
        let file = dir.join("f");
        std::fs::write(&file, "x").unwrap();
        let f = file.to_str().unwrap();
        let mut all = vec!["--sensor-lib", f, "--engine-lib", f, "--storage-lib", f, "--device", "/dev/video2", "--state-dir", "/tmp/s", "--engine-config", f];
        all.extend_from_slice(extra);
        all.into_iter().map(String::from).collect()
    }

    #[test]
    fn parses_a_complete_command_line_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::parse(args(&[], dir.path())).unwrap();
        assert_eq!(config.bus, BusKind::System);
        assert_eq!(config.auth, AuthMode::Polkit);
        assert_eq!(config.target_far, DEFAULT_TARGET_FAR);
        assert_eq!(config.device, "/dev/video2");
    }

    #[test]
    fn rejects_invalid_values_with_context() {
        let dir = tempfile::tempdir().unwrap();
        for (extra, needle) in [
            (vec!["--bus", "mars"], "--bus"),
            (vec!["--auth", "none"], "--auth"),
            (vec!["--log-level", "loud"], "--log-level"),
            (vec!["--target-far", "2"], "--target-far"),
            (vec!["--target-far", "abc"], "--target-far"),
            (vec!["--bogus", "1"], "--bogus"),
        ] {
            let error = Config::parse(args(&extra, dir.path())).unwrap_err();
            assert!(error.contains(needle), "{error}");
        }
        assert!(Config::parse(Vec::<String>::new()).unwrap_err().contains("is required"));
        let mut missing_file = args(&[], dir.path());
        missing_file[1] = "/nonexistent/lib.so".into();
        assert!(Config::parse(missing_file).unwrap_err().contains("not a file"));
    }
}
