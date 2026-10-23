use std::time::Instant;

pub trait SessionLog: Send {
    fn write_line(&self, line: &str);
}

pub struct StderrLog;

impl SessionLog for StderrLog {
    fn write_line(&self, line: &str) {
        eprintln!("{line}");
    }
}

pub fn line(event: &str, fields: &str) -> String {
    format!("sensor-adapter-ir INFO {event} {fields}")
}

pub fn quoted(text: &str) -> String {
    format!("{:?}", text.replace(['\n', '\r'], " "))
}

pub fn millis_between(earlier: Option<Instant>, now: Instant) -> String {
    earlier.map_or("none".into(), |at| now.saturating_duration_since(at).as_millis().to_string())
}
