use std::fmt::Write as _;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "error" => Some(Level::Error),
            "warn" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" => Some(Level::Debug),
            "trace" => Some(Level::Trace),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uid(u32),
    Count(u64),
    Label(&'static str),
    Reason(String),
}

impl Value {
    fn render(&self, out: &mut String) {
        match self {
            Value::Uid(v) => write!(out, "{v}"),
            Value::Count(v) => write!(out, "{v}"),
            Value::Label(v) => write!(out, "{v}"),
            Value::Reason(v) => write!(out, "{:?}", v.replace(['\n', '\r'], " ")),
        }
        .expect("writing to a String cannot fail");
    }
}

pub trait LogSink: Send + Sync {
    fn write_line(&self, line: &str);
}

struct StderrSink;

impl LogSink for StderrSink {
    fn write_line(&self, line: &str) {
        eprintln!("{line}");
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static SINK: Mutex<Option<Arc<dyn LogSink>>> = Mutex::new(None);

pub fn configure(level: Level, sink: Arc<dyn LogSink>) {
    LEVEL.store(level as u8, Ordering::SeqCst);
    *SINK.lock().unwrap_or_else(PoisonError::into_inner) = Some(sink);
}

pub fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::SeqCst);
}

pub fn log(level: Level, event: &'static str, fields: &[(&'static str, Value)]) {
    if level as u8 > LEVEL.load(Ordering::SeqCst) {
        return;
    }
    let mut line = format!("openhello-keyd {} {event}", level.label());
    for (name, value) in fields {
        line.push(' ');
        line.push_str(name);
        line.push('=');
        value.render(&mut line);
    }
    let sink = SINK.lock().unwrap_or_else(PoisonError::into_inner).clone();
    match sink {
        Some(sink) => sink.write_line(&line),
        None => StderrSink.write_line(&line),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_parse_and_order() {
        assert_eq!(Level::parse("trace"), Some(Level::Trace));
        assert_eq!(Level::parse("loud"), None);
        assert!(Level::Trace > Level::Error);
    }

    #[test]
    fn reasons_stay_on_one_line() {
        let mut out = String::new();
        Value::Reason("bad\nthing".into()).render(&mut out);
        assert_eq!(out, "\"bad thing\"");
    }
}
