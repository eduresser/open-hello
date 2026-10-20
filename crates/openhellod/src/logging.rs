use std::fmt::Write as _;
use std::sync::Arc;

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
    Flag(bool),
    Label(&'static str),
    Reason(String),
}

impl Value {
    pub fn reason(error: &crate::backends::DaemonError) -> Self {
        Value::Reason(error.to_string())
    }

    fn render(&self, out: &mut String) {
        match self {
            Value::Uid(v) => write!(out, "{v}"),
            Value::Count(v) => write!(out, "{v}"),
            Value::Flag(v) => write!(out, "{v}"),
            Value::Label(v) => write!(out, "{v}"),
            Value::Reason(v) => write!(out, "{:?}", v.replace(['\n', '\r'], " ")),
        }
        .expect("writing to a String cannot fail");
    }
}

pub trait LogSink: Send + Sync {
    fn write_line(&self, line: &str);
}

pub struct StderrSink;

impl LogSink for StderrSink {
    fn write_line(&self, line: &str) {
        eprintln!("{line}");
    }
}

#[derive(Clone)]
pub struct Logger {
    level: Level,
    sink: Arc<dyn LogSink>,
}

impl Logger {
    pub fn new(level: Level, sink: Arc<dyn LogSink>) -> Self {
        Self { level, sink }
    }

    pub fn stderr(level: Level) -> Self {
        Self::new(level, Arc::new(StderrSink))
    }

    pub fn log(&self, level: Level, event: &'static str, fields: &[(&'static str, Value)]) {
        if level > self.level {
            return;
        }
        let mut line = format!("openhellod {} {event}", level.label());
        for (name, value) in fields {
            line.push(' ');
            line.push_str(name);
            line.push('=');
            value.render(&mut line);
        }
        self.sink.write_line(&line);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    pub(crate) struct CaptureSink(pub Mutex<Vec<String>>);

    impl LogSink for CaptureSink {
        fn write_line(&self, line: &str) {
            self.0.lock().unwrap().push(line.to_string());
        }
    }

    fn allowed(value: &Value) -> bool {
        match value {
            Value::Uid(_) | Value::Count(_) | Value::Flag(_) | Value::Label(_) | Value::Reason(_) => true,
        }
    }

    #[test]
    fn value_kinds_are_limited_to_scalars_and_labels() {
        assert!(allowed(&Value::Count(1)));
    }

    #[test]
    fn lines_carry_level_event_and_fields() {
        let sink = Arc::new(CaptureSink::default());
        let logger = Logger::new(Level::Info, sink.clone());
        logger.log(Level::Info, "verify", &[("uid", Value::Uid(1000)), ("accepted", Value::Flag(true)), ("verdict", Value::Label("accepted"))]);
        assert_eq!(*sink.0.lock().unwrap(), vec!["openhellod INFO verify uid=1000 accepted=true verdict=accepted"]);
    }

    #[test]
    fn verbosity_filters_and_reasons_stay_on_one_line() {
        let sink = Arc::new(CaptureSink::default());
        let logger = Logger::new(Level::Warn, sink.clone());
        logger.log(Level::Debug, "hidden", &[]);
        logger.log(Level::Error, "failed", &[("reason", Value::Reason("bad\nthing".into()))]);
        let lines = sink.0.lock().unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].ends_with("reason=\"bad thing\""));
    }

    #[test]
    fn levels_parse_and_order() {
        assert_eq!(Level::parse("trace"), Some(Level::Trace));
        assert_eq!(Level::parse("loud"), None);
        assert!(Level::Trace > Level::Error);
    }
}
