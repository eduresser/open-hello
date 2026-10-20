use std::sync::{Arc, Mutex};

use openhellod::backends::*;
use openhellod::core::{Biometrics, DEFAULT_TARGET_FAR};
use openhellod::logging::{Level, LogSink, Logger};

const PIXELS: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
const TEMPLATE: &[u8] = b"TOP-SECRET-TEMPLATE-\xde\xad\xbe\xef\x01\x02\x03";

#[derive(Default)]
struct Capture(Mutex<Vec<String>>);

impl LogSink for Capture {
    fn write_line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }
}

struct Sensor;

impl SensorBackend for Sensor {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        Ok(CapturedFrame { width: 4, height: 2, pixels: PIXELS.to_vec() })
    }
}

struct Engine;

impl EngineBackend for Engine {
    fn enroll_begin(&mut self, _: u64) -> Result<u64, DaemonError> {
        Ok(1)
    }

    fn enroll_submit(&mut self, _: u64, _: u64, _: &CapturedFrame) -> Result<EnrollProgress, DaemonError> {
        Ok(EnrollProgress { verdict: Verdict::Accepted, state: EnrollState::Complete, filled: 6, required: 6 })
    }

    fn enroll_commit(&mut self, _: u64) -> Result<Vec<u8>, DaemonError> {
        Ok(TEMPLATE.to_vec())
    }

    fn enroll_discard(&mut self, _: u64) -> Result<(), DaemonError> {
        Ok(())
    }

    fn verify(&mut self, _: &[CapturedFrame], template: &[u8], _: f64) -> Result<MatchDecision, DaemonError> {
        Ok(MatchDecision { live: true, accepted: template == TEMPLATE })
    }

    fn identify(&mut self, _: &[CapturedFrame], candidates: &[(u32, Vec<u8>)], _: f64) -> Result<IdentifyDecision, DaemonError> {
        Ok(IdentifyDecision { live: true, matched_uid: candidates.first().map(|(uid, _)| *uid) })
    }
}

#[derive(Default)]
struct Storage(std::collections::BTreeMap<u32, Vec<u8>>);

impl StorageBackend for Storage {
    fn put(&mut self, uid: u32, template: &[u8]) -> Result<(), DaemonError> {
        self.0.insert(uid, template.to_vec());
        Ok(())
    }

    fn get(&mut self, uid: u32) -> Result<Vec<u8>, DaemonError> {
        self.0.get(&uid).cloned().ok_or(DaemonError::NotFound)
    }

    fn list_uids(&mut self) -> Result<Vec<u32>, DaemonError> {
        Ok(self.0.keys().copied().collect())
    }

    fn purge(&mut self, uid: u32) -> Result<(), DaemonError> {
        self.0.remove(&uid);
        Ok(())
    }
}

fn forbidden_renderings() -> Vec<String> {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let decimal = |bytes: &[u8]| bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ");
    vec![
        hex(&PIXELS),
        hex(&PIXELS).to_uppercase(),
        decimal(&PIXELS),
        decimal(&PIXELS[..4]),
        format!("{PIXELS:?}"),
        "TOP-SECRET".into(),
        hex(TEMPLATE),
        decimal(&TEMPLATE[TEMPLATE.len() - 4..]),
        format!("{:?}", TEMPLATE),
    ]
}

// @spec:AC-015
// @principle:P-010
#[test]
fn a_full_cycle_at_trace_verbosity_never_logs_frame_or_template_bytes() {
    let capture = Arc::new(Capture::default());
    let logger = Logger::new(Level::Trace, capture.clone());
    let mut core = Biometrics::new(Box::new(Sensor), Box::new(Engine), Box::new(Storage::default()), DEFAULT_TARGET_FAR).with_logger(logger);

    let handle = core.enroll_begin(1000).unwrap();
    core.enroll_capture(&handle).unwrap();
    core.enroll_commit(&handle).unwrap();
    assert!(core.verify(1000).unwrap());
    assert!(!core.verify(4242).unwrap());
    assert_eq!(core.identify().unwrap(), Some(1000));
    assert!(core.enroll_commit("enroll-unknown").is_err());
    core.purge(1000).unwrap();

    let lines = capture.0.lock().unwrap();
    for event in ["enroll-begin", "enroll-frame", "enroll-commit", "verify", "identify", "purge", "verify-template-unavailable"] {
        assert!(lines.iter().any(|l| l.contains(event)), "missing {event} in {lines:#?}");
    }
    for rendering in forbidden_renderings() {
        assert!(!lines.iter().any(|l| l.contains(&rendering)), "log leaked `{rendering}`:\n{lines:#?}");
    }
}
