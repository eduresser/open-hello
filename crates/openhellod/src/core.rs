use std::collections::HashMap;
use std::time::Instant;

use crate::backends::{
    DaemonError, EngineBackend, EnrollProgress, EnrollState, SensorBackend, StorageBackend,
};
use crate::logging::{Level, Logger, Value};

pub const BURST_FRAMES: usize = 10;
pub const DEFAULT_TARGET_FAR: f64 = 1e-5;

struct EnrollSession {
    uid: u32,
    engine_session: u64,
}

pub struct Biometrics {
    sensor: Box<dyn SensorBackend>,
    engine: Box<dyn EngineBackend>,
    storage: Box<dyn StorageBackend>,
    sessions: HashMap<String, EnrollSession>,
    next_session: u64,
    started: Instant,
    target_far: f64,
    logger: Logger,
}

impl Biometrics {
    pub fn new(
        sensor: Box<dyn SensorBackend>,
        engine: Box<dyn EngineBackend>,
        storage: Box<dyn StorageBackend>,
        target_far: f64,
    ) -> Self {
        Self { sensor, engine, storage, sessions: HashMap::new(), next_session: 1, started: Instant::now(), target_far, logger: Logger::stderr(Level::Info) }
    }

    pub fn with_logger(mut self, logger: Logger) -> Self {
        self.logger = logger;
        self
    }

    pub fn logger(&self) -> &Logger {
        &self.logger
    }

    pub fn enroll_begin(&mut self, uid: u32) -> Result<String, DaemonError> {
        let engine_session = self.engine.enroll_begin(self.now_ms())?;
        let handle = format!("enroll-{}", self.next_session);
        self.next_session += 1;
        self.sessions.insert(handle.clone(), EnrollSession { uid, engine_session });
        self.logger.log(Level::Info, "enroll-begin", &[("uid", Value::Uid(uid))]);
        Ok(handle)
    }

    pub fn enroll_capture(&mut self, handle: &str) -> Result<EnrollProgress, DaemonError> {
        let engine_session = self.session(handle)?.engine_session;
        let frame = self.sensor.capture()?;
        let progress = self.engine.enroll_submit(engine_session, self.now_ms(), &frame)?;
        self.logger.log(
            Level::Debug,
            "enroll-frame",
            &[
                ("verdict", Value::Label(progress.verdict.as_str())),
                ("filled", Value::Count(progress.filled.into())),
                ("required", Value::Count(progress.required.into())),
                ("width", Value::Count(frame.width.into())),
                ("height", Value::Count(frame.height.into())),
                ("frame_bytes", Value::Count(frame.pixels.len() as u64)),
            ],
        );
        if progress.state == EnrollState::Failed {
            self.sessions.remove(handle);
        }
        Ok(progress)
    }

    pub fn enroll_commit(&mut self, handle: &str) -> Result<(), DaemonError> {
        let EnrollSession { uid, engine_session } = self.take_session(handle)?;
        let template = self.engine.enroll_commit(engine_session)?;
        self.logger.log(Level::Debug, "enroll-commit", &[("uid", Value::Uid(uid)), ("template_bytes", Value::Count(template.len() as u64))]);
        self.storage.put(uid, &template)
    }

    pub fn enroll_discard(&mut self, handle: &str) -> Result<(), DaemonError> {
        let session = self.take_session(handle)?;
        self.engine.enroll_discard(session.engine_session)
    }

    pub fn session_uid(&self, handle: &str) -> Result<u32, DaemonError> {
        Ok(self.session(handle)?.uid)
    }

    pub fn verify(&mut self, uid: u32) -> Result<bool, DaemonError> {
        let template = match self.storage.get(uid) {
            Ok(template) => template,
            Err(error @ (DaemonError::NotFound | DaemonError::Tampered)) => {
                self.logger.log(Level::Warn, "verify-template-unavailable", &[("uid", Value::Uid(uid)), ("reason", Value::reason(&error))]);
                return Ok(false);
            }
            Err(other) => return Err(other),
        };
        let frames = self.capture_burst()?;
        let decision = self.engine.verify(&frames, &template, self.target_far)?;
        self.logger.log(
            Level::Info,
            "verify",
            &[("uid", Value::Uid(uid)), ("live", Value::Flag(decision.live)), ("accepted", Value::Flag(decision.accepted))],
        );
        Ok(decision.live && decision.accepted)
    }

    pub fn identify(&mut self) -> Result<Option<u32>, DaemonError> {
        let mut candidates = Vec::new();
        for uid in self.storage.list_uids()? {
            match self.storage.get(uid) {
                Ok(template) => candidates.push((uid, template)),
                Err(error @ (DaemonError::NotFound | DaemonError::Tampered)) => {
                    self.logger.log(Level::Warn, "identify-template-unavailable", &[("uid", Value::Uid(uid)), ("reason", Value::reason(&error))]);
                }
                Err(other) => return Err(other),
            }
        }
        if candidates.is_empty() {
            return Ok(None);
        }
        let frames = self.capture_burst()?;
        let decision = self.engine.identify(&frames, &candidates, self.target_far)?;
        self.logger.log(
            Level::Info,
            "identify",
            &[
                ("candidates", Value::Count(candidates.len() as u64)),
                ("live", Value::Flag(decision.live)),
                ("found", Value::Flag(decision.matched_uid.is_some())),
            ],
        );
        Ok(decision.matched_uid.filter(|_| decision.live))
    }

    pub fn purge(&mut self, uid: u32) -> Result<(), DaemonError> {
        self.storage.purge(uid)?;
        self.logger.log(Level::Info, "purge", &[("uid", Value::Uid(uid))]);
        Ok(())
    }

    fn capture_burst(&mut self) -> Result<Vec<crate::backends::CapturedFrame>, DaemonError> {
        (0..BURST_FRAMES).map(|_| self.sensor.capture()).collect()
    }

    fn session(&self, handle: &str) -> Result<&EnrollSession, DaemonError> {
        self.sessions
            .get(handle)
            .ok_or_else(|| DaemonError::InvalidRequest(format!("unknown enrollment session `{handle}`")))
    }

    fn take_session(&mut self, handle: &str) -> Result<EnrollSession, DaemonError> {
        self.sessions
            .remove(handle)
            .ok_or_else(|| DaemonError::InvalidRequest(format!("unknown enrollment session `{handle}`")))
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
}

#[cfg(test)]
pub(crate) mod fakes {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::backends::*;

    pub struct FakeSensor;

    impl SensorBackend for FakeSensor {
        fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
            Ok(CapturedFrame { width: 2, height: 2, pixels: vec![1, 2, 3, 4] })
        }
    }

    #[derive(Default)]
    pub struct EngineLog {
        pub verified_templates: Vec<Vec<u8>>,
        pub committed: Vec<u64>,
    }

    pub struct FakeEngine {
        pub log: Arc<Mutex<EngineLog>>,
        pub live: bool,
        pub accept_template: Vec<u8>,
        pub fail_state: bool,
    }

    impl EngineBackend for FakeEngine {
        fn enroll_begin(&mut self, _: u64) -> Result<u64, DaemonError> {
            Ok(77)
        }

        fn enroll_submit(&mut self, _: u64, _: u64, _: &CapturedFrame) -> Result<EnrollProgress, DaemonError> {
            let state = if self.fail_state { EnrollState::Failed } else { EnrollState::Complete };
            Ok(EnrollProgress { verdict: Verdict::Accepted, state, filled: 6, required: 6 })
        }

        fn enroll_commit(&mut self, session: u64) -> Result<Vec<u8>, DaemonError> {
            self.log.lock().unwrap().committed.push(session);
            Ok(self.accept_template.clone())
        }

        fn enroll_discard(&mut self, _: u64) -> Result<(), DaemonError> {
            Ok(())
        }

        fn verify(&mut self, frames: &[CapturedFrame], template: &[u8], _: f64) -> Result<MatchDecision, DaemonError> {
            assert_eq!(frames.len(), BURST_FRAMES);
            self.log.lock().unwrap().verified_templates.push(template.to_vec());
            Ok(MatchDecision { live: self.live, accepted: template == self.accept_template.as_slice() })
        }

        fn identify(&mut self, _: &[CapturedFrame], candidates: &[(u32, Vec<u8>)], _: f64) -> Result<IdentifyDecision, DaemonError> {
            let matched_uid = candidates.iter().find(|(_, t)| *t == self.accept_template).map(|(uid, _)| *uid);
            Ok(IdentifyDecision { live: self.live, matched_uid })
        }
    }

    #[derive(Clone, Default)]
    pub struct MemoryStorage {
        pub files: Arc<Mutex<BTreeMap<u32, Vec<u8>>>>,
        pub tampered: Arc<Mutex<Vec<u32>>>,
    }

    impl StorageBackend for MemoryStorage {
        fn put(&mut self, uid: u32, template: &[u8]) -> Result<(), DaemonError> {
            self.files.lock().unwrap().insert(uid, template.to_vec());
            Ok(())
        }

        fn get(&mut self, uid: u32) -> Result<Vec<u8>, DaemonError> {
            if self.tampered.lock().unwrap().contains(&uid) {
                return Err(DaemonError::Tampered);
            }
            self.files.lock().unwrap().get(&uid).cloned().ok_or(DaemonError::NotFound)
        }

        fn list_uids(&mut self) -> Result<Vec<u32>, DaemonError> {
            Ok(self.files.lock().unwrap().keys().copied().collect())
        }

        fn purge(&mut self, uid: u32) -> Result<(), DaemonError> {
            self.files.lock().unwrap().remove(&uid);
            Ok(())
        }
    }

    pub fn core_with(storage: MemoryStorage, live: bool, template: &[u8]) -> (Biometrics, Arc<Mutex<EngineLog>>) {
        let log = Arc::new(Mutex::new(EngineLog::default()));
        let engine = FakeEngine { log: log.clone(), live, accept_template: template.to_vec(), fail_state: false };
        (Biometrics::new(Box::new(FakeSensor), Box::new(engine), Box::new(storage), DEFAULT_TARGET_FAR), log)
    }
}

#[cfg(test)]
mod tests {
    use super::fakes::*;
    use super::*;

    #[test]
    fn enrollment_commit_persists_the_engine_template_for_the_session_uid() {
        let storage = MemoryStorage::default();
        let (mut core, log) = core_with(storage.clone(), true, b"tpl-1000");
        let handle = core.enroll_begin(1000).unwrap();
        assert_eq!(core.session_uid(&handle).unwrap(), 1000);
        assert_eq!(core.enroll_capture(&handle).unwrap().state, EnrollState::Complete);
        core.enroll_commit(&handle).unwrap();
        assert_eq!(storage.files.lock().unwrap().get(&1000).unwrap(), b"tpl-1000");
        assert_eq!(log.lock().unwrap().committed, vec![77]);
        assert!(core.enroll_commit(&handle).is_err());
    }

    #[test]
    fn discard_and_failed_sessions_invalidate_the_handle() {
        let (mut core, _) = core_with(MemoryStorage::default(), true, b"x");
        let handle = core.enroll_begin(1000).unwrap();
        core.enroll_discard(&handle).unwrap();
        assert!(matches!(core.enroll_capture(&handle), Err(DaemonError::InvalidRequest(_))));

        let engine = FakeEngine { log: Default::default(), live: true, accept_template: vec![], fail_state: true };
        let mut failing = Biometrics::new(Box::new(FakeSensor), Box::new(engine), Box::new(MemoryStorage::default()), DEFAULT_TARGET_FAR);
        let handle = failing.enroll_begin(1000).unwrap();
        assert_eq!(failing.enroll_capture(&handle).unwrap().state, EnrollState::Failed);
        assert!(failing.session_uid(&handle).is_err());
    }

    #[test]
    fn verify_accepts_matching_live_face_and_rejects_everything_else() {
        let storage = MemoryStorage::default();
        storage.files.lock().unwrap().insert(1000, b"mine".to_vec());
        storage.files.lock().unwrap().insert(1001, b"theirs".to_vec());
        let (mut core, _) = core_with(storage.clone(), true, b"mine");
        assert!(core.verify(1000).unwrap());
        assert!(!core.verify(1001).unwrap());
        assert!(!core.verify(4242).unwrap());

        let (mut spoofed, _) = core_with(storage, false, b"mine");
        assert!(!spoofed.verify(1000).unwrap());
    }

    #[test]
    fn verify_treats_tampered_templates_as_unavailable() {
        let storage = MemoryStorage::default();
        storage.files.lock().unwrap().insert(1000, b"mine".to_vec());
        storage.tampered.lock().unwrap().push(1000);
        let (mut core, log) = core_with(storage, true, b"mine");
        assert!(!core.verify(1000).unwrap());
        assert!(log.lock().unwrap().verified_templates.is_empty());
    }

    #[test]
    fn identify_resolves_one_uid_skipping_tampered_and_requires_liveness() {
        let storage = MemoryStorage::default();
        for (uid, tpl) in [(1000u32, b"a".to_vec()), (1001, b"b".to_vec()), (1002, b"c".to_vec())] {
            storage.files.lock().unwrap().insert(uid, tpl);
        }
        storage.tampered.lock().unwrap().push(1000);
        let (mut core, _) = core_with(storage.clone(), true, b"b");
        assert_eq!(core.identify().unwrap(), Some(1001));
        let (mut unknown, _) = core_with(storage.clone(), true, b"zzz");
        assert_eq!(unknown.identify().unwrap(), None);
        let (mut spoofed, _) = core_with(storage, false, b"b");
        assert_eq!(spoofed.identify().unwrap(), None);
        let (mut empty, _) = core_with(MemoryStorage::default(), true, b"b");
        assert_eq!(empty.identify().unwrap(), None);
    }

    #[test]
    fn purge_removes_the_users_stored_template() {
        let storage = MemoryStorage::default();
        storage.files.lock().unwrap().insert(1000, b"mine".to_vec());
        let (mut core, _) = core_with(storage.clone(), true, b"mine");
        core.purge(1000).unwrap();
        assert!(storage.files.lock().unwrap().is_empty());
    }
}
