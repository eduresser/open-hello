use std::collections::HashMap;
use std::time::Instant;

use crate::backends::{
    AuthVerdict, DaemonError, EngineBackend, EnrollProgress, EnrollState, SensorBackend, StorageBackend,
};
use crate::logging::{Level, Logger, Value};
use crate::ticket_client::{TicketClient, TicketDelivery};

pub const MAX_SCORED_FRAMES: u32 = 16;
pub const MAX_ATTEMPT_FRAMES: usize = 48;
pub const DEFAULT_TARGET_FAR: f64 = 1e-5;

struct AuthOutcome {
    uid: Option<u32>,
    frames: u32,
}

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
    tickets: Option<TicketClient>,
    last_delivery: Option<TicketDelivery>,
}

impl Biometrics {
    pub fn new(
        sensor: Box<dyn SensorBackend>,
        engine: Box<dyn EngineBackend>,
        storage: Box<dyn StorageBackend>,
        target_far: f64,
    ) -> Self {
        Self { sensor, engine, storage, sessions: HashMap::new(), next_session: 1, started: Instant::now(), target_far, logger: Logger::stderr(Level::Info), tickets: None, last_delivery: None }
    }

    pub fn with_logger(mut self, logger: Logger) -> Self {
        self.logger = logger;
        self
    }

    pub fn with_ticket_client(mut self, client: Option<TicketClient>) -> Self {
        self.tickets = client;
        self
    }

    pub fn last_ticket_delivery(&self) -> Option<TicketDelivery> {
        self.last_delivery
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
        let outcome = self.authenticate(&[(uid, template)])?;
        let accepted = outcome.uid == Some(uid);
        self.logger.log(
            Level::Info,
            "verify",
            &[("uid", Value::Uid(uid)), ("frames", Value::Count(outcome.frames.into())), ("accepted", Value::Flag(accepted))],
        );
        if accepted {
            self.deliver_ticket(uid);
        }
        Ok(accepted)
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
        let outcome = self.authenticate(&candidates)?;
        self.logger.log(
            Level::Info,
            "identify",
            &[
                ("candidates", Value::Count(candidates.len() as u64)),
                ("frames", Value::Count(outcome.frames.into())),
                ("found", Value::Flag(outcome.uid.is_some())),
            ],
        );
        if let Some(uid) = outcome.uid {
            self.deliver_ticket(uid);
        }
        Ok(outcome.uid)
    }

    pub fn purge(&mut self, uid: u32) -> Result<(), DaemonError> {
        self.storage.purge(uid)?;
        self.logger.log(Level::Info, "purge", &[("uid", Value::Uid(uid))]);
        Ok(())
    }

    fn deliver_ticket(&mut self, uid: u32) {
        self.last_delivery = None;
        let Some(client) = self.tickets.as_mut() else { return };
        let delivery = client.deliver(uid);
        self.logger.log(Level::Info, "ticket", &[("uid", Value::Uid(uid)), ("delivery", Value::Label(delivery.as_str()))]);
        self.last_delivery = Some(delivery);
    }

    fn authenticate(&mut self, candidates: &[(u32, Vec<u8>)]) -> Result<AuthOutcome, DaemonError> {
        let session = self.engine.auth_begin(candidates, self.target_far, MAX_SCORED_FRAMES)?;
        let outcome = self.score_until_decided(session);
        let ended = self.engine.auth_end(session);
        let outcome = outcome?;
        ended?;
        Ok(outcome)
    }

    fn score_until_decided(&mut self, session: u64) -> Result<AuthOutcome, DaemonError> {
        let mut frames = 0;
        for _ in 0..MAX_ATTEMPT_FRAMES {
            let frame = self.sensor.capture()?;
            let progress = self.engine.auth_submit(session, &frame)?;
            frames = progress.scored_frames;
            match progress.verdict {
                AuthVerdict::Accepted(uid) => return Ok(AuthOutcome { uid: Some(uid), frames }),
                AuthVerdict::Rejected => break,
                AuthVerdict::Continue => {}
            }
        }
        Ok(AuthOutcome { uid: None, frames })
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
        pub frames_submitted: u32,
        pub sessions_ended: u32,
    }

    pub const FRAMES_TO_DECIDE: u32 = 3;

    pub struct FakeEngine {
        pub log: Arc<Mutex<EngineLog>>,
        pub live: bool,
        pub accept_template: Vec<u8>,
        pub fail_state: bool,
        pub frames_to_decide: u32,
        pub candidates: Vec<(u32, Vec<u8>)>,
        pub submitted: u32,
    }

    impl FakeEngine {
        pub fn new(log: Arc<Mutex<EngineLog>>, live: bool, accept_template: &[u8]) -> Self {
            Self {
                log,
                live,
                accept_template: accept_template.to_vec(),
                fail_state: false,
                frames_to_decide: FRAMES_TO_DECIDE,
                candidates: Vec::new(),
                submitted: 0,
            }
        }
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

        fn auth_begin(&mut self, candidates: &[(u32, Vec<u8>)], _: f64, max_scored_frames: u32) -> Result<u64, DaemonError> {
            assert_eq!(max_scored_frames, MAX_SCORED_FRAMES);
            self.log.lock().unwrap().verified_templates.extend(candidates.iter().map(|(_, template)| template.clone()));
            self.candidates = candidates.to_vec();
            self.submitted = 0;
            Ok(5)
        }

        fn auth_submit(&mut self, _: u64, _: &CapturedFrame) -> Result<AuthProgress, DaemonError> {
            self.submitted += 1;
            self.log.lock().unwrap().frames_submitted += 1;
            let verdict = if self.submitted < self.frames_to_decide {
                AuthVerdict::Continue
            } else {
                let matched = self.candidates.iter().find(|(_, template)| *template == self.accept_template).map(|(uid, _)| *uid);
                matched.filter(|_| self.live).map_or(AuthVerdict::Rejected, AuthVerdict::Accepted)
            };
            Ok(AuthProgress { verdict, scored_frames: self.submitted })
        }

        fn auth_end(&mut self, _: u64) -> Result<(), DaemonError> {
            self.log.lock().unwrap().sessions_ended += 1;
            Ok(())
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
        let engine = FakeEngine::new(log.clone(), live, template);
        (Biometrics::new(Box::new(FakeSensor), Box::new(engine), Box::new(storage), DEFAULT_TARGET_FAR), log)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::fakes::*;
    use super::*;
    use crate::backends::CapturedFrame;
    use crate::ticket_client::test_keyd::TestKeyd;

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

        let mut engine = FakeEngine::new(Default::default(), true, b"");
        engine.fail_state = true;
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

    // @spec:AC-005
    #[test]
    fn verify_stops_at_the_frame_that_decides_instead_of_capturing_a_fixed_burst() {
        let storage = MemoryStorage::default();
        storage.files.lock().unwrap().insert(1000, b"mine".to_vec());
        let (mut core, log) = core_with(storage, true, b"mine");
        assert!(core.verify(1000).unwrap());
        let log = log.lock().unwrap();
        assert_eq!(log.frames_submitted, FRAMES_TO_DECIDE);
        assert_eq!(log.sessions_ended, 1);
    }

    #[test]
    fn authentication_gives_up_after_the_attempt_limit_and_still_ends_the_session() {
        let storage = MemoryStorage::default();
        storage.files.lock().unwrap().insert(1000, b"mine".to_vec());
        let log = Arc::new(Mutex::new(EngineLog::default()));
        let mut engine = FakeEngine::new(log.clone(), true, b"mine");
        engine.frames_to_decide = u32::MAX;
        let mut core = Biometrics::new(Box::new(FakeSensor), Box::new(engine), Box::new(storage), DEFAULT_TARGET_FAR);
        assert!(!core.verify(1000).unwrap());
        let log = log.lock().unwrap();
        assert_eq!(log.frames_submitted as usize, MAX_ATTEMPT_FRAMES);
        assert_eq!(log.sessions_ended, 1);
    }

    #[test]
    fn sensor_failure_during_authentication_is_an_error_and_the_session_is_still_ended() {
        struct BrokenSensor;

        impl SensorBackend for BrokenSensor {
            fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
                Err(DaemonError::Backend("camera unplugged".into()))
            }
        }

        let storage = MemoryStorage::default();
        storage.files.lock().unwrap().insert(1000, b"mine".to_vec());
        let log = Arc::new(Mutex::new(EngineLog::default()));
        let engine = FakeEngine::new(log.clone(), true, b"mine");
        let mut core = Biometrics::new(Box::new(BrokenSensor), Box::new(engine), Box::new(storage), DEFAULT_TARGET_FAR);
        assert!(matches!(core.verify(1000), Err(DaemonError::Backend(_))));
        assert_eq!(log.lock().unwrap().sessions_ended, 1);
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

    fn keyd_core(storage: MemoryStorage, live: bool, template: &[u8], socket: &std::path::Path) -> Biometrics {
        let (core, _) = core_with(storage, live, template);
        core.with_ticket_client(Some(TicketClient::new(socket)))
    }

    fn storage_with(entries: &[(u32, &[u8])]) -> MemoryStorage {
        let storage = MemoryStorage::default();
        for (uid, template) in entries {
            storage.files.lock().unwrap().insert(*uid, template.to_vec());
        }
        storage
    }

    // @spec:AC-019
    #[test]
    fn a_matching_verify_delivers_a_ticket_the_keyd_verifier_accepts() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keyd.sock");
        let keyd = TestKeyd::start(&socket, 3);
        let mut core = keyd_core(storage_with(&[(1000, b"mine")]), true, b"mine", &socket);
        assert!(core.verify(1000).unwrap());
        assert_eq!(core.last_ticket_delivery(), Some(TicketDelivery::Delivered));
        assert_eq!(*keyd.accepted_uids.lock().unwrap(), vec![1000]);
    }

    // @spec:AC-019
    #[test]
    fn identify_delivers_a_ticket_only_for_the_winning_uid() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keyd.sock");
        let keyd = TestKeyd::start(&socket, 3);
        let storage = storage_with(&[(1000, b"a"), (1001, b"b")]);
        let mut core = keyd_core(storage, true, b"b", &socket);
        assert_eq!(core.identify().unwrap(), Some(1001));
        assert_eq!(*keyd.accepted_uids.lock().unwrap(), vec![1001]);
    }

    // @spec:AC-023
    #[test]
    fn no_match_sends_nothing_to_the_keyd_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keyd.sock");
        let keyd = TestKeyd::start(&socket, 3);
        let storage = storage_with(&[(1000, b"mine")]);
        let mut no_face = keyd_core(storage.clone(), false, b"mine", &socket);
        assert!(!no_face.verify(1000).unwrap());
        assert_eq!(no_face.identify().unwrap(), None);
        let mut stranger = keyd_core(storage, true, b"someone-else", &socket);
        assert!(!stranger.verify(1000).unwrap());
        assert_eq!(stranger.identify().unwrap(), None);
        assert_eq!(no_face.last_ticket_delivery(), None);
        assert_eq!(stranger.last_ticket_delivery(), None);
        assert_eq!(*keyd.connections.lock().unwrap(), 0);
        assert!(keyd.accepted_uids.lock().unwrap().is_empty());
    }

    #[test]
    fn an_unavailable_keyd_does_not_change_the_verify_result() {
        let dir = tempfile::tempdir().unwrap();
        let mut core = keyd_core(storage_with(&[(1000, b"mine")]), true, b"mine", &dir.path().join("missing.sock"));
        assert!(core.verify(1000).unwrap());
        assert_eq!(core.last_ticket_delivery(), Some(TicketDelivery::Unavailable));
        assert_eq!(core.identify().unwrap(), Some(1000));
    }

    #[test]
    fn without_a_ticket_client_verify_behaves_as_before() {
        let (mut core, _) = core_with(storage_with(&[(1000, b"mine")]), true, b"mine");
        assert!(core.verify(1000).unwrap());
        assert_eq!(core.last_ticket_delivery(), None);
    }

    #[test]
    fn a_keyd_restart_between_verifies_still_delivers() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keyd.sock");
        let first = TestKeyd::start(&socket, 3);
        let mut core = keyd_core(storage_with(&[(1000, b"mine")]), true, b"mine", &socket);
        assert!(core.verify(1000).unwrap());
        first.stop();
        let second = TestKeyd::start(&socket, 5);
        assert!(core.verify(1000).unwrap());
        assert_eq!(core.last_ticket_delivery(), Some(TicketDelivery::Delivered));
        assert_eq!(*second.accepted_uids.lock().unwrap(), vec![1000]);
    }
}
