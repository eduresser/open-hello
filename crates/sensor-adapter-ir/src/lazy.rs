use std::time::{Duration, Instant};

use crate::session_log::{self, millis_between, quoted, SessionLog, StderrLog};
use crate::{CaptureSession, Frame, FrameSource, SensorError};

pub const IDLE_RELEASE: Duration = Duration::from_secs(3);
pub const RESTART_PAUSES: [Duration; 2] = [Duration::from_millis(500), Duration::from_millis(1500)];

type Opener<S> = Box<dyn FnMut() -> Result<CaptureSession<S>, SensorError> + Send>;
type Pause = Box<dyn FnMut(Duration) + Send>;

pub struct LazyCapture<S: FrameSource> {
    opener: Opener<S>,
    session: Option<CaptureSession<S>>,
    last_used: Instant,
    opened_at: Instant,
    released_at: Option<Instant>,
    good_frames: u64,
    log: Box<dyn SessionLog>,
    pause: Pause,
}

impl<S: FrameSource> LazyCapture<S> {
    pub fn new(opener: Opener<S>, now: Instant) -> Self {
        Self {
            opener,
            session: None,
            last_used: now,
            opened_at: now,
            released_at: None,
            good_frames: 0,
            log: Box::new(StderrLog),
            pause: Box::new(std::thread::sleep),
        }
    }

    #[cfg(test)]
    pub fn with_log(mut self, log: Box<dyn SessionLog>) -> Self {
        self.log = log;
        self
    }

    #[cfg(test)]
    pub fn with_pause(mut self, pause: Pause) -> Self {
        self.pause = pause;
        self
    }

    pub fn is_open(&self) -> bool {
        self.session.is_some()
    }

    pub fn next_frame(&mut self, now: Instant) -> Result<Frame, SensorError> {
        if self.session.is_none() {
            self.open(now)?;
        }
        self.last_used = now;
        let session = self.session.as_mut().expect("session was just opened");
        let frame = session.next_frame();
        match &frame {
            Ok(_) => self.good_frames += 1,
            Err(error) => self.close(now, "error", Some(error)),
        }
        frame
    }

    pub fn release(&mut self, now: Instant) {
        self.close(now, "requested", None);
    }

    pub fn release_if_idle(&mut self, now: Instant, idle: Duration) -> bool {
        let expired = self.session.is_some() && now.duration_since(self.last_used) >= idle;
        if expired {
            self.close(now, "idle", None);
        }
        expired
    }

    fn open(&mut self, now: Instant) -> Result<(), SensorError> {
        let mut attempt = 1;
        loop {
            let error = match (self.opener)() {
                Ok(session) => {
                    self.session = Some(session);
                    self.opened_at = now;
                    self.good_frames = 0;
                    self.log_open(attempt, now);
                    return Ok(());
                }
                Err(error) => error,
            };
            let pause = RESTART_PAUSES.get(attempt - 1).filter(|_| error.is_transient_start_failure()).copied();
            self.log_open_failed(attempt, now, pause, &error);
            let Some(pause) = pause else { return Err(error) };
            (self.pause)(pause);
            attempt += 1;
        }
    }

    fn close(&mut self, now: Instant, reason: &str, error: Option<&SensorError>) {
        if self.session.take().is_none() {
            return;
        }
        self.released_at = Some(now);
        let mut fields = format!(
            "reason={reason} open_ms={} good_frames={}",
            millis_between(Some(self.opened_at), now),
            self.good_frames
        );
        if let Some(error) = error {
            fields.push_str(&format!(" error={}", quoted(&error.to_string())));
        }
        self.log.write_line(&session_log::line("camera-release", &fields));
    }

    fn log_open(&self, attempt: usize, now: Instant) {
        let fields = format!("attempt={attempt} since_release_ms={}", millis_between(self.released_at, now));
        self.log.write_line(&session_log::line("camera-open", &fields));
    }

    fn log_open_failed(&self, attempt: usize, now: Instant, pause: Option<Duration>, error: &SensorError) {
        let retry = pause.map_or("none".into(), |pause| pause.as_millis().to_string());
        let fields = format!(
            "attempt={attempt} since_release_ms={} retry_in_ms={retry} error={}",
            millis_between(self.released_at, now),
            quoted(&error.to_string())
        );
        self.log.write_line(&session_log::line("camera-open-failed", &fields));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::Emitter;

    const PIXELS: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

    struct LitSource {
        fail_after: Option<usize>,
        served: usize,
        released: Arc<AtomicUsize>,
    }

    impl FrameSource for LitSource {
        fn start(&mut self) -> Result<(), SensorError> {
            Ok(())
        }

        fn next_frame(&mut self) -> Result<Frame, SensorError> {
            if self.fail_after == Some(self.served) {
                return Err(SensorError::Device("unplugged".into()));
            }
            self.served += 1;
            Ok(Frame { width: 2, height: 2, pixels: PIXELS.to_vec(), timestamp_us: 0 })
        }
    }

    impl Drop for LitSource {
        fn drop(&mut self) {
            self.released.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Unused;

    impl Emitter for Unused {
        fn activate(&mut self) -> Result<(), SensorError> {
            unreachable!("the stream is lit")
        }
    }

    struct Fixture {
        lazy: LazyCapture<LitSource>,
        opened: Arc<AtomicUsize>,
        released: Arc<AtomicUsize>,
        start: Instant,
    }

    fn fixture(fail_after: Option<usize>) -> Fixture {
        let opened = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicUsize::new(0));
        let (opened_in, released_in) = (opened.clone(), released.clone());
        let opener: Opener<LitSource> = Box::new(move || {
            opened_in.fetch_add(1, Ordering::SeqCst);
            let source = LitSource { fail_after, served: 0, released: released_in.clone() };
            CaptureSession::begin(&mut Unused, source)
        });
        let start = Instant::now();
        Fixture { lazy: LazyCapture::new(opener, start), opened, released, start }
    }

    // @spec:AC-011
    #[test]
    fn camera_is_not_opened_until_a_frame_is_requested() {
        let fixture = fixture(None);
        assert!(!fixture.lazy.is_open());
        assert_eq!(fixture.opened.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn consecutive_frames_reuse_one_session() {
        let mut fixture = fixture(None);
        for second in 0..5 {
            fixture.lazy.next_frame(fixture.start + Duration::from_secs(second)).unwrap();
        }
        assert_eq!(fixture.opened.load(Ordering::SeqCst), 1);
    }

    // @spec:AC-011
    #[test]
    fn camera_is_released_after_the_idle_period_and_reopened_on_the_next_frame() {
        let mut fixture = fixture(None);
        fixture.lazy.next_frame(fixture.start).unwrap();
        assert!(!fixture.lazy.release_if_idle(fixture.start + IDLE_RELEASE - Duration::from_millis(1), IDLE_RELEASE));
        assert!(fixture.lazy.is_open());
        assert!(fixture.lazy.release_if_idle(fixture.start + IDLE_RELEASE, IDLE_RELEASE));
        assert!(!fixture.lazy.is_open());
        assert_eq!(fixture.released.load(Ordering::SeqCst), 1);
        fixture.lazy.next_frame(fixture.start + Duration::from_secs(10)).unwrap();
        assert_eq!(fixture.opened.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn explicit_release_closes_the_camera_at_once_and_the_next_frame_reopens_it() {
        let mut fixture = fixture(None);
        fixture.lazy.next_frame(fixture.start).unwrap();
        fixture.lazy.release(fixture.start);
        assert!(!fixture.lazy.is_open());
        assert_eq!(fixture.released.load(Ordering::SeqCst), 1);
        fixture.lazy.next_frame(fixture.start).unwrap();
        assert_eq!(fixture.opened.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn releasing_a_closed_camera_does_nothing() {
        let mut fixture = fixture(None);
        assert!(!fixture.lazy.release_if_idle(fixture.start + Duration::from_secs(60), IDLE_RELEASE));
    }

    // @spec:AC-011
    #[test]
    fn capture_error_releases_the_camera_so_the_next_call_starts_fresh() {
        let mut fixture = fixture(Some(PROBE_FRAMES_FOR_TEST + 1));
        let failed = (0..PROBE_FRAMES_FOR_TEST + 5).map(|_| fixture.lazy.next_frame(fixture.start)).any(|frame| frame.is_err());
        assert!(failed);
        assert!(!fixture.lazy.is_open());
        assert_eq!(fixture.released.load(Ordering::SeqCst), 1);
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<String>>>);

    impl SessionLog for Captured {
        fn write_line(&self, line: &str) {
            self.0.lock().unwrap().push(line.to_string());
        }
    }

    struct Restarting {
        lazy: LazyCapture<LitSource>,
        attempts: Arc<AtomicUsize>,
        pauses: Arc<Mutex<Vec<Duration>>>,
        log: Captured,
        start: Instant,
    }

    fn incomplete() -> SensorError {
        SensorError::IncompleteFrames { count: 30, bytes_used: 100, size_image: 4, flags: 0x40 }
    }

    fn restarting(failures: usize, error: fn() -> SensorError) -> Restarting {
        let attempts = Arc::new(AtomicUsize::new(0));
        let pauses = Arc::new(Mutex::new(Vec::new()));
        let log = Captured::default();
        let (attempts_in, pauses_in) = (attempts.clone(), pauses.clone());
        let opener: Opener<LitSource> = Box::new(move || {
            if attempts_in.fetch_add(1, Ordering::SeqCst) < failures {
                return Err(error());
            }
            let source = LitSource { fail_after: None, served: 0, released: Arc::new(AtomicUsize::new(0)) };
            CaptureSession::begin(&mut Unused, source)
        });
        let start = Instant::now();
        let lazy = LazyCapture::new(opener, start)
            .with_log(Box::new(log.clone()))
            .with_pause(Box::new(move |pause| pauses_in.lock().unwrap().push(pause)));
        Restarting { lazy, attempts, pauses, log, start }
    }

    // @spec:AC-075
    #[test]
    fn a_start_that_fails_once_or_twice_is_restarted_with_the_requested_pauses() {
        for (failures, pauses) in [(1, vec![Duration::from_millis(500)]), (2, RESTART_PAUSES.to_vec())] {
            let mut fixture = restarting(failures, incomplete);
            let frame = fixture.lazy.next_frame(fixture.start).unwrap();
            assert_eq!(frame.pixels, PIXELS);
            assert_eq!(fixture.attempts.load(Ordering::SeqCst), failures + 1);
            assert_eq!(*fixture.pauses.lock().unwrap(), pauses);
        }
    }

    // @spec:AC-075
    #[test]
    fn a_start_that_fails_three_times_reports_the_incomplete_frames_error() {
        let mut fixture = restarting(3, incomplete);
        let error = fixture.lazy.next_frame(fixture.start).unwrap_err();
        assert!(matches!(error, SensorError::IncompleteFrames { .. }));
        assert_eq!(fixture.attempts.load(Ordering::SeqCst), 3);
        assert_eq!(*fixture.pauses.lock().unwrap(), RESTART_PAUSES.to_vec());
        assert!(!fixture.lazy.is_open());
    }

    // @spec:AC-075
    #[test]
    fn other_start_failures_are_not_restarted() {
        let unplugged: fn() -> SensorError = || SensorError::NoDevice("gone".into());
        let dark: fn() -> SensorError = || SensorError::NoIllumination;
        for error in [unplugged, dark] {
            let mut fixture = restarting(5, error);
            assert!(fixture.lazy.next_frame(fixture.start).is_err());
            assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
            assert!(fixture.pauses.lock().unwrap().is_empty());
        }
    }

    // @spec:AC-075
    // @principle:P-010
    #[test]
    fn session_events_are_logged_with_timings_and_never_carry_frame_bytes() {
        let mut fixture = restarting(1, incomplete);
        fixture.lazy.next_frame(fixture.start).unwrap();
        fixture.lazy.next_frame(fixture.start).unwrap();
        fixture.lazy.release_if_idle(fixture.start + IDLE_RELEASE, IDLE_RELEASE);
        fixture.lazy.next_frame(fixture.start + Duration::from_millis(3600)).unwrap();
        fixture.lazy.release(fixture.start + Duration::from_millis(3700));
        let lines = fixture.log.0.lock().unwrap().clone();
        let expected = [
            "camera-open-failed attempt=1 since_release_ms=none retry_in_ms=500 error=\"camera device error: camera keeps delivering incomplete frames (30 in a row; last: bytesused=100 of 4, flags=0x40)\"",
            "camera-open attempt=2 since_release_ms=none",
            "camera-release reason=idle open_ms=3000 good_frames=2",
            "camera-open attempt=1 since_release_ms=600",
            "camera-release reason=requested open_ms=100 good_frames=1",
        ];
        assert_eq!(lines.len(), expected.len(), "{lines:#?}");
        for (line, event) in lines.iter().zip(expected) {
            assert_eq!(line, &format!("sensor-adapter-ir INFO {event}"));
        }
        for forbidden in ["deadbeef", "DEADBEEF", "222, 173, 190, 239", "[222, 173", "0xDE"] {
            assert!(!lines.iter().any(|line| line.contains(forbidden)), "log leaked `{forbidden}`");
        }
    }

    #[test]
    fn a_capture_error_is_logged_with_the_good_frames_delivered_before_it() {
        let mut fixture = fixture(Some(PROBE_FRAMES_FOR_TEST + 1));
        let log = Captured::default();
        fixture.lazy = fixture.lazy.with_log(Box::new(log.clone()));
        while fixture.lazy.next_frame(fixture.start).is_ok() {}
        let lines = log.0.lock().unwrap().clone();
        let release = lines.iter().find(|line| line.contains("camera-release")).expect("release line");
        assert!(release.contains("reason=error"), "{release}");
        assert!(release.contains(&format!("good_frames={}", PROBE_FRAMES_FOR_TEST + 1)), "{release}");
        assert!(release.contains("error=\"camera device error: unplugged\""), "{release}");
    }

    const PROBE_FRAMES_FOR_TEST: usize = crate::illumination::PROBE_LIT_FRAMES;
}
