use std::time::{Duration, Instant};

use crate::{CaptureSession, Frame, FrameSource, SensorError};

pub const IDLE_RELEASE: Duration = Duration::from_secs(3);

type Opener<S> = Box<dyn FnMut() -> Result<CaptureSession<S>, SensorError> + Send>;

pub struct LazyCapture<S: FrameSource> {
    opener: Opener<S>,
    session: Option<CaptureSession<S>>,
    last_used: Instant,
}

impl<S: FrameSource> LazyCapture<S> {
    pub fn new(opener: Opener<S>, now: Instant) -> Self {
        Self { opener, session: None, last_used: now }
    }

    #[cfg(test)]
    pub fn is_open(&self) -> bool {
        self.session.is_some()
    }

    pub fn next_frame(&mut self, now: Instant) -> Result<Frame, SensorError> {
        if self.session.is_none() {
            self.session = Some((self.opener)()?);
        }
        self.last_used = now;
        let session = self.session.as_mut().expect("session was just opened");
        let frame = session.next_frame();
        if frame.is_err() {
            self.session = None;
        }
        frame
    }

    pub fn release_if_idle(&mut self, now: Instant, idle: Duration) -> bool {
        let expired = self.session.is_some() && now.duration_since(self.last_used) >= idle;
        if expired {
            self.session = None;
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::Emitter;

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
            Ok(Frame { width: 2, height: 2, pixels: vec![80; 4], timestamp_us: 0 })
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

    const PROBE_FRAMES_FOR_TEST: usize = crate::illumination::PROBE_FRAMES;
}
