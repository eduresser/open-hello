use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use openhello_gui_core::{ClientError, ClientErrorKind, ClientResult, EnrollClient, Frame, ManageClient, Progress, Status};

use crate::options::DemoMode;

const WIDTH: u32 = 640;
const HEIGHT: u32 = 360;
const SEGMENT_TICKS: u32 = 25;
const REQUIRED: u32 = 6;
const TICK: Duration = Duration::from_millis(33);
const PAUSE: Duration = Duration::from_millis(1400);
const RECOVERY_CODE: &str = "4F2A-91C7-D03B-6E58-A1F4-7B29";
const SCRIPT: [&str; 13] = [
    "move-left",
    "too-far",
    "too-dark",
    "accepted",
    "accepted",
    "accepted",
    "yaw-out-of-range",
    "accepted",
    "accepted",
    "accepted",
    "blurred",
    "too-soon",
    "no-face",
];

pub struct DemoClient {
    mode: DemoMode,
    face: Arc<AtomicBool>,
    pace: Duration,
    ticks: u32,
    frames: u32,
    verdict: &'static str,
    noise: Vec<u8>,
}

impl DemoClient {
    pub fn new(mode: DemoMode, face: Arc<AtomicBool>) -> Self {
        Self::paced(mode, face, TICK)
    }

    pub fn paced(mode: DemoMode, face: Arc<AtomicBool>, pace: Duration) -> Self {
        Self { mode, face, pace, ticks: 0, frames: 0, verdict: SCRIPT[0], noise: noise() }
    }

    fn sleep(&self, duration: Duration) {
        if !self.pace.is_zero() {
            thread::sleep(duration);
        }
    }

    fn read_status(&self) -> ClientResult<Status> {
        if self.mode.fail {
            return Err(ClientError::new(ClientErrorKind::CameraBusy, "demo"));
        }
        let face = self.face.load(Ordering::Relaxed);
        Ok(Status { face, key: face })
    }
}

fn noise() -> Vec<u8> {
    let mut seed = 0x9E37_79B9u32;
    (0..65_536)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            (seed % 28) as u8
        })
        .collect()
}

fn script_len() -> u32 {
    SCRIPT.iter().take_while(|verdict| **verdict != "blurred").count() as u32
}

struct Blob {
    cx: f32,
    cy: f32,
    rx: f32,
    ry: f32,
    gain: f32,
}

impl Blob {
    fn at(frames: u32, verdict: &str) -> Self {
        let t = frames as f32 / 30.0;
        let swell = 3.0 * (t * 1.3).sin();
        Self {
            cx: 320.0 + 38.0 * (t * 0.9).sin(),
            cy: 180.0 + 16.0 * (t * 0.6 + 1.0).sin(),
            rx: 74.0 + swell,
            ry: 98.0 + swell,
            gain: if verdict == "too-dark" { 0.35 } else { 1.0 },
        }
    }

    fn level(&self, x: u32, y: u32, noise: u8) -> u8 {
        let dx = (x as f32 - self.cx) / self.rx;
        let dy = (y as f32 - self.cy) / self.ry;
        let d = dx * dx + dy * dy;
        let face = ((1.15 - d) * 6.0).clamp(0.0, 1.0);
        let base = 38.0 + face * (150.0 - 40.0 * d.min(1.0));
        ((base + noise as f32) * self.gain).min(255.0) as u8
    }
}

impl EnrollClient for DemoClient {
    fn check_ready(&mut self) -> ClientResult<()> {
        if self.mode.blocked {
            return Err(ClientError::new(ClientErrorKind::CameraBusy, "demo"));
        }
        Ok(())
    }

    fn status(&mut self, _uid: u32) -> ClientResult<Status> {
        self.read_status()
    }

    fn enroll_begin(&mut self, _uid: u32) -> ClientResult<String> {
        self.sleep(PAUSE);
        self.ticks = 0;
        Ok("demo".into())
    }

    fn enroll_capture(&mut self, _handle: &str) -> ClientResult<Progress> {
        self.sleep(self.pace);
        let total = script_len() * SEGMENT_TICKS;
        let finished = !self.mode.hold && self.ticks >= total;
        let position = if self.mode.hold { self.ticks % total } else { self.ticks.min(total - 1) };
        let index = (position / SEGMENT_TICKS) as usize;
        self.verdict = SCRIPT[index];
        let accepted = SCRIPT[..=index].iter().filter(|verdict| **verdict == "accepted").count() as u32;
        self.ticks += 1;
        let (state, filled) = if finished { ("complete", REQUIRED) } else { ("in-progress", accepted.min(REQUIRED)) };
        Ok(Progress { verdict: self.verdict.into(), state: state.into(), filled, required: REQUIRED })
    }

    fn enroll_frame(&mut self, _handle: &str) -> ClientResult<Frame> {
        self.frames += 1;
        let blob = Blob::at(self.frames, self.verdict);
        let shift = self.frames.wrapping_mul(7919) as usize;
        let pixels = (0..HEIGHT)
            .flat_map(|y| (0..WIDTH).map(move |x| (x, y)))
            .map(|(x, y)| blob.level(x, y, self.noise[(shift + (y * WIDTH + x) as usize) % self.noise.len()]))
            .collect();
        Ok(Frame { width: WIDTH, height: HEIGHT, pixels })
    }

    fn enroll_commit(&mut self, _handle: &str) -> ClientResult<()> {
        self.face.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn enroll_discard(&mut self, _handle: &str) -> ClientResult<()> {
        Ok(())
    }

    fn provision(&mut self, _uid: u32) -> ClientResult<String> {
        self.sleep(PAUSE);
        Ok(RECOVERY_CODE.into())
    }
}

impl ManageClient for DemoClient {
    fn status(&mut self, _uid: u32) -> ClientResult<Status> {
        self.read_status()
    }

    fn verify(&mut self, _uid: u32) -> ClientResult<bool> {
        self.sleep(PAUSE);
        Ok(true)
    }

    fn purge(&mut self, _uid: u32) -> ClientResult<()> {
        self.sleep(PAUSE);
        self.face.store(false, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use openhello_gui_core::{EnrollmentFlow, Language, Step};

    use super::*;
    use crate::capture::CaptureView;

    fn flow(mode: DemoMode) -> EnrollmentFlow<DemoClient> {
        let client = DemoClient::paced(mode, Arc::new(AtomicBool::new(false)), Duration::ZERO);
        EnrollmentFlow::new(client, 1000, Language::English)
    }

    // @spec:AC-059
    #[test]
    fn the_demo_capture_grows_the_progress_and_shows_a_frame_and_a_sentence_on_every_tick() {
        let mut flow = flow(DemoMode::default());
        flow.start();
        flow.confirm_identity();
        let strings = *flow.strings();
        let mut views = Vec::new();
        while let Some(update) = flow.tick() {
            views.push(CaptureView::new(update, &strings));
        }
        assert_eq!(flow.step(), Step::RecoveryCode);
        let first = &views[0];
        assert_eq!((first.guidance, first.progress), ("Move a little to your left", 0.0));
        assert!(views.iter().all(|view| view.frame.is_some() && !view.guidance.is_empty()));
        assert!(views.windows(2).all(|pair| pair[1].progress >= pair[0].progress));
        assert_eq!(views.last().map(|view| view.progress_text.as_str()), Some("6 of 6"));
    }

    // @spec:AC-070
    #[test]
    fn the_blocked_demo_refuses_to_start_and_creates_no_session() {
        let mut flow = flow(DemoMode { blocked: true, ..DemoMode::default() });
        flow.start();
        assert!(flow.blocked().is_some());
        assert_eq!(flow.step(), Step::Welcome);
    }
}
