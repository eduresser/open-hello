use std::thread;
use std::time::{Duration, Instant};

use openhello_gui_core::{ClientResult, EnrollClient, Frame, ManageClient, Progress, Status};

const WIDTH: u32 = 160;
const HEIGHT: u32 = 120;
const REQUIRED: u32 = 6;
const TICK: Duration = Duration::from_millis(220);
const PAUSE: Duration = Duration::from_millis(1400);
const VERDICTS: [&str; 8] = ["no-face", "move-left", "move-left", "too-far", "too-far", "too-close", "accepted", "accepted"];

pub struct DemoClient {
    face: bool,
    filled: u32,
    calls: usize,
    started: Instant,
}

impl DemoClient {
    pub fn new(face: bool) -> Self {
        Self { face, filled: 0, calls: 0, started: Instant::now() }
    }
}

fn synthetic_frame(seconds: f32) -> Vec<u8> {
    let center_x = WIDTH as f32 * (0.35 + 0.1 * seconds.sin());
    let center_y = HEIGHT as f32 * 0.5;
    (0..HEIGHT)
        .flat_map(|y| (0..WIDTH).map(move |x| (x, y)))
        .map(|(x, y)| {
            let dx = (x as f32 - center_x) / 28.0;
            let dy = (y as f32 - center_y) / 38.0;
            let blob = (1.0 - (dx * dx + dy * dy)).clamp(0.0, 1.0);
            let background = 40.0 + 30.0 * (x as f32 / WIDTH as f32);
            (background + 180.0 * blob).min(255.0) as u8
        })
        .collect()
}

impl EnrollClient for DemoClient {
    fn status(&mut self, _uid: u32) -> ClientResult<Status> {
        Ok(Status { face: self.face, key: self.face, pin: self.face })
    }

    fn enroll_begin(&mut self, _uid: u32) -> ClientResult<String> {
        thread::sleep(PAUSE);
        self.filled = 0;
        self.calls = 0;
        Ok("demo".into())
    }

    fn enroll_capture(&mut self, _handle: &str) -> ClientResult<Progress> {
        thread::sleep(TICK);
        let verdict = VERDICTS[self.calls % VERDICTS.len()];
        self.calls += 1;
        if verdict == "accepted" {
            self.filled += 1;
        }
        let state = if self.filled >= REQUIRED { "complete" } else { "capturing" };
        Ok(Progress { verdict: verdict.into(), state: state.into(), filled: self.filled, required: REQUIRED })
    }

    fn enroll_frame(&mut self, _handle: &str) -> ClientResult<Frame> {
        Ok(Frame { width: WIDTH, height: HEIGHT, pixels: synthetic_frame(self.started.elapsed().as_secs_f32()) })
    }

    fn enroll_commit(&mut self, _handle: &str) -> ClientResult<()> {
        self.face = true;
        Ok(())
    }

    fn enroll_discard(&mut self, _handle: &str) -> ClientResult<()> {
        Ok(())
    }

    fn set_pin(&mut self, _uid: u32, _pin: &str) -> ClientResult<()> {
        Ok(())
    }

    fn provision(&mut self, _uid: u32) -> ClientResult<String> {
        thread::sleep(PAUSE);
        Ok("K7QF-92MD-XW4P-8TNH".into())
    }
}

impl ManageClient for DemoClient {
    fn status(&mut self, _uid: u32) -> ClientResult<Status> {
        Ok(Status { face: self.face, key: self.face, pin: self.face })
    }

    fn verify(&mut self, _uid: u32) -> ClientResult<bool> {
        thread::sleep(PAUSE);
        Ok(true)
    }

    fn purge(&mut self, _uid: u32) -> ClientResult<()> {
        thread::sleep(PAUSE);
        self.face = false;
        Ok(())
    }
}
