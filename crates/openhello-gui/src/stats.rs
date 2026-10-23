use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use slint::{ComponentHandle, RenderingState, Timer, TimerMode};

use crate::MainWindow;

static PREVIEWS: AtomicU32 = AtomicU32::new(0);
static RENDERS: AtomicU32 = AtomicU32::new(0);

pub fn count_preview() {
    PREVIEWS.fetch_add(1, Ordering::Relaxed);
}

pub fn start(window: &MainWindow) -> Timer {
    if let Err(error) = window.window().set_rendering_notifier(|state, _| {
        if matches!(state, RenderingState::AfterRendering) {
            RENDERS.fetch_add(1, Ordering::Relaxed);
        }
    }) {
        eprintln!("render counter unavailable: {error}");
    }
    let timer = Timer::default();
    timer.start(TimerMode::Repeated, Duration::from_secs(1), report);
    timer
}

fn report() {
    let previews = PREVIEWS.swap(0, Ordering::Relaxed);
    let renders = RENDERS.swap(0, Ordering::Relaxed);
    eprintln!("preview_updates/s={previews} rendered_frames/s={renders}");
}
