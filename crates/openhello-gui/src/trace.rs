use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

static ENABLED: AtomicBool = AtomicBool::new(false);
static START: OnceLock<Instant> = OnceLock::new();
static LAST: Mutex<Option<String>> = Mutex::new(None);

pub fn enable() {
    START.get_or_init(Instant::now);
    ENABLED.store(true, Ordering::Relaxed);
}

pub fn log(what: impl AsRef<str>) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let Ok(mut last) = LAST.lock() else { return };
    let what = what.as_ref();
    if repeats(&mut last, what) {
        return;
    }
    let ms = START.get().map_or(0, |start| start.elapsed().as_millis());
    eprintln!("{}", line(ms, what));
}

fn line(ms: u128, what: &str) -> String {
    format!("[{ms:>7} ms] {what}")
}

fn repeats(last: &mut Option<String>, what: &str) -> bool {
    if last.as_deref() == Some(what) {
        return true;
    }
    *last = Some(what.to_owned());
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // @spec:AC-076
    #[test]
    fn a_line_carries_the_elapsed_milliseconds_and_the_event() {
        assert_eq!(line(42, "clicked test"), "[     42 ms] clicked test");
    }

    // @spec:AC-076
    #[test]
    fn consecutive_identical_lines_are_dropped_but_a_repeat_after_another_line_is_kept() {
        let mut last = None;
        assert!(!repeats(&mut last, "worker emit capture-frame"));
        assert!(repeats(&mut last, "worker emit capture-frame"));
        assert!(!repeats(&mut last, "pointer pressed"));
        assert!(!repeats(&mut last, "worker emit capture-frame"));
    }
}
