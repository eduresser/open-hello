use std::cell::RefCell;

use crate::Page;

pub type Shown = (Page, bool, bool);

pub struct Tracker<K> {
    inside: bool,
    physical: (f64, f64),
    shown: Option<K>,
}

impl<K: PartialEq> Tracker<K> {
    pub const fn new() -> Self {
        Self { inside: false, physical: (0.0, 0.0), shown: None }
    }

    pub fn entered(&mut self) {
        self.inside = true;
    }

    pub fn left(&mut self) {
        self.inside = false;
    }

    pub fn moved(&mut self, x: f64, y: f64) {
        self.inside = true;
        self.physical = (x, y);
    }

    pub fn physical(&self) -> (f64, f64) {
        self.physical
    }

    pub fn refresh(&mut self, key: K, scale: f32) -> Option<(f32, f32)> {
        let changed = self.shown.as_ref() != Some(&key);
        self.shown = Some(key);
        (changed && self.inside).then(|| self.logical(scale))
    }

    fn logical(&self, scale: f32) -> (f32, f32) {
        let scale = f64::from(scale.max(f32::EPSILON));
        ((self.physical.0 / scale) as f32, (self.physical.1 / scale) as f32)
    }
}

thread_local! {
    static TRACKER: RefCell<Tracker<Shown>> = const { RefCell::new(Tracker::new()) };
}

pub fn with<R>(f: impl FnOnce(&mut Tracker<Shown>) -> R) -> R {
    TRACKER.with(|tracker| f(&mut tracker.borrow_mut()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // @spec:AC-077
    #[test]
    fn the_first_screen_refreshes_the_target_when_the_pointer_is_inside() {
        let mut tracker = Tracker::new();
        tracker.moved(200.0, 100.0);
        assert_eq!(tracker.refresh("welcome", 1.0), Some((200.0, 100.0)));
    }

    // @spec:AC-077
    #[test]
    fn nothing_is_sent_while_the_pointer_is_outside_the_window() {
        let mut tracker = Tracker::new();
        assert_eq!(tracker.refresh("welcome", 1.0), None);
        tracker.moved(10.0, 10.0);
        tracker.left();
        assert_eq!(tracker.refresh("done", 1.0), None);
        tracker.entered();
        assert_eq!(tracker.refresh("manage", 1.0), Some((10.0, 10.0)));
    }

    // @spec:AC-077
    #[test]
    fn physical_pixels_become_logical_pixels_with_the_scale_factor() {
        let mut tracker = Tracker::new();
        tracker.moved(300.0, 150.0);
        assert_eq!(tracker.refresh("welcome", 1.5), Some((200.0, 100.0)));
    }

    // @spec:AC-077
    #[test]
    fn the_same_screen_does_not_send_again_but_a_change_does() {
        let mut tracker = Tracker::new();
        tracker.moved(5.0, 6.0);
        assert!(tracker.refresh(("capture", false, false), 1.0).is_some());
        assert_eq!(tracker.refresh(("capture", false, false), 1.0), None);
        assert!(tracker.refresh(("capture", true, false), 1.0).is_some());
        assert!(tracker.refresh(("capture", true, true), 1.0).is_some());
    }

    // @spec:AC-077
    #[test]
    fn the_last_position_is_kept_after_the_pointer_leaves() {
        let mut tracker: Tracker<u8> = Tracker::new();
        tracker.moved(7.0, 8.0);
        tracker.left();
        assert_eq!(tracker.physical(), (7.0, 8.0));
    }
}
