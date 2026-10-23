pub trait Flags {
    fn busy(&self) -> bool;
    fn set_busy(&self, busy: bool);
    fn set_testing(&self, testing: bool);
}

pub fn begin(flags: &impl Flags, testing: bool) -> bool {
    if flags.busy() {
        return false;
    }
    flags.set_busy(true);
    flags.set_testing(testing);
    true
}

pub fn settle(flags: &impl Flags) {
    flags.set_busy(false);
    flags.set_testing(false);
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[derive(Default)]
    struct Fake {
        busy: Cell<bool>,
        testing: Cell<bool>,
    }

    impl Flags for Fake {
        fn busy(&self) -> bool {
            self.busy.get()
        }

        fn set_busy(&self, busy: bool) {
            self.busy.set(busy);
        }

        fn set_testing(&self, testing: bool) {
            self.testing.set(testing);
        }
    }

    // @spec:AC-076
    #[test]
    fn the_first_click_is_accepted_and_the_repeat_is_ignored_until_the_screen_settles() {
        let flags = Fake::default();
        assert!(begin(&flags, true));
        assert!(flags.busy.get() && flags.testing.get());
        assert!(!begin(&flags, false));
        assert!(flags.testing.get());
        settle(&flags);
        assert!(!flags.busy.get() && !flags.testing.get());
        assert!(begin(&flags, false));
    }
}
