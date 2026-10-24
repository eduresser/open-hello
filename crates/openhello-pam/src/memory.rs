use std::time::{Duration, Instant};

// Long-lived callers such as lock screens re-run PAM every second and forget an earlier success on each run;
// answering a TPM-proven success again from memory keeps their unlock valid between runs.
pub const REUSE_WINDOW: Duration = Duration::from_secs(60);

struct Success {
    uid: u32,
    service: String,
    at: Instant,
}

#[derive(Default)]
pub struct SuccessMemory(Option<Success>);

impl SuccessMemory {
    pub const fn new() -> Self {
        Self(None)
    }

    pub fn remember(&mut self, uid: u32, service: &str, now: Instant) {
        self.0 = Some(Success { uid, service: service.to_string(), at: now });
    }

    pub fn recalls(&self, uid: u32, service: &str, now: Instant) -> bool {
        self.0.as_ref().is_some_and(|success| {
            success.uid == uid && success.service == service && now.saturating_duration_since(success.at) < REUSE_WINDOW
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_success_is_recalled_only_for_the_same_user_and_service_within_the_window() {
        let start = Instant::now();
        let mut memory = SuccessMemory::new();
        assert!(!memory.recalls(1000, "kde", start));
        memory.remember(1000, "kde", start);
        assert!(memory.recalls(1000, "kde", start + Duration::from_secs(59)));
        assert!(!memory.recalls(1000, "kde", start + REUSE_WINDOW));
        assert!(!memory.recalls(1001, "kde", start));
        assert!(!memory.recalls(1000, "sudo", start));
        memory.remember(1001, "sddm", start);
        assert!(!memory.recalls(1000, "kde", start), "only the latest success is kept");
    }
}
