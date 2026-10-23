#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DemoMode {
    pub enrolled: bool,
    pub blocked: bool,
    pub hold: bool,
    pub fail: bool,
    pub cycle_tests: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    pub demo: Option<DemoMode>,
    pub stats: bool,
    pub trace_input: bool,
}

impl Options {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Self {
        let mut options = Options::default();
        let mut mode = DemoMode::default();
        let mut demo = std::env::var("OPENHELLO_GUI_DEMO").is_ok_and(|value| value == "1");
        for arg in args {
            match arg.as_str() {
                "--demo" => demo = true,
                "--demo-enrolled" => (demo, mode.enrolled) = (true, true),
                "--demo-blocked" => (demo, mode.blocked) = (true, true),
                "--demo-test" => (demo, mode.cycle_tests) = (true, true),
                "--hold" => mode.hold = true,
                "--fail" => mode.fail = true,
                "--stats" => options.stats = true,
                "--trace-input" => options.trace_input = true,
                other => eprintln!("unknown option: {other}"),
            }
        }
        options.demo = demo.then_some(mode);
        options
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Options {
        Options::parse(args.iter().map(|arg| arg.to_string()))
    }

    // @spec:AC-076
    #[test]
    fn trace_input_is_off_by_default_and_turned_on_by_its_flag() {
        assert!(!parse(&[]).trace_input);
        assert!(parse(&["--trace-input"]).trace_input);
    }
}
