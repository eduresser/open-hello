fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    if let Err(error) = slint_build::compile_with_config("ui/app.slint", config) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
