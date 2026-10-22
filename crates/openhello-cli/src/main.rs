use std::process::ExitCode;

use openhello_cli::dbus_client::DbusClient;
use openhello_cli::keyd_client::KeydClient;
use openhello_cli::terminal::TerminalPins;
use openhello_cli::{execute, parse_args, Outcome, Services, USAGE};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("pam") {
        return match openhello_cli::pam_enable::run(&args[1..], &mut std::io::stdout()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(failure) => {
                eprintln!("openhello-cli: {}", failure.message);
                ExitCode::from(failure.code)
            }
        };
    }
    let current_uid = unsafe { libc::getuid() };
    let invocation = match parse_args(std::env::args().skip(1), current_uid) {
        Ok(invocation) => invocation,
        Err(problem) => {
            eprintln!("openhello-cli: {problem}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let connected = DbusClient::connect(invocation.bus)
        .and_then(|b| Ok((b, KeydClient::connect(invocation.bus)?)));
    let (mut biometrics, mut keys) = match connected {
        Ok(clients) => clients,
        Err(problem) => {
            eprintln!("openhello-cli: {problem}");
            return ExitCode::from(3);
        }
    };
    let mut services = Services {
        biometrics: &mut biometrics,
        keys: &mut keys,
        pins: &mut TerminalPins,
    };
    let outcome = execute(&mut services, invocation.command, &mut std::io::stdout());
    if let Outcome::Failed(problem) | Outcome::ProvisionFailed(problem) = &outcome {
        eprintln!("openhello-cli: {problem}");
    }
    ExitCode::from(outcome.exit_code())
}
