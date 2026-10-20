use std::process::ExitCode;

use openhello_cli::dbus_client::DbusClient;
use openhello_cli::{execute, parse_args, Outcome, USAGE};

fn main() -> ExitCode {
    let current_uid = unsafe { libc::getuid() };
    let invocation = match parse_args(std::env::args().skip(1), current_uid) {
        Ok(invocation) => invocation,
        Err(problem) => {
            eprintln!("openhello-cli: {problem}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let mut client = match DbusClient::connect(invocation.bus) {
        Ok(client) => client,
        Err(problem) => {
            eprintln!("openhello-cli: {problem}");
            return ExitCode::from(3);
        }
    };
    let outcome = execute(&mut client, invocation.command, &mut std::io::stdout());
    if let Outcome::Failed(problem) = &outcome {
        eprintln!("openhello-cli: {problem}");
    }
    ExitCode::from(outcome.exit_code())
}
