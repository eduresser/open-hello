use std::io::{BufRead, Write};
use std::os::fd::AsRawFd;

use crate::{Answers, PinPrompt};

pub struct TerminalPins;

pub struct TerminalAnswers;

struct EchoOff {
    fd: i32,
    saved: libc::termios,
}

impl EchoOff {
    fn engage(fd: i32) -> Result<Self, String> {
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err("the PIN must be typed on a terminal".into());
        }
        let mut silent = saved;
        silent.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &silent) } != 0 {
            return Err("cannot turn off terminal echo".into());
        }
        Ok(Self { fd, saved })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved) };
    }
}

impl PinPrompt for TerminalPins {
    fn read_secret(&mut self, prompt: &str) -> Result<String, String> {
        let stdin = std::io::stdin();
        let guard = EchoOff::engage(stdin.as_raw_fd())?;
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let read = stdin.lock().read_line(&mut line);
        drop(guard);
        eprintln!();
        read.map_err(|e| format!("cannot read the PIN: {e}"))?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    }
}

impl Answers for TerminalAnswers {
    fn ask(&mut self, question: &str) -> Result<String, String> {
        print!("{question}");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) => Err("no answer was given".into()),
            Ok(_) => Ok(line.trim_end_matches(['\n', '\r']).to_string()),
            Err(e) => Err(format!("cannot read the answer: {e}")),
        }
    }
}
