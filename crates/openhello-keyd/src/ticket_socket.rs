use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use openhello_ticket::TICKET_LEN;

use crate::tpm::failure;
use crate::{KeydError, Protectors};

pub const OP_TICKET_KEY: u8 = 1;
pub const OP_TICKET: u8 = 2;
pub const STATUS_REFUSED: u8 = 0;
pub const STATUS_ACCEPTED: u8 = 1;
const MAX_PAYLOAD: usize = 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct TicketSocketConfig {
    pub path: PathBuf,
    pub allowed_uid: u32,
    pub expected_exe: Option<PathBuf>,
}

pub struct TicketSocket {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TicketSocket {
    pub fn bind(
        protectors: Arc<Protectors>,
        config: TicketSocketConfig,
    ) -> Result<Self, KeydError> {
        if config.path.exists() {
            std::fs::remove_file(&config.path)
                .map_err(|e| failure("replacing the ticket socket", &e.to_string(), &[]))?;
        }
        let listener = UnixListener::bind(&config.path)
            .map_err(|e| failure("binding the ticket socket", &e.to_string(), &[]))?;
        std::fs::set_permissions(&config.path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| failure("securing the ticket socket", &e.to_string(), &[]))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = stop.clone();
            let config = config.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        serve(&protectors, &config, stream);
                    }
                }
            })
        };
        Ok(Self {
            path: config.path,
            stop,
            thread: Some(thread),
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TicketSocket {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.path);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn serve(protectors: &Protectors, config: &TicketSocketConfig, mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    if !peer_allowed(&stream, config) {
        let _ = stream.write_all(&[STATUS_REFUSED]);
        return;
    }
    while let Some((op, payload)) = read_frame(&mut stream) {
        let reply = match (op, payload.len()) {
            // The ticket key is lost on a keyd restart; openhellod must fetch it again.
            (OP_TICKET_KEY, 0) => {
                let mut reply = vec![STATUS_ACCEPTED];
                reply.extend_from_slice(&*protectors.ticket_key_bytes());
                reply
            }
            (OP_TICKET, TICKET_LEN) => match protectors.unlock_for_socket(&payload) {
                Ok(()) => vec![STATUS_ACCEPTED],
                Err(error) => {
                    eprintln!("openhello-keyd: ticket refused: {error}");
                    let _ = stream.write_all(&[STATUS_REFUSED]);
                    return;
                }
            },
            _ => {
                eprintln!("openhello-keyd: request refused: not a ticket frame");
                let _ = stream.write_all(&[STATUS_REFUSED]);
                return;
            }
        };
        if stream.write_all(&reply).is_err() {
            return;
        }
    }
}

fn read_frame(stream: &mut UnixStream) -> Option<(u8, Vec<u8>)> {
    let mut header = [0u8; 3];
    stream.read_exact(&mut header).ok()?;
    let len = usize::from(u16::from_be_bytes([header[1], header[2]]));
    if len > MAX_PAYLOAD {
        eprintln!("openhello-keyd: request refused: payload of {len} bytes is not a ticket");
        let _ = stream.write_all(&[STATUS_REFUSED]);
        return None;
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).ok()?;
    Some((header[0], payload))
}

fn peer_allowed(stream: &UnixStream, config: &TicketSocketConfig) -> bool {
    let Some((uid, pid)) = peer_credentials(stream) else {
        return false;
    };
    if uid != config.allowed_uid {
        eprintln!("openhello-keyd: ticket socket peer refused: uid {uid} is not allowed");
        return false;
    }
    if let Some(expected) = &config.expected_exe {
        match std::fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(actual) if &actual == expected => {}
            _ => {
                eprintln!("openhello-keyd: ticket socket peer refused: pid {pid} is not the expected executable");
                return false;
            }
        }
    }
    true
}

fn peer_credentials(stream: &UnixStream) -> Option<(u32, i32)> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some((cred.uid, cred.pid))
}
