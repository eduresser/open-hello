use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::ticket_socket::{STATUS_ACCEPTED, STATUS_REFUSED};
use crate::tpm::failure;
use crate::{KeydError, Protectors};

pub const OP_UNLOCK_TAKE_GRANT: u8 = 1;
pub const OP_UNLOCK_PIN: u8 = 2;
pub const OP_UNLOCK_RECOVERY: u8 = 3;
pub const RECOVERY_SEPARATOR: u8 = b'\n';
const MAX_PAYLOAD: usize = 128;
const MAX_CONNECTIONS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct UnlockSocketConfig {
    pub path: PathBuf,
}

pub struct UnlockSocket {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl UnlockSocket {
    pub fn bind(
        protectors: Arc<Protectors>,
        config: UnlockSocketConfig,
    ) -> Result<Self, KeydError> {
        if config.path.exists() {
            std::fs::remove_file(&config.path)
                .map_err(|e| failure("replacing the unlock socket", &e.to_string(), &[]))?;
        }
        let listener = UnixListener::bind(&config.path)
            .map_err(|e| failure("binding the unlock socket", &e.to_string(), &[]))?;
        // Any local user may connect; SO_PEERCRED, not the file mode, decides whose key is addressed.
        std::fs::set_permissions(&config.path, std::fs::Permissions::from_mode(0o666))
            .map_err(|e| failure("opening the unlock socket to users", &e.to_string(), &[]))?;
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                        active.fetch_sub(1, Ordering::SeqCst);
                        continue;
                    }
                    let protectors = protectors.clone();
                    let active = active.clone();
                    std::thread::spawn(move || {
                        serve(&protectors, stream);
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
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

impl Drop for UnlockSocket {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.path);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn serve(protectors: &Protectors, mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let Some(uid) = peer_uid(&stream) else {
        refuse(&mut stream);
        return;
    };
    while let Some((op, payload)) = read_frame(&mut stream) {
        let Some(reply) = answer(protectors, uid, op, &payload) else {
            eprintln!("openhello-keyd: unlock request refused for uid {uid}");
            refuse(&mut stream);
            return;
        };
        if write_reply(&mut stream, STATUS_ACCEPTED, &reply).is_err() {
            return;
        }
    }
}

fn answer(
    protectors: &Protectors,
    uid: u32,
    op: u8,
    payload: &Zeroizing<Vec<u8>>,
) -> Option<Zeroizing<Vec<u8>>> {
    match op {
        OP_UNLOCK_TAKE_GRANT if payload.is_empty() => {
            let secret = protectors.take_grant(uid)?;
            Some(Zeroizing::new(secret.expose().as_bytes().to_vec()))
        }
        OP_UNLOCK_PIN => {
            let pin = std::str::from_utf8(payload).ok()?;
            let secret = protectors.unlock_with_pin(uid, pin).ok()?;
            Some(Zeroizing::new(secret.expose().as_bytes().to_vec()))
        }
        OP_UNLOCK_RECOVERY => {
            let code = std::str::from_utf8(payload).ok()?;
            let (secret, fresh) = protectors.unlock_with_recovery(uid, code).ok()?;
            let mut reply = Zeroizing::new(secret.expose().as_bytes().to_vec());
            reply.push(RECOVERY_SEPARATOR);
            reply.extend_from_slice(fresh.reveal().as_bytes());
            Some(reply)
        }
        _ => None,
    }
}

fn refuse(stream: &mut UnixStream) {
    let _ = write_reply(stream, STATUS_REFUSED, &[]);
}

fn write_reply(stream: &mut UnixStream, status: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut frame = Zeroizing::new(Vec::with_capacity(3 + payload.len()));
    frame.push(status);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)
}

fn read_frame(stream: &mut UnixStream) -> Option<(u8, Zeroizing<Vec<u8>>)> {
    let mut header = [0u8; 3];
    stream.read_exact(&mut header).ok()?;
    let len = usize::from(u16::from_be_bytes([header[1], header[2]]));
    if len > MAX_PAYLOAD {
        eprintln!("openhello-keyd: unlock request refused: payload of {len} bytes");
        return None;
    }
    let mut payload = Zeroizing::new(vec![0u8; len]);
    stream.read_exact(&mut payload).ok()?;
    Some((header[0], payload))
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
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
    (rc == 0).then_some(cred.uid)
}
