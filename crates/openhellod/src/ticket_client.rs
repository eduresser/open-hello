use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use openhello_ticket::{Issuer, TicketKey, KEY_LEN};

pub const SOCKET_ENV: &str = "OPENHELLO_KEYD_TICKET_SOCKET";
const OP_TICKET_KEY: u8 = 1;
const OP_TICKET: u8 = 2;
const STATUS_ACCEPTED: u8 = 1;
const IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketDelivery {
    Delivered,
    Refused,
    Unavailable,
}

impl TicketDelivery {
    pub fn as_str(self) -> &'static str {
        match self {
            TicketDelivery::Delivered => "delivered",
            TicketDelivery::Refused => "refused",
            TicketDelivery::Unavailable => "unavailable",
        }
    }
}

enum Attempt {
    Delivered,
    Refused,
    Unavailable,
}

pub struct TicketClient {
    path: PathBuf,
    key: Option<TicketKey>,
}

impl TicketClient {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            key: None,
        }
    }

    pub fn from_env() -> Option<Self> {
        std::env::var_os(SOCKET_ENV)
            .filter(|path| !path.is_empty())
            .map(Self::new)
    }

    pub fn deliver(&mut self, uid: u32) -> TicketDelivery {
        let had_cached_key = self.key.is_some();
        let first = self.attempt(uid);
        let retry = had_cached_key && !matches!(first, Attempt::Delivered);
        let last = if retry {
            self.key = None;
            self.attempt(uid)
        } else {
            first
        };
        match last {
            Attempt::Delivered => TicketDelivery::Delivered,
            Attempt::Refused => TicketDelivery::Refused,
            Attempt::Unavailable => TicketDelivery::Unavailable,
        }
    }

    fn attempt(&mut self, uid: u32) -> Attempt {
        let Ok(mut stream) = self.connect() else {
            return Attempt::Unavailable;
        };
        let key = match self.key.as_ref() {
            Some(key) => key.duplicate(),
            None => match fetch_key(&mut stream) {
                Some(key) => {
                    self.key = Some(key.duplicate());
                    key
                }
                None => return Attempt::Unavailable,
            },
        };
        let Ok(ticket) = Issuer::new(key).issue(uid) else {
            return Attempt::Unavailable;
        };
        match request(&mut stream, OP_TICKET, &ticket.encode(), 1) {
            Some(reply) if reply[0] == STATUS_ACCEPTED => Attempt::Delivered,
            Some(_) => Attempt::Refused,
            None => Attempt::Unavailable,
        }
    }

    fn connect(&self) -> std::io::Result<UnixStream> {
        let stream = UnixStream::connect(&self.path)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        Ok(stream)
    }
}

fn fetch_key(stream: &mut UnixStream) -> Option<TicketKey> {
    let reply = request(stream, OP_TICKET_KEY, &[], 1 + KEY_LEN)?;
    if reply[0] != STATUS_ACCEPTED {
        return None;
    }
    Some(TicketKey::from_bytes(reply[1..].try_into().ok()?))
}

fn request(stream: &mut UnixStream, op: u8, payload: &[u8], reply_len: usize) -> Option<Vec<u8>> {
    let mut frame = vec![op];
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).ok()?;
    let mut reply = vec![0u8; reply_len];
    stream.read_exact(&mut reply[..1]).ok()?;
    if reply[0] == STATUS_ACCEPTED {
        stream.read_exact(&mut reply[1..]).ok()?;
    } else {
        reply.truncate(1);
    }
    Some(reply)
}

#[cfg(test)]
pub(crate) mod test_keyd {
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;

    use openhello_ticket::{Ticket, Verifier, TICKET_LEN};

    use super::*;

    pub struct TestKeyd {
        path: PathBuf,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
        pub accepted_uids: Arc<Mutex<Vec<u32>>>,
        pub connections: Arc<Mutex<u32>>,
    }

    impl TestKeyd {
        pub fn start(path: &Path, key_byte: u8) -> Self {
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path).unwrap();
            let key = [key_byte; KEY_LEN];
            let accepted_uids = Arc::new(Mutex::new(Vec::new()));
            let connections = Arc::new(Mutex::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = {
                let (stop, accepted, connections) =
                    (stop.clone(), accepted_uids.clone(), connections.clone());
                std::thread::spawn(move || {
                    let mut verifier = Verifier::new(TicketKey::from_bytes(key));
                    for stream in listener.incoming() {
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        *connections.lock().unwrap() += 1;
                        if let Ok(stream) = stream {
                            serve(key, &mut verifier, &accepted, stream);
                        }
                    }
                })
            };
            Self {
                path: path.to_path_buf(),
                stop,
                thread: Some(thread),
                accepted_uids,
                connections,
            }
        }

        pub fn stop(mut self) {
            self.shutdown();
        }

        fn shutdown(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = UnixStream::connect(&self.path);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }

    impl Drop for TestKeyd {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    fn serve(
        key: [u8; KEY_LEN],
        verifier: &mut Verifier,
        accepted: &Mutex<Vec<u32>>,
        mut stream: UnixStream,
    ) {
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        loop {
            let mut header = [0u8; 3];
            if stream.read_exact(&mut header).is_err() {
                return;
            }
            let mut payload = vec![0u8; usize::from(u16::from_be_bytes([header[1], header[2]]))];
            if stream.read_exact(&mut payload).is_err() {
                return;
            }
            let reply = match (header[0], payload.len()) {
                (OP_TICKET_KEY, 0) => {
                    let mut reply = vec![STATUS_ACCEPTED];
                    reply.extend_from_slice(&key);
                    reply
                }
                (OP_TICKET, TICKET_LEN) => {
                    let uid = Ticket::decode(&payload).map(|t| t.uid());
                    match uid
                        .ok()
                        .filter(|uid| verifier.verify(&payload, *uid).is_ok())
                    {
                        Some(uid) => {
                            accepted.lock().unwrap().push(uid);
                            vec![STATUS_ACCEPTED]
                        }
                        None => {
                            let _ = stream.write_all(&[0]);
                            return;
                        }
                    }
                }
                _ => {
                    let _ = stream.write_all(&[0]);
                    return;
                }
            };
            if stream.write_all(&reply).is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_keyd::TestKeyd;
    use super::*;

    #[test]
    fn protocol_constants_match_the_keyd_server() {
        assert_eq!(OP_TICKET_KEY, openhello_keyd::OP_TICKET_KEY);
        assert_eq!(OP_TICKET, openhello_keyd::OP_TICKET);
        assert_eq!(STATUS_ACCEPTED, openhello_keyd::STATUS_ACCEPTED);
    }

    #[test]
    fn absent_socket_variable_turns_the_feature_off() {
        std::env::remove_var(SOCKET_ENV);
        assert!(TicketClient::from_env().is_none());
        std::env::set_var(SOCKET_ENV, "/run/openhello/keyd-ticket.sock");
        assert!(TicketClient::from_env().is_some());
        std::env::remove_var(SOCKET_ENV);
    }

    #[test]
    fn delivery_is_unavailable_when_nothing_listens() {
        let dir = tempfile::tempdir().unwrap();
        let mut client = TicketClient::new(dir.path().join("missing.sock"));
        assert_eq!(client.deliver(1000), TicketDelivery::Unavailable);
    }

    #[test]
    fn a_restarted_keyd_with_a_new_key_is_picked_up_on_the_next_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyd.sock");
        let first = TestKeyd::start(&path, 7);
        let mut client = TicketClient::new(&path);
        assert_eq!(client.deliver(1000), TicketDelivery::Delivered);
        assert_eq!(client.deliver(1000), TicketDelivery::Delivered);
        assert_eq!(first.accepted_uids.lock().unwrap().len(), 2);
        first.stop();
        assert_eq!(client.deliver(1000), TicketDelivery::Unavailable);

        let second = TestKeyd::start(&path, 9);
        assert_eq!(client.deliver(1000), TicketDelivery::Delivered);
        assert_eq!(*second.accepted_uids.lock().unwrap(), vec![1000]);
    }
}
