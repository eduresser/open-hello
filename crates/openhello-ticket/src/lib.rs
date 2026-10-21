use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_TTL_MS: u64 = 5_000;
pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 16;
const MAC_LEN: usize = 32;
const BODY_LEN: usize = 4 + NONCE_LEN + 8;
pub const TICKET_LEN: usize = BODY_LEN + MAC_LEN;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TicketError {
    #[error("ticket is malformed")]
    Malformed,
    #[error("ticket signature is invalid")]
    InvalidMac,
    #[error("ticket was issued for another user")]
    UidMismatch,
    #[error("ticket has expired")]
    Expired,
    #[error("ticket was already used")]
    Reused,
    #[error("could not gather randomness")]
    Entropy,
}

pub trait Clock {
    fn now_ms(&self) -> u64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Ephemeral HMAC key shared by the issuer and the verifier; wiped on drop, never printed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TicketKey([u8; KEY_LEN]);

impl TicketKey {
    pub fn generate() -> Result<Self, TicketError> {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::getrandom(&mut bytes).map_err(|_| TicketError::Entropy)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn duplicate(&self) -> Self {
        Self(self.0)
    }

    fn mac(&self, body: &[u8]) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(body);
        mac
    }
}

impl std::fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TicketKey(..)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Ticket {
    uid: u32,
    nonce: [u8; NONCE_LEN],
    expiry_ms: u64,
    mac: [u8; MAC_LEN],
}

impl Ticket {
    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn expiry_ms(&self) -> u64 {
        self.expiry_ms
    }

    pub fn encode(&self) -> [u8; TICKET_LEN] {
        let mut out = [0u8; TICKET_LEN];
        out[..BODY_LEN].copy_from_slice(&body(self.uid, &self.nonce, self.expiry_ms));
        out[BODY_LEN..].copy_from_slice(&self.mac);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TicketError> {
        if bytes.len() != TICKET_LEN {
            return Err(TicketError::Malformed);
        }
        Ok(Self {
            uid: u32::from_be_bytes(bytes[..4].try_into().map_err(|_| TicketError::Malformed)?),
            nonce: bytes[4..4 + NONCE_LEN]
                .try_into()
                .map_err(|_| TicketError::Malformed)?,
            expiry_ms: u64::from_be_bytes(
                bytes[4 + NONCE_LEN..BODY_LEN]
                    .try_into()
                    .map_err(|_| TicketError::Malformed)?,
            ),
            mac: bytes[BODY_LEN..]
                .try_into()
                .map_err(|_| TicketError::Malformed)?,
        })
    }
}

impl std::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ticket")
            .field("uid", &self.uid)
            .finish_non_exhaustive()
    }
}

fn body(uid: u32, nonce: &[u8; NONCE_LEN], expiry_ms: u64) -> [u8; BODY_LEN] {
    let mut out = [0u8; BODY_LEN];
    out[..4].copy_from_slice(&uid.to_be_bytes());
    out[4..4 + NONCE_LEN].copy_from_slice(nonce);
    out[4 + NONCE_LEN..].copy_from_slice(&expiry_ms.to_be_bytes());
    out
}

pub struct Issuer<C: Clock = SystemClock> {
    key: TicketKey,
    clock: C,
    ttl_ms: u64,
}

impl Issuer {
    pub fn new(key: TicketKey) -> Self {
        Self::with_clock(key, SystemClock)
    }
}

impl<C: Clock> Issuer<C> {
    pub fn with_clock(key: TicketKey, clock: C) -> Self {
        Self {
            key,
            clock,
            ttl_ms: DEFAULT_TTL_MS,
        }
    }

    pub fn with_ttl_ms(mut self, ttl_ms: u64) -> Self {
        self.ttl_ms = ttl_ms;
        self
    }

    pub fn issue(&self, uid: u32) -> Result<Ticket, TicketError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| TicketError::Entropy)?;
        let expiry_ms = self.clock.now_ms().saturating_add(self.ttl_ms);
        let mac = self
            .key
            .mac(&body(uid, &nonce, expiry_ms))
            .finalize()
            .into_bytes()
            .into();
        Ok(Ticket {
            uid,
            nonce,
            expiry_ms,
            mac,
        })
    }
}

pub struct Verifier<C: Clock = SystemClock> {
    key: TicketKey,
    clock: C,
    used: HashMap<[u8; NONCE_LEN], u64>,
}

impl Verifier {
    pub fn new(key: TicketKey) -> Self {
        Self::with_clock(key, SystemClock)
    }
}

impl<C: Clock> Verifier<C> {
    pub fn with_clock(key: TicketKey, clock: C) -> Self {
        Self {
            key,
            clock,
            used: HashMap::new(),
        }
    }

    /// Checks MAC (constant time), uid, expiry and single use, in that order. A ticket is
    /// consumed only when every check passes, so a refused attempt never burns a valid nonce.
    pub fn verify(&mut self, bytes: &[u8], expected_uid: u32) -> Result<(), TicketError> {
        let ticket = Ticket::decode(bytes)?;
        let signed = body(ticket.uid, &ticket.nonce, ticket.expiry_ms);
        self.key
            .mac(&signed)
            .verify_slice(&ticket.mac)
            .map_err(|_| TicketError::InvalidMac)?;
        if ticket.uid != expected_uid {
            return Err(TicketError::UidMismatch);
        }
        let now = self.clock.now_ms();
        if now >= ticket.expiry_ms {
            return Err(TicketError::Expired);
        }
        self.purge_expired(now);
        if self.used.contains_key(&ticket.nonce) {
            return Err(TicketError::Reused);
        }
        self.used.insert(ticket.nonce, ticket.expiry_ms);
        Ok(())
    }

    /// Forgets nonces whose ticket can no longer pass the expiry check anyway.
    pub fn purge_expired(&mut self, now_ms: u64) {
        self.used.retain(|_, expiry| *expiry > now_ms);
    }

    pub fn tracked_nonces(&self) -> usize {
        self.used.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[derive(Clone)]
    struct TestClock(Arc<AtomicU64>);

    impl TestClock {
        fn at(ms: u64) -> Self {
            Self(Arc::new(AtomicU64::new(ms)))
        }
        fn advance(&self, ms: u64) {
            self.0.fetch_add(ms, Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    const UID: u32 = 1000;

    fn pair() -> (Issuer<TestClock>, Verifier<TestClock>, TestClock) {
        let clock = TestClock::at(1_000_000);
        let key = TicketKey::generate().unwrap();
        let issuer = Issuer::with_clock(key.duplicate(), clock.clone());
        let verifier = Verifier::with_clock(key, clock.clone());
        (issuer, verifier, clock)
    }

    #[test]
    fn fresh_ticket_for_the_expected_user_is_accepted() {
        let (issuer, mut verifier, _) = pair();
        let ticket = issuer.issue(UID).unwrap();
        assert_eq!(ticket.uid(), UID);
        assert_eq!(verifier.verify(&ticket.encode(), UID), Ok(()));
    }

    #[test]
    fn encoding_round_trips() {
        let (issuer, _, _) = pair();
        let ticket = issuer.issue(UID).unwrap();
        let decoded = Ticket::decode(&ticket.encode()).unwrap();
        assert!(decoded == ticket);
        assert_eq!(decoded.expiry_ms(), 1_000_000 + DEFAULT_TTL_MS);
    }

    #[test]
    fn ttl_is_configurable() {
        let clock = TestClock::at(0);
        let key = TicketKey::generate().unwrap();
        let issuer = Issuer::with_clock(key.duplicate(), clock.clone()).with_ttl_ms(100);
        let mut verifier = Verifier::with_clock(key, clock.clone());
        let ticket = issuer.issue(UID).unwrap();
        clock.advance(99);
        assert_eq!(verifier.verify(&ticket.encode(), UID), Ok(()));
        let late = issuer.issue(UID).unwrap();
        clock.advance(100);
        assert_eq!(
            verifier.verify(&late.encode(), UID),
            Err(TicketError::Expired)
        );
    }

    // @spec:AC-020
    #[test]
    fn expired_ticket_is_refused() {
        let (issuer, mut verifier, clock) = pair();
        let ticket = issuer.issue(UID).unwrap();
        clock.advance(DEFAULT_TTL_MS - 1);
        let still_valid = issuer.issue(UID).unwrap();
        assert_eq!(verifier.verify(&still_valid.encode(), UID), Ok(()));
        clock.advance(1);
        assert_eq!(
            verifier.verify(&ticket.encode(), UID),
            Err(TicketError::Expired)
        );
        assert_eq!(TicketError::Expired.to_string(), "ticket has expired");
    }

    // @spec:AC-021
    #[test]
    fn second_use_of_the_same_ticket_is_refused() {
        let (issuer, mut verifier, _) = pair();
        let bytes = issuer.issue(UID).unwrap().encode();
        assert_eq!(verifier.verify(&bytes, UID), Ok(()));
        assert_eq!(verifier.verify(&bytes, UID), Err(TicketError::Reused));
        let other = issuer.issue(UID).unwrap().encode();
        assert_eq!(verifier.verify(&other, UID), Ok(()));
    }

    // @spec:AC-022
    #[test]
    fn tampered_mac_is_refused() {
        let (issuer, mut verifier, _) = pair();
        let mut bytes = issuer.issue(UID).unwrap().encode();
        bytes[TICKET_LEN - 1] ^= 0x01;
        assert_eq!(verifier.verify(&bytes, UID), Err(TicketError::InvalidMac));
    }

    // @spec:AC-022
    #[test]
    fn tampered_body_is_refused() {
        let (issuer, mut verifier, _) = pair();
        let mut bytes = issuer.issue(UID).unwrap().encode();
        bytes[BODY_LEN - 1] ^= 0x01;
        assert_eq!(verifier.verify(&bytes, UID), Err(TicketError::InvalidMac));
        let mut rewritten = issuer.issue(UID).unwrap().encode();
        rewritten[..4].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(verifier.verify(&rewritten, 0), Err(TicketError::InvalidMac));
    }

    // @spec:AC-022
    #[test]
    fn ticket_for_another_user_is_refused_and_not_consumed() {
        let (issuer, mut verifier, _) = pair();
        let bytes = issuer.issue(UID).unwrap().encode();
        assert_eq!(
            verifier.verify(&bytes, UID + 1),
            Err(TicketError::UidMismatch)
        );
        assert_eq!(verifier.verify(&bytes, UID), Ok(()));
    }

    // @spec:AC-022
    #[test]
    fn ticket_signed_with_another_key_is_refused() {
        let (_, mut verifier, clock) = pair();
        let rogue = Issuer::with_clock(TicketKey::generate().unwrap(), clock);
        let bytes = rogue.issue(UID).unwrap().encode();
        assert_eq!(verifier.verify(&bytes, UID), Err(TicketError::InvalidMac));
    }

    #[test]
    fn truncated_oversized_and_garbage_bytes_are_malformed() {
        let (issuer, mut verifier, _) = pair();
        let bytes = issuer.issue(UID).unwrap().encode();
        assert_eq!(verifier.verify(&[], UID), Err(TicketError::Malformed));
        assert_eq!(
            verifier.verify(&bytes[..TICKET_LEN - 1], UID),
            Err(TicketError::Malformed)
        );
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(verifier.verify(&longer, UID), Err(TicketError::Malformed));
        assert_eq!(
            verifier.verify(&[0xAB; TICKET_LEN], UID),
            Err(TicketError::InvalidMac)
        );
        assert!(Ticket::decode(b"garbage").is_err());
    }

    #[test]
    fn ledger_drops_expired_nonces() {
        let (issuer, mut verifier, clock) = pair();
        for _ in 0..3 {
            verifier
                .verify(&issuer.issue(UID).unwrap().encode(), UID)
                .unwrap();
        }
        assert_eq!(verifier.tracked_nonces(), 3);
        clock.advance(DEFAULT_TTL_MS);
        verifier
            .verify(&issuer.issue(UID).unwrap().encode(), UID)
            .unwrap();
        assert_eq!(verifier.tracked_nonces(), 1);
        clock.advance(DEFAULT_TTL_MS);
        verifier.purge_expired(clock.now_ms());
        assert_eq!(verifier.tracked_nonces(), 0);
    }

    #[test]
    fn debug_output_hides_key_and_ticket_material() {
        let key = TicketKey::from_bytes([0x5A; KEY_LEN]);
        assert_eq!(format!("{key:?}"), "TicketKey(..)");
        let issuer = Issuer::new(key);
        let ticket = issuer.issue(UID).unwrap();
        let shown = format!("{ticket:?}");
        assert!(!shown.contains("nonce") && !shown.contains("mac"));
    }
}
