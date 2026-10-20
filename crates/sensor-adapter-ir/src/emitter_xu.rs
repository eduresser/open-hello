use std::os::fd::RawFd;

use crate::SensorError;

const UVC_SET_CUR: u8 = 0x01;
const UVCIOC_CTRL_QUERY: libc::c_ulong = crate::ioctl::iowr(b'u', 0x21, 16);

#[repr(C)]
struct UvcXuControlQuery {
    unit: u8,
    selector: u8,
    query: u8,
    size: u16,
    data: *mut u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitterControl {
    pub unit: u8,
    pub selector: u8,
    pub payload: Vec<u8>,
}

impl EmitterControl {
    pub fn parse(spec: &str) -> Result<Self, SensorError> {
        let invalid = || SensorError::EmitterConfig(format!("expected `unit:selector:hexpayload`, got `{spec}`"));
        let mut parts = spec.split(':');
        let unit = parts.next().and_then(|p| p.parse().ok()).ok_or_else(invalid)?;
        let selector = parts.next().and_then(|p| p.parse().ok()).ok_or_else(invalid)?;
        let payload = decode_hex(parts.next().ok_or_else(invalid)?).ok_or_else(invalid)?;
        if parts.next().is_some() || payload.is_empty() {
            return Err(invalid());
        }
        Ok(Self { unit, selector, payload })
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

pub trait Emitter {
    fn activate(&mut self) -> Result<(), SensorError>;
}

pub struct XuEmitter {
    fd: RawFd,
    control: EmitterControl,
}

impl XuEmitter {
    pub fn new(fd: RawFd, control: EmitterControl) -> Self {
        Self { fd, control }
    }
}

impl Emitter for XuEmitter {
    fn activate(&mut self) -> Result<(), SensorError> {
        let mut payload = self.control.payload.clone();
        let mut query = UvcXuControlQuery {
            unit: self.control.unit,
            selector: self.control.selector,
            query: UVC_SET_CUR,
            size: payload.len() as u16,
            data: payload.as_mut_ptr(),
        };
        let rc = unsafe { libc::ioctl(self.fd, UVCIOC_CTRL_QUERY, &mut query) };
        if rc < 0 {
            return Err(SensorError::EmitterActivation(std::io::Error::last_os_error().to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unit_selector_and_hex_payload() {
        let control = EmitterControl::parse("14:6:01030200").unwrap();
        assert_eq!(control, EmitterControl { unit: 14, selector: 6, payload: vec![1, 3, 2, 0] });
    }

    #[test]
    fn rejects_malformed_specs() {
        for spec in ["", "14:6", "x:6:01", "14:6:0", "14:6:zz", "14:6:01:02", "14:6:"] {
            assert!(EmitterControl::parse(spec).is_err(), "{spec}");
        }
    }

    #[test]
    fn query_struct_matches_kernel_layout() {
        assert_eq!(std::mem::size_of::<UvcXuControlQuery>(), 16);
    }
}
