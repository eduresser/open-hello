use std::path::Path;

use crate::emitter_xu::{Emitter, XuTransport, UVC_GET_CUR, UVC_GET_LEN, UVC_GET_MAX, UVC_SET_CUR};
use crate::SensorError;

// MS_CAMERA_CONTROL_XU {0f3f95dc-2632-4c4e-92c9-a04782f43bc8}, in descriptor byte order
const MSXU_GUID: [u8; 16] = [0xdc, 0x95, 0x3f, 0x0f, 0x32, 0x26, 0x4e, 0x4c, 0x92, 0xc9, 0xa0, 0x47, 0x82, 0xf4, 0x3b, 0xc8];
const FACE_AUTH_SELECTOR: u8 = 6;
const ALTERNATING_ILLUMINATION: u8 = 0x02;
const CAPABILITIES_BYTE: usize = 1;
const MODE_BYTE: usize = 2;
const MIN_PAYLOAD_LEN: usize = 3;
const MAX_PAYLOAD_LEN: usize = 64;

const DESCRIPTOR_INTERFACE: u8 = 0x04;
const DESCRIPTOR_CS_INTERFACE: u8 = 0x24;
const SUBTYPE_EXTENSION_UNIT: u8 = 0x06;
const CLASS_VIDEO: u8 = 0x0e;
const SUBCLASS_VIDEO_CONTROL: u8 = 0x01;
const GUID_OFFSET: usize = 4;
const NUM_PINS_OFFSET: usize = 21;
const SOURCES_OFFSET: usize = 22;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsxuUnit {
    pub unit: u8,
    controls: Vec<u8>,
}

impl MsxuUnit {
    pub fn supports(&self, selector: u8) -> bool {
        let bit = usize::from(selector.saturating_sub(1));
        selector > 0 && self.controls.get(bit / 8).is_some_and(|byte| byte & (1 << (bit % 8)) != 0)
    }
}

pub fn find_unit(descriptors: &[u8], video_control_interface: u8) -> Option<MsxuUnit> {
    let mut offset = 0;
    let mut in_target_interface = false;
    while offset + 2 <= descriptors.len() {
        let length = usize::from(descriptors[offset]);
        if length < 2 || offset + length > descriptors.len() {
            return None;
        }
        let descriptor = &descriptors[offset..offset + length];
        match descriptor[1] {
            DESCRIPTOR_INTERFACE if length >= 7 => {
                in_target_interface = descriptor[2] == video_control_interface
                    && descriptor[5] == CLASS_VIDEO
                    && descriptor[6] == SUBCLASS_VIDEO_CONTROL;
            }
            DESCRIPTOR_CS_INTERFACE if in_target_interface && descriptor.get(2) == Some(&SUBTYPE_EXTENSION_UNIT) => {
                if let Some(unit) = parse_extension_unit(descriptor) {
                    return Some(unit);
                }
            }
            _ => {}
        }
        offset += length;
    }
    None
}

fn parse_extension_unit(descriptor: &[u8]) -> Option<MsxuUnit> {
    if descriptor.get(GUID_OFFSET..GUID_OFFSET + 16)? != MSXU_GUID {
        return None;
    }
    let pins = usize::from(*descriptor.get(NUM_PINS_OFFSET)?);
    let control_size_at = SOURCES_OFFSET + pins;
    let control_size = usize::from(*descriptor.get(control_size_at)?);
    let controls = descriptor.get(control_size_at + 1..control_size_at + 1 + control_size)?.to_vec();
    Some(MsxuUnit { unit: descriptor[3], controls })
}

pub fn locate_face_auth_unit(device_path: &str) -> Option<MsxuUnit> {
    let node = Path::new(device_path).file_name()?.to_str()?;
    let interface = std::fs::canonicalize(format!("/sys/class/video4linux/{node}/device")).ok()?;
    let interface_number = interface.file_name()?.to_str()?.rsplit('.').next()?.parse().ok()?;
    let descriptors = std::fs::read(interface.parent()?.join("descriptors")).ok()?;
    find_unit(&descriptors, interface_number).filter(|unit| unit.supports(FACE_AUTH_SELECTOR))
}

pub struct MsxuEmitter<T: XuTransport> {
    transport: T,
    unit: u8,
}

impl<T: XuTransport> MsxuEmitter<T> {
    pub fn new(transport: T, unit: u8) -> Self {
        Self { transport, unit }
    }

    fn read(&mut self, request: u8, length: usize) -> Result<Vec<u8>, SensorError> {
        let mut data = vec![0; length];
        self.transport.query(self.unit, FACE_AUTH_SELECTOR, request, &mut data)?;
        Ok(data)
    }

    fn payload_len(&mut self) -> Result<usize, SensorError> {
        let raw = self.read(UVC_GET_LEN, 2)?;
        let length = usize::from(u16::from_le_bytes([raw[0], raw[1]]));
        if (MIN_PAYLOAD_LEN..=MAX_PAYLOAD_LEN).contains(&length) {
            Ok(length)
        } else {
            Err(SensorError::EmitterActivation(format!("face-auth control reports unexpected length {length}")))
        }
    }

    fn write_alternating(&mut self, mut payload: Vec<u8>) -> Result<(), SensorError> {
        payload[MODE_BYTE] = ALTERNATING_ILLUMINATION;
        self.transport
            .query(self.unit, FACE_AUTH_SELECTOR, UVC_SET_CUR, &mut payload)
            .map_err(|error| SensorError::EmitterWriteRefused(error.to_string()))
    }
}

impl<T: XuTransport> Emitter for MsxuEmitter<T> {
    fn controllable(&self) -> bool {
        true
    }

    fn ensure(&mut self) -> Result<(), SensorError> {
        let length = self.payload_len()?;
        let current = self.read(UVC_GET_CUR, length)?;
        if current[MODE_BYTE] == ALTERNATING_ILLUMINATION {
            return Ok(());
        }
        let maximum = self.read(UVC_GET_MAX, length)?;
        if current[CAPABILITIES_BYTE] & ALTERNATING_ILLUMINATION == 0 || maximum[MODE_BYTE] < ALTERNATING_ILLUMINATION {
            return Err(SensorError::EmitterActivation(
                "camera does not support alternating frame illumination".into(),
            ));
        }
        self.write_alternating(current)?;
        let confirmed = self.read(UVC_GET_CUR, length)?;
        if confirmed[MODE_BYTE] != ALTERNATING_ILLUMINATION {
            return Err(SensorError::EmitterNotConfirmed(confirmed[MODE_BYTE]));
        }
        Ok(())
    }

    fn activate(&mut self) -> Result<(), SensorError> {
        self.ensure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extension_unit(unit: u8, guid: [u8; 16], controls: &[u8]) -> Vec<u8> {
        let mut descriptor = vec![0, DESCRIPTOR_CS_INTERFACE, SUBTYPE_EXTENSION_UNIT, unit];
        descriptor.extend(guid);
        descriptor.extend([controls.len() as u8 * 8, 1, 2, controls.len() as u8]);
        descriptor.extend(controls);
        descriptor.push(0);
        descriptor[0] = descriptor.len() as u8;
        descriptor
    }

    fn interface(number: u8, class: u8, subclass: u8) -> Vec<u8> {
        vec![9, DESCRIPTOR_INTERFACE, number, 0, 0, class, subclass, 0, 0]
    }

    fn camera_descriptors() -> Vec<u8> {
        [
            vec![18; 18],
            interface(0, CLASS_VIDEO, SUBCLASS_VIDEO_CONTROL),
            extension_unit(4, [7; 16], &[0xff]),
            interface(2, CLASS_VIDEO, SUBCLASS_VIDEO_CONTROL),
            extension_unit(4, [7; 16], &[0xff]),
            extension_unit(7, MSXU_GUID, &[0xe6, 0x01, 0x00, 0x00]),
            interface(3, CLASS_VIDEO, 0x02),
        ]
        .concat()
    }

    // @spec:AC-011
    #[test]
    fn finds_the_microsoft_unit_by_guid_on_the_requested_interface() {
        let unit = find_unit(&camera_descriptors(), 2).unwrap();
        assert_eq!(unit.unit, 7);
        let supported: Vec<u8> = (1..=16).filter(|&s| unit.supports(s)).collect();
        assert_eq!(supported, vec![2, 3, 6, 7, 8, 9]);
    }

    // @spec:AC-011
    #[test]
    fn ignores_the_unit_on_other_interfaces_and_other_guids() {
        assert_eq!(find_unit(&camera_descriptors(), 0), None);
        assert_eq!(find_unit(&camera_descriptors(), 3), None);
    }

    #[test]
    fn truncated_descriptors_do_not_panic() {
        let full = camera_descriptors();
        for end in 0..full.len() {
            let _ = find_unit(&full[..end], 2);
        }
        assert_eq!(find_unit(&[], 2), None);
    }

    struct FakeCamera {
        control: Vec<u8>,
        maximum: Vec<u8>,
        writes: Vec<Vec<u8>>,
        ignore_writes: bool,
        refuse_writes: bool,
    }

    impl FakeCamera {
        fn new(control: &[u8], maximum: &[u8]) -> Self {
            Self { control: control.to_vec(), maximum: maximum.to_vec(), writes: Vec::new(), ignore_writes: false, refuse_writes: false }
        }
    }

    impl XuTransport for &mut FakeCamera {
        fn query(&mut self, unit: u8, selector: u8, request: u8, data: &mut [u8]) -> Result<(), SensorError> {
            assert_eq!((unit, selector), (7, FACE_AUTH_SELECTOR));
            match request {
                UVC_GET_LEN => data.copy_from_slice(&(self.control.len() as u16).to_le_bytes()),
                UVC_GET_CUR => data.copy_from_slice(&self.control),
                UVC_GET_MAX => data.copy_from_slice(&self.maximum),
                UVC_SET_CUR => {
                    if self.refuse_writes {
                        return Err(SensorError::EmitterActivation("Input/output error".into()));
                    }
                    self.writes.push(data.to_vec());
                    if !self.ignore_writes {
                        self.control = data.to_vec();
                    }
                }
                other => panic!("unexpected request {other:#x}"),
            }
            Ok(())
        }
    }

    const DEFAULT_CONTROL: [u8; 9] = [1, 3, 2, 0, 0, 0, 0, 0, 0];

    const AMBIENT_CONTROL: [u8; 9] = [1, 3, 1, 0, 0, 0, 0, 0, 0];
    const ALTERNATING_CONTROL: [u8; 9] = [1, 3, 2, 0, 0, 0, 0, 0, 0];

    // @covers:AC-039-write
    #[test]
    fn ensure_writes_alternating_mode_when_the_camera_comes_up_in_mode_1_and_confirms_it() {
        let mut camera = FakeCamera::new(&AMBIENT_CONTROL, &DEFAULT_CONTROL);
        MsxuEmitter::new(&mut camera, 7).ensure().unwrap();
        assert_eq!(camera.writes, vec![ALTERNATING_CONTROL.to_vec()]);
        assert_eq!(camera.control, ALTERNATING_CONTROL.to_vec());
    }

    // @covers:AC-039-no-rewrite
    #[test]
    fn ensure_does_not_write_when_the_mode_is_already_alternating() {
        let mut camera = FakeCamera::new(&ALTERNATING_CONTROL, &DEFAULT_CONTROL);
        MsxuEmitter::new(&mut camera, 7).ensure().unwrap();
        assert!(camera.writes.is_empty());
    }

    // @covers:AC-039-unsupported
    #[test]
    fn unsupported_capability_or_range_is_rejected_before_any_write() {
        let mut no_capability = FakeCamera::new(&[1, 1, 1, 0, 0, 0, 0, 0, 0], &DEFAULT_CONTROL);
        assert!(matches!(MsxuEmitter::new(&mut no_capability, 7).ensure(), Err(SensorError::EmitterActivation(_))));
        assert!(no_capability.writes.is_empty());

        let mut low_maximum = FakeCamera::new(&AMBIENT_CONTROL, &[1, 3, 1, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(MsxuEmitter::new(&mut low_maximum, 7).ensure(), Err(SensorError::EmitterActivation(_))));
        assert!(low_maximum.writes.is_empty());
    }

    // @covers:AC-039-not-confirmed
    #[test]
    fn ensure_fails_when_the_camera_does_not_keep_the_mode() {
        let mut camera = FakeCamera::new(&AMBIENT_CONTROL, &DEFAULT_CONTROL);
        camera.ignore_writes = true;
        let error = MsxuEmitter::new(&mut camera, 7).ensure().unwrap_err();
        assert!(matches!(error, SensorError::EmitterNotConfirmed(1)));
    }

    // @covers:AC-039-refused
    #[test]
    fn ensure_fails_with_a_distinct_error_when_the_write_is_refused() {
        let mut camera = FakeCamera::new(&AMBIENT_CONTROL, &DEFAULT_CONTROL);
        camera.refuse_writes = true;
        let error = MsxuEmitter::new(&mut camera, 7).ensure().unwrap_err();
        assert!(matches!(error, SensorError::EmitterWriteRefused(_)));
        assert!(camera.writes.is_empty());
    }

    #[test]
    fn unexpected_payload_length_is_rejected() {
        let mut camera = FakeCamera::new(&[1, 3], &[1, 3]);
        assert!(MsxuEmitter::new(&mut camera, 7).ensure().is_err());
    }
}
