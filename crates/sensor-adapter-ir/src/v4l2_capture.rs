use std::ffi::CString;
use std::os::fd::RawFd;

use crate::ioctl::{iow, iowr};
use crate::{Frame, FrameSource, SensorError};

const BUF_TYPE_VIDEO_CAPTURE: u32 = 1;
const MEMORY_MMAP: u32 = 1;
const BUFFER_COUNT: u32 = 4;
const BUF_FLAG_ERROR: u32 = 0x40;
const MAX_CONSECUTIVE_BAD_FRAMES: usize = 30;
const FOURCC_GREY: u32 = u32::from_le_bytes(*b"GREY");
const FOURCC_YUYV: u32 = u32::from_le_bytes(*b"YUYV");

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PixFormat {
    width: u32,
    height: u32,
    pixelformat: u32,
    field: u32,
    bytesperline: u32,
    sizeimage: u32,
    colorspace: u32,
    priv_: u32,
    flags: u32,
    ycbcr_enc: u32,
    quantization: u32,
    xfer_func: u32,
}

#[repr(C)]
struct Format {
    type_: u32,
    _align: u32,
    pix: PixFormat,
    _rest: [u8; 152],
}

#[repr(C)]
struct RequestBuffers {
    count: u32,
    type_: u32,
    memory: u32,
    capabilities: u32,
    flags: u8,
    reserved: [u8; 3],
}

#[repr(C)]
struct Timeval {
    sec: i64,
    usec: i64,
}

#[repr(C)]
struct Timecode {
    type_: u32,
    flags: u32,
    frames: u8,
    seconds: u8,
    minutes: u8,
    hours: u8,
    userbits: [u8; 4],
}

#[repr(C)]
struct Buffer {
    index: u32,
    type_: u32,
    bytesused: u32,
    flags: u32,
    field: u32,
    timestamp: Timeval,
    timecode: Timecode,
    sequence: u32,
    memory: u32,
    offset: u64,
    length: u32,
    reserved2: u32,
    request_fd: u32,
}

const VIDIOC_S_FMT: libc::c_ulong = iowr(b'V', 5, std::mem::size_of::<Format>());
const VIDIOC_REQBUFS: libc::c_ulong = iowr(b'V', 8, std::mem::size_of::<RequestBuffers>());
const VIDIOC_QUERYBUF: libc::c_ulong = iowr(b'V', 9, std::mem::size_of::<Buffer>());
const VIDIOC_QBUF: libc::c_ulong = iowr(b'V', 15, std::mem::size_of::<Buffer>());
const VIDIOC_DQBUF: libc::c_ulong = iowr(b'V', 17, std::mem::size_of::<Buffer>());
const VIDIOC_STREAMON: libc::c_ulong = iow(b'V', 18, std::mem::size_of::<i32>());
const VIDIOC_STREAMOFF: libc::c_ulong = iow(b'V', 19, std::mem::size_of::<i32>());

struct MappedBuffer {
    ptr: *mut u8,
    len: usize,
}

pub struct V4l2Camera {
    fd: RawFd,
    buffers: Vec<MappedBuffer>,
    format: PixFormat,
    streaming: bool,
}

// The mmap'd buffers are only touched through &mut self, and the camera lives behind a Mutex
unsafe impl Send for V4l2Camera {}

fn os_error(context: &str) -> SensorError {
    let error = std::io::Error::last_os_error();
    let detail = format!("{context}: {error}");
    match error.raw_os_error() {
        Some(libc::EBUSY) => SensorError::DeviceBusy(detail),
        Some(libc::ENOENT | libc::ENODEV) => SensorError::NoDevice(detail),
        _ => SensorError::Device(detail),
    }
}

fn zeroed<T>() -> T {
    unsafe { std::mem::zeroed() }
}

impl V4l2Camera {
    pub fn open(device_path: &str) -> Result<Self, SensorError> {
        let mut camera = Self::open_configured(device_path)?;
        camera.map_buffers()?;
        Ok(camera)
    }

    pub fn probe(device_path: &str) -> Result<(), SensorError> {
        Self::open_configured(device_path).map(drop)
    }

    fn open_configured(device_path: &str) -> Result<Self, SensorError> {
        let path = CString::new(device_path)
            .map_err(|_| SensorError::Device(format!("invalid device path `{device_path}`")))?;
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return Err(os_error(&format!("open {device_path}")));
        }
        let mut camera = Self { fd, buffers: Vec::new(), format: PixFormat::default(), streaming: false };
        camera.negotiate_format()?;
        Ok(camera)
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }

    fn negotiate_format(&mut self) -> Result<(), SensorError> {
        let mut format: Format = zeroed();
        format.type_ = BUF_TYPE_VIDEO_CAPTURE;
        format.pix.pixelformat = FOURCC_GREY;
        if unsafe { libc::ioctl(self.fd, VIDIOC_S_FMT, &mut format) } < 0 {
            return Err(os_error("VIDIOC_S_FMT"));
        }
        match format.pix.pixelformat {
            FOURCC_GREY | FOURCC_YUYV => {
                self.format = format.pix;
                Ok(())
            }
            other => Err(SensorError::Device(format!(
                "unsupported pixel format {:?}",
                other.to_le_bytes().map(char::from)
            ))),
        }
    }

    fn map_buffers(&mut self) -> Result<(), SensorError> {
        let mut request: RequestBuffers = zeroed();
        request.count = BUFFER_COUNT;
        request.type_ = BUF_TYPE_VIDEO_CAPTURE;
        request.memory = MEMORY_MMAP;
        if unsafe { libc::ioctl(self.fd, VIDIOC_REQBUFS, &mut request) } < 0 {
            return Err(os_error("VIDIOC_REQBUFS"));
        }
        for index in 0..request.count {
            let mut buffer: Buffer = zeroed();
            buffer.index = index;
            buffer.type_ = BUF_TYPE_VIDEO_CAPTURE;
            buffer.memory = MEMORY_MMAP;
            if unsafe { libc::ioctl(self.fd, VIDIOC_QUERYBUF, &mut buffer) } < 0 {
                return Err(os_error("VIDIOC_QUERYBUF"));
            }
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    buffer.length as usize,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    self.fd,
                    buffer.offset as libc::off_t,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(os_error("mmap"));
            }
            self.buffers.push(MappedBuffer { ptr: ptr as *mut u8, len: buffer.length as usize });
            self.enqueue(index)?;
        }
        Ok(())
    }

    fn enqueue(&self, index: u32) -> Result<(), SensorError> {
        let mut buffer: Buffer = zeroed();
        buffer.index = index;
        buffer.type_ = BUF_TYPE_VIDEO_CAPTURE;
        buffer.memory = MEMORY_MMAP;
        if unsafe { libc::ioctl(self.fd, VIDIOC_QBUF, &mut buffer) } < 0 {
            return Err(os_error("VIDIOC_QBUF"));
        }
        Ok(())
    }

    fn luma(&self, raw: &[u8]) -> Vec<u8> {
        let width = self.format.width as usize;
        let height = self.format.height as usize;
        let stride = self.format.bytesperline as usize;
        let step = if self.format.pixelformat == FOURCC_YUYV { 2 } else { 1 };
        let mut out = Vec::with_capacity(width * height);
        for row in raw.chunks(stride).take(height) {
            out.extend(row.iter().step_by(step).take(width));
        }
        out
    }
}

impl FrameSource for V4l2Camera {
    fn start(&mut self) -> Result<(), SensorError> {
        let mut kind = BUF_TYPE_VIDEO_CAPTURE as i32;
        if unsafe { libc::ioctl(self.fd, VIDIOC_STREAMON, &mut kind) } < 0 {
            return Err(os_error("VIDIOC_STREAMON"));
        }
        self.streaming = true;
        Ok(())
    }

    fn next_frame(&mut self) -> Result<Frame, SensorError> {
        for _ in 0..MAX_CONSECUTIVE_BAD_FRAMES {
            let mut buffer: Buffer = zeroed();
            buffer.type_ = BUF_TYPE_VIDEO_CAPTURE;
            buffer.memory = MEMORY_MMAP;
            if unsafe { libc::ioctl(self.fd, VIDIOC_DQBUF, &mut buffer) } < 0 {
                return Err(os_error("VIDIOC_DQBUF"));
            }
            let complete = is_complete(buffer.bytesused, buffer.flags, self.format.sizeimage);
            let mapped = &self.buffers[buffer.index as usize];
            let frame = complete.then(|| {
                let raw = unsafe { std::slice::from_raw_parts(mapped.ptr, (buffer.bytesused as usize).min(mapped.len)) };
                Frame {
                    width: self.format.width,
                    height: self.format.height,
                    pixels: self.luma(raw),
                    timestamp_us: buffer.timestamp.sec as u64 * 1_000_000 + buffer.timestamp.usec as u64,
                }
            });
            self.enqueue(buffer.index)?;
            if let Some(frame) = frame {
                return Ok(frame);
            }
        }
        Err(SensorError::Device("camera keeps delivering incomplete frames".into()))
    }
}

// USB cameras occasionally deliver a short frame; the engine rejects it and would abort the session
fn is_complete(bytes_used: u32, flags: u32, size_image: u32) -> bool {
    flags & BUF_FLAG_ERROR == 0 && bytes_used == size_image
}

impl Drop for V4l2Camera {
    fn drop(&mut self) {
        unsafe {
            if self.streaming {
                let mut kind = BUF_TYPE_VIDEO_CAPTURE as i32;
                libc::ioctl(self.fd, VIDIOC_STREAMOFF, &mut kind);
            }
            for mapped in &self.buffers {
                libc::munmap(mapped.ptr as *mut libc::c_void, mapped.len);
            }
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structs_match_kernel_abi_sizes() {
        assert_eq!(std::mem::size_of::<Format>(), 208);
        assert_eq!(std::mem::size_of::<RequestBuffers>(), 20);
        assert_eq!(std::mem::size_of::<Buffer>(), 88);
    }

    #[test]
    fn errno_decides_between_busy_missing_and_generic_device_errors() {
        let with_errno = |code: i32| {
            unsafe { *libc::__errno_location() = code };
            os_error("open")
        };
        assert!(matches!(with_errno(libc::EBUSY), SensorError::DeviceBusy(_)));
        assert!(matches!(with_errno(libc::ENOENT), SensorError::NoDevice(_)));
        assert!(matches!(with_errno(libc::ENODEV), SensorError::NoDevice(_)));
        assert!(matches!(with_errno(libc::EIO), SensorError::Device(_)));
    }

    #[test]
    fn only_full_error_free_buffers_count_as_frames() {
        assert!(is_complete(230_400, 0, 230_400));
        assert!(!is_complete(125_524, 0, 230_400));
        assert!(!is_complete(230_400, BUF_FLAG_ERROR, 230_400));
        assert!(!is_complete(0, 0, 230_400));
    }

    #[test]
    fn open_reports_missing_device() {
        let error = V4l2Camera::open("/dev/openhello-no-such-camera").err().unwrap();
        assert!(matches!(error, SensorError::NoDevice(_)));
    }

    // @spec:AC-070
    #[test]
    fn probe_reports_a_missing_device_without_streaming() {
        let error = V4l2Camera::probe("/dev/openhello-no-such-camera").unwrap_err();
        assert!(matches!(error, SensorError::NoDevice(_)));
    }
}
