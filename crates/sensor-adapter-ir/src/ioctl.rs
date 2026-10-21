const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const fn ioc(dir: u32, kind: u8, nr: u8, size: usize) -> libc::c_ulong {
    ((dir << 30) | ((size as u32) << 16) | ((kind as u32) << 8) | nr as u32) as libc::c_ulong
}

pub const fn iowr(kind: u8, nr: u8, size: usize) -> libc::c_ulong {
    ioc(IOC_READ | IOC_WRITE, kind, nr, size)
}

pub const fn iow(kind: u8, nr: u8, size: usize) -> libc::c_ulong {
    ioc(IOC_WRITE, kind, nr, size)
}
