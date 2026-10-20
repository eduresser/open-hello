use openhello_plugin_abi::{FrameView, SensorHandle, Status};
use sensor_adapter_ir::openhello_sensor_interface;

const DEVICE_ENV: &str = "OPENHELLO_DEVICE";
const FRAMES: usize = 20;
const LIT_MEAN: f64 = 20.0;

fn mean(frame: &FrameView) -> f64 {
    let pixels = unsafe { std::slice::from_raw_parts(frame.data, frame.len) };
    pixels.iter().map(|&p| f64::from(p)).sum::<f64>() / pixels.len() as f64
}

// Needs a physical IR camera: OPENHELLO_DEVICE=/dev/video2 cargo test -p sensor-adapter-ir --test real_camera -- --ignored
#[test]
#[ignore]
fn real_ir_camera_returns_only_lit_frames() {
    let device = std::env::var(DEVICE_ENV).expect("OPENHELLO_DEVICE must point at the IR camera node");
    let path = std::ffi::CString::new(device).unwrap();
    let interface = unsafe { &*openhello_sensor_interface() };
    let mut handle: SensorHandle = std::ptr::null_mut();
    assert_eq!(unsafe { (interface.open)(path.as_ptr(), &mut handle) }, Status::Ok);

    let mut means = Vec::new();
    for _ in 0..FRAMES {
        let mut frame = std::mem::MaybeUninit::<FrameView>::uninit();
        assert_eq!(unsafe { (interface.capture)(handle, frame.as_mut_ptr()) }, Status::Ok);
        means.push(mean(unsafe { &*frame.as_ptr() }));
    }
    unsafe { (interface.close)(handle) };

    println!("frame means: {means:.1?}");
    assert!(means.iter().all(|&m| m >= LIT_MEAN), "unlit frame leaked: {means:?}");
}
