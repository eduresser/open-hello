#[path = "../../../tests/support/frame_fixtures.rs"]
mod frame_fixtures;

use engine_adapter_face::GrayImage;
use frame_fixtures::*;

fn frame(seed: u8) -> FixtureFrame {
    FixtureFrame { width: 4, height: 3, pixels: (0..12).map(|i| i * 3 + seed).collect() }
}

#[test]
fn pgm_round_trips_and_converts_to_engine_images() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("001.pgm");
    write_pgm(&path, &frame(7)).unwrap();
    let loaded = read_pgm(&path).unwrap();
    assert_eq!(loaded, frame(7));
    let image = GrayImage::new(loaded.width, loaded.height, loaded.pixels).unwrap();
    assert_eq!(image.at(3, 2), 40.0);
}

#[test]
fn identities_load_sorted_with_their_frames_in_order() {
    let root = tempfile::tempdir().unwrap();
    for (name, seeds) in [("bruno", vec![1u8, 2]), ("ana", vec![3u8, 4, 5])] {
        let dir = root.path().join(name);
        std::fs::create_dir(&dir).unwrap();
        for (i, seed) in seeds.iter().enumerate() {
            write_pgm(&dir.join(format!("{i:03}.pgm")), &frame(*seed)).unwrap();
        }
    }
    let identities = load_all_identities(root.path()).unwrap();
    assert_eq!(identities.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), vec!["ana", "bruno"]);
    assert_eq!(identities[0].frames, vec![frame(3), frame(4), frame(5)]);
}

#[test]
fn malformed_fixtures_report_the_offending_file() {
    let dir = tempfile::tempdir().unwrap();
    let bad_magic = dir.path().join("a.pgm");
    std::fs::write(&bad_magic, b"P6\n1 1\n255\n\0").unwrap();
    assert!(read_pgm(&bad_magic).unwrap_err().contains("not a binary PGM"));

    let truncated = dir.path().join("b.pgm");
    std::fs::write(&truncated, b"P5\n4 3\n255\n\0\0").unwrap();
    assert!(read_pgm(&truncated).unwrap_err().contains("expected 12 pixel bytes"));

    let sixteen_bit = dir.path().join("c.pgm");
    std::fs::write(&sixteen_bit, b"P5\n1 1\n65535\n\0\0").unwrap();
    assert!(read_pgm(&sixteen_bit).unwrap_err().contains("8-bit"));

    assert!(load_identity(dir.path()).is_ok() == false);
    let empty = tempfile::tempdir().unwrap();
    assert!(load_identity(empty.path()).unwrap_err().contains("no .pgm frames"));
    assert!(read_pgm(&dir.path().join("missing.pgm")).is_err());
}
