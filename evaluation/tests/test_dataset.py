from openhello_eval.dataset import link_strangers, list_identities, split_identities, prepare_cbsr_nir


def make_people(root, counts):
    for name, count in counts.items():
        (root / name).mkdir()
        for i in range(count):
            (root / name / f"{i:02d}.jpg").write_bytes(b"x")
        (root / name / "notes.txt").write_text("ignored")


def test_identities_with_enough_photos_are_enrolled_and_the_rest_are_strangers(tmp_path):
    make_people(tmp_path, {"amy": 6, "bob": 2, "cat": 5, "dan": 1})
    people = list_identities(tmp_path)
    assert list(people) == ["amy", "bob", "cat", "dan"]
    assert all(p.suffix == ".jpg" for photos in people.values() for p in photos)
    enrolled, strangers = split_identities(people, enroll_shots=3, max_eval=10, max_calibration=10)
    assert (enrolled, strangers) == (["amy", "cat"], ["bob", "dan"])


def test_limits_cap_each_group(tmp_path):
    make_people(tmp_path, {"a": 6, "b": 6, "c": 1, "d": 1})
    enrolled, strangers = split_identities(list_identities(tmp_path), 3, max_eval=1, max_calibration=1)
    assert (enrolled, strangers) == (["a"], ["c"])


def test_link_strangers_points_at_the_original_identity_folder(tmp_path):
    source, out = tmp_path / "people", tmp_path / "linked"
    source.mkdir()
    make_people(source, {"bob": 2})
    link_strangers(source, ["bob"], out)
    link_strangers(source, ["bob"], out)
    assert sorted(p.name for p in (out / "bob").iterdir() if p.suffix == ".jpg") == ["00.jpg", "01.jpg"]


def test_cbsr_bmp_files_are_grouped_by_person_and_converted_to_png(tmp_path):
    import cv2
    import numpy as np

    source = tmp_path / "cbsr" / "gallery"
    source.mkdir(parents=True)
    for name in ("0001-00-a.bmp", "0001-01-a-g.bmp", "0002-00-a.bmp"):
        cv2.imwrite(str(source / name), np.full((8, 8), 50, np.uint8))
    (source / "gallery-groundtruth.txt").write_text("not an image")
    counts = prepare_cbsr_nir(tmp_path / "cbsr", tmp_path / "people")
    assert dict(counts) == {"0001": 2, "0002": 1}
    assert sorted(p.name for p in (tmp_path / "people" / "0001").iterdir()) == ["0001-00-a.png", "0001-01-a-g.png"]
    assert list_identities(tmp_path / "people").keys() == {"0001", "0002"}
