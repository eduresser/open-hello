import json

import numpy as np

from openhello_eval.calibration import Calibration
from openhello_eval.dataset import list_identities
from openhello_eval.workflow import Run, save_embeddings
from tests.test_calibration import GOLDEN


def unit(vectors):
    return vectors / np.linalg.norm(vectors, axis=1, keepdims=True)


def make_gallery(root, enrolled, strangers):
    rng = np.random.default_rng(2)
    rows = []
    for index, (name, count) in enumerate([(f"e{i}", 6) for i in range(enrolled)] + [(f"s{i}", 1) for i in range(strangers)]):
        (root / name).mkdir()
        center = unit(rng.normal(size=(1, 512)))
        for photo in range(count):
            (root / name / f"{photo:04d}.jpg").write_bytes(b"x")
            rows.append(unit(center + 0.02 * rng.normal(size=(1, 512)))[0])
    return np.array(rows, dtype=np.float32)


def test_embeddings_are_found_even_when_the_image_folder_moves(tmp_path):
    original, moved = tmp_path / "original", tmp_path / "moved"
    original.mkdir()
    embeddings = make_gallery(original, enrolled=4, strangers=3)
    save_embeddings(tmp_path / "emb.npz", list_identities(original), embeddings, np.ones(len(embeddings), dtype=bool))
    original.rename(moved)
    run = Run(moved, tmp_path / "emb.npz", enroll_shots=3, max_eval=10, max_calibration=10)
    assert [e.name for e in run.enrolled()] == ["e0", "e1", "e2", "e3"]
    assert len(run.stranger_embeddings()) == 3


def test_photos_without_a_face_are_left_out_of_templates_and_probes(tmp_path):
    images = tmp_path / "images"
    images.mkdir()
    embeddings = make_gallery(images, enrolled=2, strangers=1)
    valid = np.ones(len(embeddings), dtype=bool)
    valid[0] = False
    save_embeddings(tmp_path / "emb.npz", list_identities(images), embeddings, valid)
    run = Run(images, tmp_path / "emb.npz", enroll_shots=3, max_eval=10, max_calibration=10)
    first = run.enrolled()[0]
    assert len(first.shots) == 2 and len(first.probes) == 3


def test_report_runs_end_to_end_on_a_small_gallery(tmp_path):
    images = tmp_path / "images"
    images.mkdir()
    embeddings = make_gallery(images, enrolled=5, strangers=4)
    save_embeddings(tmp_path / "emb.npz", list_identities(images), embeddings, np.ones(len(embeddings), dtype=bool))
    run = Run(images, tmp_path / "emb.npz", enroll_shots=3, max_eval=10, max_calibration=10)
    calibration = Calibration.from_bytes(bytes.fromhex(json.loads(GOLDEN.read_text())["calibration_hex"]))
    result = run.report(calibration, target_fars=(1e-2,))
    assert result["people"] == 5
    assert result["verify"][0]["genuine_accept"] == 1.0
    assert result["identify"][0]["strangers"] == 4
