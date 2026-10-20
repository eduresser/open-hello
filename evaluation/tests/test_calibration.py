import json
import math
from pathlib import Path

import pytest

from openhello_eval.calibration import Calibration

GOLDEN = Path(__file__).resolve().parents[2] / "crates/engine-adapter-face/tests/fixtures/calibration_golden.json"


@pytest.fixture(scope="module")
def golden():
    return json.loads(GOLDEN.read_text())


@pytest.fixture(scope="module")
def calibration(golden):
    return Calibration.from_bytes(bytes.fromhex(golden["calibration_hex"]))


def test_thresholds_match_the_rust_implementation(golden, calibration):
    for far, expected in zip(golden["target_fars"], golden["thresholds"]):
        assert calibration.threshold(far) == pytest.approx(expected, abs=1e-9), far


def test_far_at_matches_the_rust_implementation(golden, calibration):
    for score, expected in zip(golden["scores"], golden["far_at_scores"]):
        assert calibration.far_at(score) == pytest.approx(expected, rel=1e-9), score


def test_far_at_inverts_threshold(calibration):
    for far in (0.4, 0.1, 1e-2, 1e-3, 1e-5, 1e-7):
        assert calibration.far_at(calibration.threshold(far)) == pytest.approx(far, rel=1e-6)


def test_rejects_invalid_far_and_foreign_files(calibration):
    for far in (0.0, 1.0, -1e-3):
        with pytest.raises(ValueError):
            calibration.threshold(far)
    with pytest.raises(ValueError):
        Calibration.from_bytes(b"\x00" * 24)
    with pytest.raises(ValueError):
        Calibration.from_bytes(b"XXXX" + bytes.fromhex(json.loads(GOLDEN.read_text())["calibration_hex"])[4:])


def test_stricter_far_never_lowers_the_threshold(calibration):
    thresholds = [calibration.threshold(10.0 ** -exp) for exp in range(1, 10)]
    assert all(b > a for a, b in zip(thresholds, thresholds[1:]))
    assert all(math.isfinite(t) for t in thresholds)
