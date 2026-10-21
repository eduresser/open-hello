import numpy as np
import pytest

from openhello_eval.calibration import Calibration
from openhello_eval.metrics import Enrolled, equal_error_rate, evaluate, score_matrices

from tests.test_calibration import GOLDEN
import json


def unit(vectors):
    return vectors / np.linalg.norm(vectors, axis=1, keepdims=True)


def people(count, shots, probes, noise, seed=0, dim=512):
    rng = np.random.default_rng(seed)
    centers = unit(rng.normal(size=(count, dim)))
    return [
        Enrolled(f"p{i}", unit(centers[i] + noise * rng.normal(size=(shots, dim))), unit(centers[i] + noise * rng.normal(size=(probes, dim))))
        for i in range(count)
    ], centers, rng


@pytest.fixture(scope="module")
def calibration():
    return Calibration.from_bytes(bytes.fromhex(json.loads(GOLDEN.read_text())["calibration_hex"]))


def test_best_score_per_person_is_the_max_over_that_persons_shots():
    a = Enrolled("a", np.array([[1.0, 0, 0], [0, 1.0, 0]]), np.array([[0, 1.0, 0]]))
    b = Enrolled("b", np.array([[0, 0, 1.0]]), np.array([[0, 0, 1.0]]))
    best, owner, lengths = score_matrices([a, b])
    assert best.tolist() == [[1.0, 0.0], [0.0, 1.0]]
    assert owner.tolist() == [0, 1]
    assert lengths.tolist() == [2, 1]


def test_equal_error_rate_is_zero_for_separable_scores_and_half_for_identical():
    assert equal_error_rate(np.array([0.8, 0.9]), np.array([0.1, 0.2]))[0] == 0.0
    assert equal_error_rate(np.array([0.5] * 10), np.array([0.5] * 10))[0] == pytest.approx(0.5)


def test_clean_identities_are_verified_and_identified(calibration):
    enrolled, _, rng = people(count=12, shots=3, probes=4, noise=0.02)
    strangers = unit(rng.normal(size=(40, 512)))
    result = evaluate(enrolled, strangers, calibration, target_fars=(1e-2, 1e-3))
    assert result["eer"] == 0.0
    assert all(row["genuine_accept"] == 1.0 and row["measured_far"] == 0.0 for row in result["verify"])
    assert all(row["correct"] == 1.0 and row["wrong_person"] == 0.0 for row in result["identify"])
    assert result["verify"][0]["impostor_comparisons"] == 12 * 4 * 11


def test_noisy_identities_overlap_and_are_reported_honestly(calibration):
    enrolled, _, rng = people(count=12, shots=3, probes=4, noise=2.0, seed=3)
    result = evaluate(enrolled, unit(rng.normal(size=(40, 512))), calibration, target_fars=(1e-2,))
    assert result["verify"][0]["genuine_accept"] < 1.0
    assert result["identify"][0]["correct"] < 1.0


def test_stricter_far_trades_genuine_accepts_for_fewer_false_accepts(calibration):
    enrolled, _, rng = people(count=15, shots=3, probes=6, noise=0.9, seed=5)
    result = evaluate(enrolled, unit(rng.normal(size=(40, 512))), calibration, target_fars=(1e-2, 1e-5))
    lenient, strict = result["verify"]
    assert strict["genuine_accept"] <= lenient["genuine_accept"]
    assert strict["measured_far"] <= lenient["measured_far"]
