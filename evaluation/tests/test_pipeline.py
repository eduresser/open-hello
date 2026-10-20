import cv2
import numpy as np

from openhello_eval.pipeline import (
    ALIGNED_SIZE,
    ARCFACE_TEMPLATE,
    DETECTOR_SIZE,
    STRIDES,
    align_face,
    decode_yunet,
    estimate_similarity,
    letterbox,
)


def test_letterbox_fits_the_long_side_and_pads_with_zeros():
    gray = np.full((200, 400), 200, dtype=np.uint8)
    canvas, scale = letterbox(gray)
    assert scale == DETECTOR_SIZE / 400
    assert canvas.shape == (DETECTOR_SIZE, DETECTOR_SIZE)
    assert (canvas[:320, :] == 200).all() and (canvas[320:, :] == 0).all()


def planted_outputs(stride, row, col, score=0.9):
    cells = (DETECTOR_SIZE // stride) ** 2
    outputs = {
        f"cls_{stride}": np.zeros((1, cells, 1), np.float32),
        f"obj_{stride}": np.zeros((1, cells, 1), np.float32),
        f"bbox_{stride}": np.zeros((1, cells, 4), np.float32),
        f"kps_{stride}": np.zeros((1, cells, 10), np.float32),
    }
    idx = row * (DETECTOR_SIZE // stride) + col
    outputs[f"cls_{stride}"][0, idx, 0] = outputs[f"obj_{stride}"][0, idx, 0] = score
    return outputs, idx


def test_decode_yunet_recovers_the_planted_face_and_ignores_empty_cells():
    outputs = {}
    for stride in STRIDES:
        planted, idx_by_stride = planted_outputs(stride, 3, 4, score=0.9 if stride == 16 else 0.0)
        outputs.update(planted)
        if stride == 16:
            idx = idx_by_stride
    outputs["bbox_16"][0, idx] = [0.5, 0.5, np.log(2.0), np.log(2.0)]
    faces = decode_yunet(outputs)
    assert len(faces) == 1
    score, (x, y, w, h), landmarks = faces[0]
    assert abs(score - 0.9) < 1e-6
    assert (x, y, w, h) == (4.5 * 16 - 16, 3.5 * 16 - 16, 32.0, 32.0)
    assert landmarks.shape == (5, 2)


def test_decode_yunet_suppresses_overlapping_duplicates():
    outputs = {}
    for stride in STRIDES:
        outputs.update(planted_outputs(stride, 0, 0, score=0.0)[0])
    for col in (4, 5):
        planted, idx = planted_outputs(16, 3, col)
        outputs["cls_16"][0, idx, 0] = outputs["obj_16"][0, idx, 0] = 0.9 - 0.1 * (col - 4)
        outputs["bbox_16"][0, idx] = [0.0, 0.0, np.log(3.0), np.log(3.0)]
    assert len(decode_yunet(outputs)) == 1


def test_similarity_recovers_a_known_rotation_scale_and_shift():
    angle, scale, shift = np.deg2rad(12), 1.7, np.array([30.0, -8.0])
    rotation = scale * np.array([[np.cos(angle), -np.sin(angle)], [np.sin(angle), np.cos(angle)]])
    source = ((ARCFACE_TEMPLATE - shift) @ np.linalg.inv(rotation).T).astype(np.float32)
    matrix = estimate_similarity(source, ARCFACE_TEMPLATE)
    mapped = source @ matrix[:, :2].T + matrix[:, 2]
    assert np.abs(mapped - ARCFACE_TEMPLATE).max() < 1e-3


def test_aligning_template_shaped_landmarks_reproduces_the_source_crop():
    rng = np.random.default_rng(1)
    face = rng.integers(0, 255, (ALIGNED_SIZE, ALIGNED_SIZE), dtype=np.uint8)
    aligned = align_face(face, ARCFACE_TEMPLATE.copy())
    assert np.abs(aligned.astype(int) - face.astype(int)).max() <= 1
