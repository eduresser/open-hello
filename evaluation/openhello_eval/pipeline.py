from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

DETECTOR_SIZE = 640
STRIDES = (8, 16, 32)
SCORE_THRESHOLD = 0.6
NMS_IOU_THRESHOLD = 0.3
ALIGNED_SIZE = 112
ARCFACE_TEMPLATE = np.array(
    [(38.2946, 51.6963), (73.5318, 51.5014), (56.0252, 71.7366), (41.5493, 92.3655), (70.7299, 92.2041)],
    dtype=np.float32,
)


def letterbox(gray):
    height, width = gray.shape
    scale = min(DETECTOR_SIZE / width, DETECTOR_SIZE / height)
    fit_w, fit_h = int(width * scale), int(height * scale)
    xs = (np.arange(fit_w, dtype=np.float32) + 0.5) / scale - 0.5
    ys = (np.arange(fit_h, dtype=np.float32) + 0.5) / scale - 0.5
    map_x, map_y = np.meshgrid(xs, ys)
    resized = cv2.remap(gray, map_x, map_y, cv2.INTER_LINEAR, borderMode=cv2.BORDER_REPLICATE)
    canvas = np.zeros((DETECTOR_SIZE, DETECTOR_SIZE), dtype=np.uint8)
    canvas[:fit_h, :fit_w] = resized
    return canvas, scale


def _iou(a, b):
    left, top = max(a[0], b[0]), max(a[1], b[1])
    right, bottom = min(a[0] + a[2], b[0] + b[2]), min(a[1] + a[3], b[1] + b[3])
    intersection = max(right - left, 0.0) * max(bottom - top, 0.0)
    union = a[2] * a[3] + b[2] * b[3] - intersection
    return intersection / union if union > 0 else 0.0


def decode_yunet(outputs):
    candidates = []
    for stride in STRIDES:
        cls = np.clip(outputs[f"cls_{stride}"].reshape(-1), 0, 1)
        obj = np.clip(outputs[f"obj_{stride}"].reshape(-1), 0, 1)
        bbox = outputs[f"bbox_{stride}"].reshape(-1, 4)
        kps = outputs[f"kps_{stride}"].reshape(-1, 10)
        cols = DETECTOR_SIZE // stride
        score = np.sqrt(cls * obj)
        for idx in np.nonzero(score >= SCORE_THRESHOLD)[0]:
            row, col = divmod(int(idx), cols)
            b = bbox[idx]
            cx, cy = (col + b[0]) * stride, (row + b[1]) * stride
            w, h = np.exp(b[2]) * stride, np.exp(b[3]) * stride
            points = np.stack([(kps[idx, 0::2] + col) * stride, (kps[idx, 1::2] + row) * stride], axis=1)
            candidates.append((float(score[idx]), (cx - w / 2, cy - h / 2, w, h), points.astype(np.float32)))
    candidates.sort(key=lambda c: -c[0])
    kept = []
    for candidate in candidates:
        if all(_iou(k[1], candidate[1]) < NMS_IOU_THRESHOLD for k in kept):
            kept.append(candidate)
    return kept


def estimate_similarity(source, target):
    source_center, target_center = source.mean(axis=0), target.mean(axis=0)
    s, t = source - source_center, target - target_center
    cos_part = float((s * t).sum())
    sin_part = float((s[:, 0] * t[:, 1] - s[:, 1] * t[:, 0]).sum())
    denominator = float((s * s).sum())
    a, b = cos_part / denominator, sin_part / denominator
    tx = target_center[0] - (a * source_center[0] - b * source_center[1])
    ty = target_center[1] - (b * source_center[0] + a * source_center[1])
    return np.array([[a, -b, tx], [b, a, ty]], dtype=np.float64)


def align_face(gray, landmarks):
    forward = estimate_similarity(landmarks, ARCFACE_TEMPLATE)
    inverse = cv2.invertAffineTransform(forward)
    xs, ys = np.meshgrid(np.arange(ALIGNED_SIZE, dtype=np.float64), np.arange(ALIGNED_SIZE, dtype=np.float64))
    map_x = inverse[0, 0] * xs + inverse[0, 1] * ys + inverse[0, 2]
    map_y = inverse[1, 0] * xs + inverse[1, 1] * ys + inverse[1, 2]
    return cv2.remap(gray, map_x.astype(np.float32), map_y.astype(np.float32), cv2.INTER_LINEAR, borderMode=cv2.BORDER_REPLICATE)


class Pipeline:
    def __init__(self, models_dir):
        models = Path(models_dir)
        self.detector = ort.InferenceSession(str(models / "yunet.onnx"), providers=["CPUExecutionProvider"])
        self.embedder = ort.InferenceSession(str(models / "glintr100.onnx"), providers=["CPUExecutionProvider"])

    def align(self, path):
        gray = cv2.imread(str(path), cv2.IMREAD_GRAYSCALE)
        if gray is None:
            return None
        canvas, scale = letterbox(gray)
        planes = np.repeat(canvas[None, None].astype(np.float32), 3, axis=1)
        names = [o.name for o in self.detector.get_outputs()]
        outputs = dict(zip(names, self.detector.run(names, {"input": planes})))
        faces = decode_yunet(outputs)
        if not faces:
            return None
        landmarks = faces[0][2] / scale
        return align_face(gray, landmarks)

    def embed_aligned(self, aligned_faces):
        batch = np.stack(aligned_faces).astype(np.float32)
        batch = np.repeat(((batch - 127.5) / 127.5)[:, None], 3, axis=1)
        vectors = self.embedder.run(None, {"data": batch})[0]
        return vectors / np.linalg.norm(vectors, axis=1, keepdims=True)

    def embed_all(self, paths, batch_size=32, progress=None):
        embeddings = np.zeros((len(paths), 512), dtype=np.float32)
        valid = np.zeros(len(paths), dtype=bool)
        pending, rows = [], []

        def flush():
            if pending:
                embeddings[rows] = self.embed_aligned(pending)
                pending.clear()
                rows.clear()

        for row, path in enumerate(paths):
            aligned = self.align(path)
            if aligned is not None:
                pending.append(aligned)
                rows.append(row)
                valid[row] = True
                if len(pending) == batch_size:
                    flush()
            if progress and (row + 1) % 500 == 0:
                progress(row + 1, len(paths))
        flush()
        return embeddings, valid
