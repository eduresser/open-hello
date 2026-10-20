import math
import struct
from dataclasses import dataclass

import numpy as np

MAGIC = b"OHC2"
BODY_LEVELS = 64
SHAPE_EPSILON = 1e-9


@dataclass(frozen=True)
class Calibration:
    samples: int
    tail_far: float
    tail_score: float
    shape: float
    scale: float
    body_far: np.ndarray
    body_score: np.ndarray

    @classmethod
    def from_bytes(cls, data):
        expected = 4 + 8 + 4 * 8 + 4 + BODY_LEVELS * 16
        if len(data) != expected or data[:4] != MAGIC:
            raise ValueError("not an OHC2 calibration file; regenerate it with openhello-calibrate")
        samples = struct.unpack_from("<Q", data, 4)[0]
        tail_far, tail_score, shape, scale = struct.unpack_from("<4d", data, 12)
        levels = struct.unpack_from("<I", data, 44)[0]
        if levels != BODY_LEVELS:
            raise ValueError("calibration body table has the wrong size")
        table = np.frombuffer(data, dtype="<f8", count=levels * 2, offset=48).reshape(levels, 2)
        return cls(samples, tail_far, tail_score, shape, scale, table[:, 0].copy(), table[:, 1].copy())

    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as handle:
            return cls.from_bytes(handle.read())

    def threshold(self, far):
        if not 0.0 < far < 1.0:
            raise ValueError(f"target FAR must be in (0, 1), got {far}")
        if far < self.tail_far:
            ratio = far / self.tail_far
            if self.shape < SHAPE_EPSILON:
                excess = -math.log(ratio)
            else:
                excess = (ratio ** -self.shape - 1.0) / self.shape
            return self.tail_score + self.scale * excess
        if far >= self.body_far[0]:
            return float(self.body_score[0])
        log_far = np.log(self.body_far)
        return float(np.interp(math.log(far), log_far[::-1], self.body_score[::-1]))

    def far_at(self, score):
        if score > self.tail_score:
            z = (score - self.tail_score) / self.scale
            ratio = math.exp(-z) if self.shape < SHAPE_EPSILON else (1.0 + self.shape * z) ** (-1.0 / self.shape)
            return self.tail_far * ratio
        if score <= self.body_score[0]:
            return float(self.body_far[0])
        return float(np.exp(np.interp(score, self.body_score, np.log(self.body_far))))
