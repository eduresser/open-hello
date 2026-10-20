from pathlib import Path

import numpy as np

from .calibration import Calibration
from .dataset import list_identities, split_identities
from .metrics import build_enrolled, evaluate

PARITY_TOLERANCE = 0.02


def photo_key(path):
    path = Path(path)
    return f"{path.parent.name}/{path.name}"


def save_embeddings(path, people, embeddings, valid):
    paths = [photo_key(p) for photos in people.values() for p in photos]
    np.savez_compressed(path, embeddings=embeddings, valid=valid, paths=np.array(paths))


def load_embeddings(path):
    data = np.load(path, allow_pickle=False)
    return data["embeddings"], data["valid"], [photo_key(p) for p in data["paths"]]


class Run:
    def __init__(self, images_dir, embeddings_path, enroll_shots=3, max_eval=300, max_calibration=600):
        self.people = list_identities(images_dir)
        self.embeddings, self.valid, paths = load_embeddings(embeddings_path)
        self.rows = {key: i for i, key in enumerate(paths)}
        self.enroll_shots = enroll_shots
        self.enrolled_names, self.stranger_names = split_identities(self.people, enroll_shots, max_eval, max_calibration)

    def stranger_embeddings(self):
        rows = [self.rows[photo_key(self.people[name][0])] for name in self.stranger_names]
        return self.embeddings[[r for r in rows if self.valid[r]]]

    def enrolled(self):
        return build_enrolled(self.enrolled_names, self.people, self.embeddings, self.valid, self.enroll_shots, self.rows)

    def report(self, calibration, target_fars=None):
        kwargs = {} if target_fars is None else {"target_fars": target_fars}
        return evaluate(self.enrolled(), self.stranger_embeddings(), calibration, **kwargs)

    def parity(self, calibration):
        strangers = self.stranger_embeddings()
        scores = np.sort((strangers @ strangers.T)[np.triu_indices(len(strangers), k=1)])
        n = len(scores)
        indices = np.minimum(((1.0 - calibration.body_far) * n).astype(int), n - 1)
        expected = np.minimum(scores[indices], calibration.tail_score)
        difference = np.abs(expected - calibration.body_score)
        difference[-1] = abs(scores[n - int(round(calibration.tail_far * n)) - 1] - calibration.tail_score)
        return {
            "pairs_python": n,
            "pairs_rust": calibration.samples,
            "max_quantile_difference": float(difference.max()),
            "ok": n == calibration.samples and float(difference.max()) <= PARITY_TOLERANCE,
        }
