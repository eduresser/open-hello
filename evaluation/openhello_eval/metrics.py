from dataclasses import dataclass

import numpy as np

DEFAULT_TARGET_FARS = (1e-2, 1e-3, 1e-4, 1e-5)


@dataclass
class Enrolled:
    name: str
    shots: np.ndarray
    probes: np.ndarray


def build_enrolled(names, people, embeddings, valid, enroll_shots, rows_by_photo):
    enrolled = []
    for name in names:
        rows = [rows_by_photo[f"{path.parent.name}/{path.name}"] for path in people[name]]
        shot_rows, probe_rows = rows[:enroll_shots], rows[enroll_shots:]
        shots = embeddings[[r for r in shot_rows if valid[r]]]
        probes = embeddings[[r for r in probe_rows if valid[r]]]
        if len(shots) and len(probes):
            enrolled.append(Enrolled(name, shots, probes))
    return enrolled


def score_matrices(enrolled):
    gallery = np.concatenate([e.shots for e in enrolled])
    starts = np.cumsum([0] + [len(e.shots) for e in enrolled[:-1]])
    probes = np.concatenate([e.probes for e in enrolled])
    probe_owner = np.repeat(np.arange(len(enrolled)), [len(e.probes) for e in enrolled])
    best = np.maximum.reduceat(probes @ gallery.T, starts, axis=1)
    return best, probe_owner, np.array([len(e.shots) for e in enrolled])


def equal_error_rate(genuine, impostor):
    thresholds = np.unique(np.concatenate([genuine, impostor]))
    if len(thresholds) > 4000:
        thresholds = thresholds[:: len(thresholds) // 4000]
    frr = np.array([(genuine < t).mean() for t in thresholds])
    far = np.array([(impostor >= t).mean() for t in thresholds])
    index = int(np.argmin(np.abs(frr - far)))
    return float((frr[index] + far[index]) / 2), float(thresholds[index])


def verify_table(best, probe_owner, template_lengths, calibration, target_fars):
    rows = np.arange(len(probe_owner))
    own = np.zeros_like(best, dtype=bool)
    own[rows, probe_owner] = True
    genuine = best[own]
    table = []
    for far in target_fars:
        thresholds = np.array([calibration.threshold(far / n) for n in template_lengths])
        accepted = best >= thresholds[None, :]
        table.append(
            {
                "target_far": far,
                "genuine_accept": float(accepted[own].mean()),
                "measured_far": float(accepted[~own].mean()),
                "impostor_comparisons": int((~own).sum()),
            }
        )
    return table, genuine, best[~own]


def identify_table(best, probe_owner, template_lengths, stranger_best, calibration, target_fars):
    total = int(template_lengths.sum())
    winner = best.argmax(axis=1)
    top = best.max(axis=1)
    stranger_top = stranger_best.max(axis=1)
    table = []
    for far in target_fars:
        threshold = calibration.threshold(far / total)
        accepted = top >= threshold
        correct = accepted & (winner == probe_owner)
        wrong = accepted & (winner != probe_owner)
        table.append(
            {
                "target_far": far,
                "correct": float(correct.mean()),
                "wrong_person": float(wrong.mean()),
                "no_match": float((~accepted).mean()),
                "strangers_accepted": int((stranger_top >= threshold).sum()),
                "strangers": int(len(stranger_top)),
            }
        )
    return table


def evaluate(enrolled, stranger_embeddings, calibration, target_fars=DEFAULT_TARGET_FARS):
    best, probe_owner, lengths = score_matrices(enrolled)
    gallery = np.concatenate([e.shots for e in enrolled])
    starts = np.cumsum([0] + [len(e.shots) for e in enrolled[:-1]])
    stranger_best = np.maximum.reduceat(stranger_embeddings @ gallery.T, starts, axis=1)
    verify, genuine, impostor = verify_table(best, probe_owner, lengths, calibration, target_fars)
    eer, eer_threshold = equal_error_rate(genuine, impostor)
    return {
        "people": len(enrolled),
        "genuine_comparisons": int(len(genuine)),
        "impostor_comparisons": int(len(impostor)),
        "genuine_mean": float(genuine.mean()),
        "impostor_mean": float(impostor.mean()),
        "eer": eer,
        "eer_threshold": eer_threshold,
        "verify": verify,
        "identify": identify_table(best, probe_owner, lengths, stranger_best, calibration, target_fars),
        "genuine_scores": genuine,
        "impostor_scores": impostor,
    }


def format_report(result):
    lines = [
        f"people enrolled: {result['people']}",
        f"genuine comparisons: {result['genuine_comparisons']}  impostor comparisons: {result['impostor_comparisons']}",
        f"mean score  genuine {result['genuine_mean']:.3f}  impostor {result['impostor_mean']:.3f}",
        f"equal error rate {result['eer'] * 100:.3f}% at cosine {result['eer_threshold']:.3f}",
        "",
        "VERIFY (1:1)",
        f"{'target FAR':>10} {'genuine accept':>15} {'measured FAR':>14}",
    ]
    for row in result["verify"]:
        lines.append(f"{row['target_far']:>10.0e} {row['genuine_accept'] * 100:>14.2f}% {row['measured_far'] * 100:>13.4f}%")
    lines += ["", f"IDENTIFY (1:N among {result['people']} enrolled)", f"{'target FAR':>10} {'correct':>9} {'wrong person':>13} {'no match':>9} {'strangers accepted':>19}"]
    for row in result["identify"]:
        lines.append(
            f"{row['target_far']:>10.0e} {row['correct'] * 100:>8.2f}% {row['wrong_person'] * 100:>12.2f}% "
            f"{row['no_match'] * 100:>8.2f}% {row['strangers_accepted']:>12}/{row['strangers']}"
        )
    return "\n".join(lines)
