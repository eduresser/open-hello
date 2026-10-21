import nbformat as nbf

cells = [
    nbf.v4.new_markdown_cell(
        "# Accuracy evaluation\n\n"
        "Measures acceptance of the right person and rejection of others at the production thresholds. "
        "Prerequisites and commands are in this folder's `README.md`."
    ),
    nbf.v4.new_code_cell(
        "import os\n"
        "from pathlib import Path\n\n"
        "import matplotlib.pyplot as plt\n"
        "import numpy as np\n\n"
        "from openhello_eval.calibration import Calibration\n"
        "from openhello_eval.metrics import format_report\n"
        "from openhello_eval.workflow import Run\n\n"
        "DATA = Path(os.environ.get('OPENHELLO_EVAL_DATA', 'data'))\n"
        "ENROLL_SHOTS = 3\n"
        "run = Run(DATA / 'people', DATA / 'embeddings.npz', enroll_shots=ENROLL_SHOTS)\n"
        "calibration = Calibration.from_file(DATA / 'calibration.bin')\n"
        "print(len(run.enrolled_names), 'enrolled,', len(run.stranger_names), 'strangers')\n"
        "print(run.parity(calibration))"
    ),
    nbf.v4.new_markdown_cell("## Report at the production thresholds"),
    nbf.v4.new_code_cell("result = run.report(calibration)\nprint(format_report(result))"),
    nbf.v4.new_markdown_cell("## Score distributions"),
    nbf.v4.new_code_cell(
        "fig, ax = plt.subplots(figsize=(8, 3.5))\n"
        "bins = np.linspace(-0.2, 1.0, 120)\n"
        "ax.hist(result['impostor_scores'], bins=bins, density=True, alpha=0.6, label='different person')\n"
        "ax.hist(result['genuine_scores'], bins=bins, density=True, alpha=0.6, label='same person')\n"
        "for row in result['verify']:\n"
        "    ax.axvline(calibration.threshold(row['target_far'] / ENROLL_SHOTS), color='k', lw=0.6, ls='--')\n"
        "ax.set_xlabel('cosine similarity'); ax.set_ylabel('density'); ax.legend()\n"
        "plt.show()"
    ),
    nbf.v4.new_markdown_cell("## Measured FAR against target\n\nPoints above the diagonal mean the system accepts more impostors than it promises."),
    nbf.v4.new_code_cell(
        "targets = np.array([row['target_far'] for row in result['verify']])\n"
        "measured = np.array([row['measured_far'] for row in result['verify']])\n"
        "fig, ax = plt.subplots(figsize=(4.5, 4.5))\n"
        "ax.loglog(targets, measured, 'o-', label='measured')\n"
        "ax.loglog(targets, targets, 'k--', lw=0.8, label='target')\n"
        "ax.set_xlabel('target FAR'); ax.set_ylabel('measured FAR'); ax.legend()\n"
        "plt.show()"
    ),
    nbf.v4.new_markdown_cell("## Empirical ROC curve\n\nIndependent of calibration: shows the best the model allows."),
    nbf.v4.new_code_cell(
        "genuine, impostor = result['genuine_scores'], result['impostor_scores']\n"
        "cuts = np.quantile(impostor, 1 - np.logspace(-0.3, -np.log10(len(impostor)), 120))\n"
        "far = np.array([(impostor >= c).mean() for c in cuts])\n"
        "tar = np.array([(genuine >= c).mean() for c in cuts])\n"
        "fig, ax = plt.subplots(figsize=(5, 4))\n"
        "ax.semilogx(far, tar)\n"
        "ax.set_xlabel('FAR'); ax.set_ylabel('genuine accept rate'); ax.set_ylim(0.5, 1.0); ax.grid(alpha=0.3)\n"
        "plt.show()"
    ),
]

notebook = nbf.v4.new_notebook(cells=cells)
notebook.metadata["kernelspec"] = {"display_name": "Python 3", "language": "python", "name": "python3"}
nbf.write(notebook, "notebooks/evaluation.ipynb")
