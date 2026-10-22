import argparse
import json
import sys

from .calibration import Calibration
from .dataset import link_strangers, list_identities, prepare_cbsr_nir, prepare_lfw_parquet, split_identities
from .metrics import DEFAULT_TARGET_FARS, format_report
from .pipeline import Pipeline
from .workflow import Run, save_embeddings


def split_arguments(parser):
    parser.add_argument("--enroll-shots", type=int, default=3)
    parser.add_argument("--max-eval", type=int, default=300)
    parser.add_argument("--max-calibration", type=int, default=600)


def build_parser():
    parser = argparse.ArgumentParser(prog="python -m openhello_eval", description="Offline accuracy evaluation for open-hello")
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare", help="unpack the LFW parquet into one folder per person")
    prepare.add_argument("--parquet", required=True)
    prepare.add_argument("--out", required=True)

    cbsr = commands.add_parser("prepare-cbsr", help="group the CBSR NIR bmp files into one PNG folder per person")
    cbsr.add_argument("--source", required=True)
    cbsr.add_argument("--out", required=True)

    embed = commands.add_parser("embed", help="run YuNet + AuraFace over every photo")
    embed.add_argument("--models-dir", required=True)
    embed.add_argument("--images-dir", required=True)
    embed.add_argument("--out", required=True)

    strangers = commands.add_parser("strangers", help="link the calibration identities for openhello-calibrate")
    strangers.add_argument("--images-dir", required=True)
    strangers.add_argument("--out", required=True)
    split_arguments(strangers)

    for name, text in (("parity", "check Python embeddings against a Rust-made calibration file"), ("report", "accuracy at the production thresholds")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--images-dir", required=True)
        command.add_argument("--embeddings", required=True)
        command.add_argument("--calibration", required=True)
        split_arguments(command)
        if name == "report":
            command.add_argument("--json")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "prepare":
        counts = prepare_lfw_parquet(args.parquet, args.out)
        print(f"{len(counts)} people, {sum(counts.values())} photos -> {args.out}")
    elif args.command == "prepare-cbsr":
        counts = prepare_cbsr_nir(args.source, args.out)
        print(f"{len(counts)} people, {sum(counts.values())} photos -> {args.out}")
    elif args.command == "embed":
        people = list_identities(args.images_dir)
        paths = [p for photos in people.values() for p in photos]
        embeddings, valid = Pipeline(args.models_dir).embed_all(paths, progress=lambda done, total: print(f"{done}/{total}", file=sys.stderr))
        save_embeddings(args.out, people, embeddings, valid)
        print(f"{int(valid.sum())}/{len(paths)} photos with a face -> {args.out}")
    elif args.command == "strangers":
        people = list_identities(args.images_dir)
        _, names = split_identities(people, args.enroll_shots, args.max_eval, args.max_calibration)
        link_strangers(args.images_dir, names, args.out)
        print(f"{len(names)} calibration identities linked -> {args.out}")
    else:
        run = Run(args.images_dir, args.embeddings, args.enroll_shots, args.max_eval, args.max_calibration)
        calibration = Calibration.from_file(args.calibration)
        if args.command == "parity":
            result = run.parity(calibration)
            print(json.dumps(result))
            return 0 if result["ok"] else 1
        result = run.report(calibration)
        print(format_report(result))
        if args.json:
            serializable = {k: v for k, v in result.items() if not k.endswith("_scores")}
            with open(args.json, "w") as handle:
                json.dump(serializable, handle, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
