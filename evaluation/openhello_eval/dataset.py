import collections
import json
import os
from pathlib import Path

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png"}


def prepare_lfw_parquet(parquet_path, out_dir):
    import pyarrow.parquet as pq

    parquet = pq.ParquetFile(parquet_path)
    names = json.loads(parquet.schema_arrow.metadata[b"huggingface"])["info"]["features"]["label"]["names"]
    counts = collections.Counter()
    for batch in parquet.iter_batches(batch_size=256):
        for row in batch.to_pylist():
            name = names[row["label"]]
            counts[name] += 1
            folder = Path(out_dir) / name
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"{counts[name]:04d}.jpg").write_bytes(row["image"]["bytes"])
    return counts


def prepare_cbsr_nir(source_dir, out_dir):
    import cv2

    counts = collections.Counter()
    for path in sorted(Path(source_dir).rglob("*.bmp")):
        person = path.stem.split("-")[0]
        image = cv2.imread(str(path), cv2.IMREAD_GRAYSCALE)
        if not person or image is None:
            continue
        folder = Path(out_dir) / person
        folder.mkdir(parents=True, exist_ok=True)
        cv2.imwrite(str(folder / f"{path.stem}.png"), image)
        counts[person] += 1
    return counts


def list_identities(images_dir):
    people = {}
    for folder in sorted(p for p in Path(images_dir).iterdir() if p.is_dir()):
        photos = sorted(p for p in folder.iterdir() if p.suffix.lower() in IMAGE_EXTENSIONS)
        if photos:
            people[folder.name] = photos
    return people


def split_identities(people, enroll_shots, max_eval, max_calibration):
    needed = enroll_shots + 2
    enrolled = [name for name, photos in people.items() if len(photos) >= needed][:max_eval]
    strangers = [name for name, photos in people.items() if len(photos) < needed][:max_calibration]
    return enrolled, strangers


def link_strangers(images_dir, strangers, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name in strangers:
        link = out / name
        if not link.exists():
            os.symlink((Path(images_dir) / name).resolve(), link)
    return out
