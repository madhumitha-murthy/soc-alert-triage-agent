"""Download and extract OTRF event log ZIP files."""

import io
import json
import zipfile
from pathlib import Path

import requests
from tqdm import tqdm

DOWNLOAD_DIR = Path("data/downloads")


def get_host_zip_urls(dataset: dict) -> list[str]:
    """Extract Host-type ZIP URLs from a dataset metadata entry."""
    urls = []
    for f in dataset.get("files", []):
        if f.get("type") == "Host" and f.get("link", "").endswith(".zip"):
            urls.append(f["link"])
    return urls


def download_and_extract(url: str, out_dir: Path) -> list[Path]:
    """Download a ZIP and extract JSON files. Returns list of extracted paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    resp = requests.get(url, timeout=120, stream=True)
    resp.raise_for_status()

    content = io.BytesIO(resp.content)
    extracted = []
    with zipfile.ZipFile(content) as zf:
        for name in zf.namelist():
            if name.endswith(".json"):
                target = out_dir / Path(name).name
                with zf.open(name) as src, open(target, "wb") as dst:
                    dst.write(src.read())
                extracted.append(target)
    return extracted


def load_events(json_path: Path) -> list[dict]:
    """Load events from a JSON-lines file (one JSON object per line)."""
    events = []
    with open(json_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def download_dataset_logs(dataset: dict) -> list[Path]:
    """Download all host log files for a dataset. Returns extracted JSON paths."""
    dataset_id = dataset["id"]
    out_dir = DOWNLOAD_DIR / dataset_id

    # Check cache
    if out_dir.exists():
        existing = list(out_dir.glob("*.json"))
        if existing:
            return existing

    urls = get_host_zip_urls(dataset)
    all_paths = []
    for url in urls:
        paths = download_and_extract(url, out_dir)
        all_paths.extend(paths)
    return all_paths


def download_all_selected(datasets: list[dict]) -> dict[str, list[Path]]:
    """Download logs for all selected datasets. Returns {dataset_id: [json_paths]}."""
    result = {}
    for ds in tqdm(datasets, desc="Downloading event logs"):
        did = ds["id"]
        try:
            paths = download_dataset_logs(ds)
            result[did] = paths
            print(f"  {did}: {len(paths)} JSON file(s)")
        except Exception as e:
            print(f"  {did}: FAILED — {e}")
            result[did] = []
    return result
