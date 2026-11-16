"""Download and parse all OTRF Security-Datasets metadata YAML files."""

import json
from pathlib import Path

import requests
import yaml

METADATA_BASE = (
    "https://api.github.com/repos/OTRF/Security-Datasets"
    "/contents/datasets/atomic/_metadata"
)
RAW_BASE = (
    "https://raw.githubusercontent.com/OTRF/Security-Datasets"
    "/master/datasets/atomic/_metadata"
)
OUT_DIR = Path("data/raw/metadata")


def list_metadata_files() -> list[str]:
    """Get list of YAML metadata filenames from GitHub API."""
    resp = requests.get(METADATA_BASE, timeout=30)
    resp.raise_for_status()
    entries = resp.json()
    return [e["name"] for e in entries if e["name"].endswith(".yaml")]


def download_metadata(filename: str) -> dict:
    """Download and parse one metadata YAML file."""
    url = f"{RAW_BASE}/{filename}"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return yaml.safe_load(resp.text)


def fetch_all_metadata(out_dir: Path | None = None) -> list[dict]:
    """Download all metadata, cache locally, return parsed list."""
    out_dir = out_dir or OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    cache_path = out_dir / "all_metadata.json"
    if cache_path.exists():
        print(f"Using cached metadata from {cache_path}")
        with open(cache_path) as f:
            return json.load(f)

    print("Fetching metadata file list from GitHub...")
    filenames = list_metadata_files()
    print(f"Found {len(filenames)} metadata files")

    all_meta = []
    for i, fname in enumerate(filenames):
        print(f"  [{i+1}/{len(filenames)}] {fname}")
        try:
            meta = download_metadata(fname)
            meta["_filename"] = fname
            all_meta.append(meta)
        except Exception as e:
            print(f"    SKIP: {e}")

    with open(cache_path, "w") as f:
        json.dump(all_meta, f, indent=2, default=str)
    print(f"Saved {len(all_meta)} metadata records to {cache_path}")

    return all_meta


def summarise_metadata(all_meta: list[dict]) -> None:
    """Print summary of available datasets."""
    windows = [
        m for m in all_meta
        if "Windows" in (m.get("platform") or [])
    ]
    print(f"\nTotal metadata: {len(all_meta)}")
    print(f"Windows datasets: {len(windows)}")

    # Extract ATT&CK info
    techniques = {}
    tactics = {}
    for m in windows:
        for mapping in m.get("attack_mappings", []):
            tech = mapping.get("technique", "")
            sub = mapping.get("sub-technique") or mapping.get("sub_technique")
            tactic = mapping.get("tactics", ["unknown"])
            full_tech = f"{tech}.{sub}" if sub else tech

            techniques.setdefault(full_tech, []).append(m.get("id", "?"))
            for t in (tactic if isinstance(tactic, list) else [tactic]):
                tactics.setdefault(t, []).append(m.get("id", "?"))

    print(f"\nUnique techniques: {len(techniques)}")
    for tech, ids in sorted(techniques.items()):
        print(f"  {tech}: {len(ids)} datasets")

    print("\nTactics:")
    for tac, ids in sorted(tactics.items()):
        print(f"  {tac}: {len(ids)} datasets")

    # Show datasets with download URLs
    print("\nDatasets with host log files:")
    count = 0
    for m in windows:
        files = m.get("files", [])
        for f in files:
            if f.get("type") == "Host" and f.get("link", "").endswith(".zip"):
                count += 1
                techs = [
                    f"{am.get('technique','?')}.{am.get('sub_technique','')}"
                    if am.get("sub_technique") else am.get("technique", "?")
                    for am in m.get("attack_mappings", [])
                ]
                print(f"  {m.get('id','?')} | {m.get('title','?')[:60]} | {', '.join(techs)}")
    print(f"Total downloadable host datasets: {count}")


if __name__ == "__main__":
    meta = fetch_all_metadata()
    summarise_metadata(meta)
