"""Saving scan reports as JSON files in a folder."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path("reports")


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "scan"


def save_report(data: dict, target: Path, out_dir: Path = REPORTS_DIR) -> Path:
    """Write the report as JSON into out_dir and return its path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{datetime.now():%Y-%m-%d_%H-%M-%S}_{_slug(target.resolve().name)}"
    path = out_dir / f"{stem}.json"
    n = 1
    while path.exists():  # two scans in the same second must not overwrite each other
        path = out_dir / f"{stem}-{n}.json"
        n += 1
    path.write_text(json.dumps(data, indent=2, default=str))
    return path