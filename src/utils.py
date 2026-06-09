from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from .schemas import ALLOWED_CONFIG_TYPES


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return ""


def write_csv(path: Path, rows: Iterable[dict], headers: list[str]) -> None:
    ensure_dir(path.parent)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def normalize_text(text: str) -> str:
    return " ".join((text or "").lower().split())


def discover_config_files(config_root: Path) -> list[Path]:
    if not config_root.exists():
        return []
    files: list[Path] = []
    for path in config_root.rglob("*"):
        if path.is_file():
            files.append(path)
    return sorted(files)


def infer_config_type(path: Path) -> str:
    parent = path.parent.name.lower()
    if parent in ALLOWED_CONFIG_TYPES:
        return parent
    extension = path.suffix.lower().lstrip(".")
    if extension in {"conf", "rules"}:
        return "unknown"
    if extension in {"yml", "yaml"}:
        return "unknown"
    return "unknown"


def safe_json_load(path: Path):
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
