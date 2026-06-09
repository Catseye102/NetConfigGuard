from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from .schemas import ALLOWED_CONFIG_TYPES, ALLOWED_DETECTORS, ALLOWED_SEVERITIES
from .utils import discover_config_files, infer_config_type, write_csv


def _count_files_by_type(config_root: Path) -> dict[str, int]:
    counts = {config_type: 0 for config_type in ALLOWED_CONFIG_TYPES}
    for path in discover_config_files(config_root):
        config_type = infer_config_type(path)
        counts[config_type] = counts.get(config_type, 0) + 1
    return counts


def _ensure_series(df: pd.DataFrame, column: str, allowed: set[str]) -> dict[str, int]:
    if column not in df.columns:
        return {value: 0 for value in allowed}
    counts = df[column].value_counts().to_dict()
    return {value: int(counts.get(value, 0)) for value in allowed}


def _write_bar_chart(output_path: Path, title: str, labels: list[str], values: list[int]) -> None:
    plt.figure(figsize=(8, 4))
    plt.bar(labels, values)
    plt.title(title)
    plt.xlabel("Category")
    plt.ylabel("Count")
    plt.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path)
    plt.close()


def run_evaluation(
    results_dir: Path = Path("results"),
    config_root: Path = Path("data/configs"),
) -> None:
    hybrid_path = results_dir / "hybrid_findings.csv"
    if hybrid_path.exists():
        df = pd.read_csv(hybrid_path)
    else:
        df = pd.DataFrame()

    files_by_type = _count_files_by_type(config_root)
    issues_by_type = _ensure_series(df, "config_type", ALLOWED_CONFIG_TYPES)
    issues_by_severity = _ensure_series(df, "severity", ALLOWED_SEVERITIES)
    issues_by_detector = _ensure_series(df, "detector", ALLOWED_DETECTORS)

    if "suggested_fix" in df.columns:
        fixes = df["suggested_fix"].fillna("").astype(str).str.strip()
        with_fix = int((fixes != "").sum())
    else:
        with_fix = 0

    summary_rows = []
    for config_type, count in files_by_type.items():
        summary_rows.append({"metric": f"files_scanned_{config_type}", "value": count})
    for config_type, count in issues_by_type.items():
        summary_rows.append({"metric": f"issues_{config_type}", "value": count})
    for severity, count in issues_by_severity.items():
        summary_rows.append({"metric": f"issues_severity_{severity}", "value": count})
    for detector, count in issues_by_detector.items():
        summary_rows.append({"metric": f"issues_detector_{detector}", "value": count})
    summary_rows.append({"metric": "findings_with_suggested_fix", "value": with_fix})

    write_csv(results_dir / "summary.csv", summary_rows, ["metric", "value"])

    type_labels = list(issues_by_type.keys())
    type_values = [issues_by_type[label] for label in type_labels]
    _write_bar_chart(results_dir / "issues_by_config_type.png", "Issues by Config Type", type_labels, type_values)

    severity_labels = list(issues_by_severity.keys())
    severity_values = [issues_by_severity[label] for label in severity_labels]
    _write_bar_chart(results_dir / "issues_by_severity.png", "Issues by Severity", severity_labels, severity_values)


def main() -> None:
    run_evaluation()


if __name__ == "__main__":
    main()
