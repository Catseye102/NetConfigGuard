from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .schemas import Finding, findings_to_rows
from .utils import normalize_text, write_csv

HEADERS = [
    "file_path",
    "file_name",
    "config_type",
    "issue_id",
    "issue",
    "severity",
    "evidence",
    "risk",
    "suggested_fix",
    "detector",
    "source",
]


def _primary_key(finding: Finding) -> tuple[str, str, str]:
    return (finding.file_name, finding.config_type, finding.issue_id)


def _fallback_key(finding: Finding) -> tuple[str, str, str]:
    issue = normalize_text(finding.issue)
    evidence = normalize_text(finding.evidence)
    return (finding.file_name, finding.config_type, f"{issue}|{evidence}")


def run_hybrid_detector(
    rule_findings: Iterable[Finding],
    model_findings: Iterable[Finding],
    output_path: Path,
) -> list[Finding]:
    merged: list[Finding] = []
    index: dict[tuple[str, str, str], Finding] = {}

    for finding in rule_findings:
        key = _primary_key(finding)
        index[key] = finding
        merged.append(finding)

    for finding in model_findings:
        if finding.issue_id:
            key = _primary_key(finding)
            match = index.get(key)
        else:
            key = _fallback_key(finding)
            match = index.get(key)

        if match:
            match.detector = "hybrid"
            match.source = "rule+model"
        else:
            merged.append(finding)
            index[key] = finding

    write_csv(output_path, findings_to_rows(merged), HEADERS)
    return merged
