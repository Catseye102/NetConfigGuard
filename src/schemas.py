from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Iterable

ALLOWED_CONFIG_TYPES = {"ssh", "nginx", "docker", "firewall", "kubernetes", "unknown"}
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALLOWED_DETECTORS = {"rule", "model", "hybrid"}


@dataclass
class Finding:
    file_path: str
    file_name: str
    config_type: str
    issue_id: str
    issue: str
    severity: str
    evidence: str
    risk: str
    suggested_fix: str
    detector: str
    source: str


def _normalize_value(value: str) -> str:
    return (value or "").strip()


def coerce_finding(
    raw: Dict[str, object],
    detector_default: str = "model",
    source_default: str = "manual",
) -> Finding:
    config_type = _normalize_value(str(raw.get("config_type", "unknown"))).lower()
    if config_type not in ALLOWED_CONFIG_TYPES:
        config_type = "unknown"

    severity = _normalize_value(str(raw.get("severity", "info"))).lower()
    if severity not in ALLOWED_SEVERITIES:
        severity = "info"

    detector = _normalize_value(str(raw.get("detector", detector_default))).lower()
    if detector not in ALLOWED_DETECTORS:
        detector = detector_default

    source = _normalize_value(str(raw.get("source", source_default)))

    return Finding(
        file_path=_normalize_value(str(raw.get("file_path", ""))),
        file_name=_normalize_value(str(raw.get("file_name", ""))),
        config_type=config_type,
        issue_id=_normalize_value(str(raw.get("issue_id", ""))),
        issue=_normalize_value(str(raw.get("issue", ""))),
        severity=severity,
        evidence=_normalize_value(str(raw.get("evidence", ""))),
        risk=_normalize_value(str(raw.get("risk", ""))),
        suggested_fix=_normalize_value(str(raw.get("suggested_fix", ""))),
        detector=detector,
        source=source,
    )


def findings_to_rows(findings: Iterable[Finding]) -> list[dict[str, str]]:
    return [asdict(finding) for finding in findings]
