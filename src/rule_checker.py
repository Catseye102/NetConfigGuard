from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import yaml

from .schemas import Finding, findings_to_rows
from .utils import infer_config_type, normalize_text, read_text_file, write_csv

DB_PORTS = {"3306", "5432", "6379", "27017", "9200", "1433"}
ADMIN_PORTS = {"2375": "high", "2376": "high", "8080": "medium", "9090": "medium", "9200": "high"}


def _line_evidence(lines: list[str], pattern: str) -> str:
    for line in lines:
        if pattern in line.lower():
            return line.strip()
    return pattern


def _add_finding(findings: list[Finding], **kwargs) -> None:
    findings.append(Finding(**kwargs))


def scan_ssh(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()

    rules = [
        ("permitrootlogin yes", "SSH_ROOT_LOGIN_ENABLED", "PermitRootLogin enabled", "high",
         "Allows direct privileged login over the network.", "Set PermitRootLogin no."),
        ("passwordauthentication yes", "SSH_PASSWORD_AUTH_ENABLED", "PasswordAuthentication enabled", "high",
         "Increases exposure to password guessing and credential attacks.",
         "Set PasswordAuthentication no and use key-based authentication."),
        ("permitemptypasswords yes", "SSH_EMPTY_PASSWORDS_ENABLED", "PermitEmptyPasswords enabled", "critical",
         "Allows accounts with empty passwords to authenticate.", "Set PermitEmptyPasswords no."),
        ("x11forwarding yes", "SSH_X11_FORWARDING_ENABLED", "X11Forwarding enabled", "low",
         "Expands remote session capabilities and may be unnecessary for servers.",
         "Set X11Forwarding no unless explicitly required."),
        ("pubkeyauthentication no", "SSH_PUBKEY_AUTH_DISABLED", "PubkeyAuthentication disabled", "medium",
         "Disables stronger key-based authentication.", "Set PubkeyAuthentication yes."),
    ]

    for needle, issue_id, issue, severity, risk, fix in rules:
        if needle in text.lower():
            evidence = _line_evidence(lines, needle)
            _add_finding(
                findings,
                file_path=str(path),
                file_name=path.name,
                config_type="ssh",
                issue_id=issue_id,
                issue=issue,
                severity=severity,
                evidence=evidence,
                risk=risk,
                suggested_fix=fix,
                detector="rule",
                source="ssh_rules",
            )
    return findings


def scan_firewall(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for line in lines:
        lower = line.lower()
        if not lower.strip():
            continue

        if ("0.0.0.0/0" in lower or "any/any" in lower or "any any" in lower) and "22" in lower:
            _add_finding(
                findings,
                file_path=str(path),
                file_name=path.name,
                config_type="firewall",
                issue_id="FW_PUBLIC_SSH_EXPOSURE",
                issue="Public SSH exposure",
                severity="high",
                evidence=line.strip(),
                risk="Exposes SSH to untrusted networks.",
                suggested_fix="Restrict SSH to trusted admin IP ranges.",
                detector="rule",
                source="firewall_rules",
            )

        if ("0.0.0.0/0" in lower or "any/any" in lower or "any any" in lower):
            if any(port in lower for port in DB_PORTS):
                _add_finding(
                    findings,
                    file_path=str(path),
                    file_name=path.name,
                    config_type="firewall",
                    issue_id="FW_PUBLIC_DATABASE_EXPOSURE",
                    issue="Public database/admin port exposure",
                    severity="high",
                    evidence=line.strip(),
                    risk="Exposes database/admin services to the public internet.",
                    suggested_fix="Do not expose database/admin ports publicly; restrict to private networks.",
                    detector="rule",
                    source="firewall_rules",
                )

        if "allow all" in lower or "any any" in lower or "0.0.0.0/0" in lower and "0.0.0.0/0" in lower:
            _add_finding(
                findings,
                file_path=str(path),
                file_name=path.name,
                config_type="firewall",
                issue_id="FW_ALLOW_ALL_INBOUND",
                issue="Allow all inbound",
                severity="critical",
                evidence=line.strip(),
                risk="Allows unrestricted inbound traffic.",
                suggested_fix="Replace broad allow rules with least-privilege rules.",
                detector="rule",
                source="firewall_rules",
            )
    return findings


def _has_header(text: str, header: str) -> bool:
    return header.lower() in text.lower()


def scan_nginx(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lower = text.lower()
    lines = text.splitlines()

    if not _has_header(text, "add_header x-frame-options"):
        _add_finding(
            findings,
            file_path=str(path),
            file_name=path.name,
            config_type="nginx",
            issue_id="NGINX_MISSING_X_FRAME_OPTIONS",
            issue="Missing X-Frame-Options header",
            severity="low",
            evidence="add_header X-Frame-Options not found",
            risk="Missing clickjacking protection headers.",
            suggested_fix="Add add_header X-Frame-Options \"DENY\" always; or SAMEORIGIN if appropriate.",
            detector="rule",
            source="nginx_rules",
        )

    if not _has_header(text, "add_header content-security-policy"):
        _add_finding(
            findings,
            file_path=str(path),
            file_name=path.name,
            config_type="nginx",
            issue_id="NGINX_MISSING_CSP",
            issue="Missing Content-Security-Policy header",
            severity="medium",
            evidence="add_header Content-Security-Policy not found",
            risk="Missing CSP can allow script injection attacks.",
            suggested_fix="Add a Content-Security-Policy header suitable for the application.",
            detector="rule",
            source="nginx_rules",
        )

    tls_present = "listen 443" in lower or "ssl_certificate" in lower
    if tls_present and not _has_header(text, "strict-transport-security"):
        _add_finding(
            findings,
            file_path=str(path),
            file_name=path.name,
            config_type="nginx",
            issue_id="NGINX_MISSING_HSTS",
            issue="Missing Strict-Transport-Security",
            severity="medium",
            evidence="Strict-Transport-Security not found",
            risk="Without HSTS, clients may downgrade to HTTP.",
            suggested_fix="Add Strict-Transport-Security with an appropriate max-age.",
            detector="rule",
            source="nginx_rules",
        )

    if "listen 80" in lower:
        has_redirect = any("return 301 https" in normalize_text(line) or "return 308 https" in normalize_text(line) for line in lines)
        if not has_redirect:
            _add_finding(
                findings,
                file_path=str(path),
                file_name=path.name,
                config_type="nginx",
                issue_id="NGINX_NO_HTTP_TO_HTTPS_REDIRECT",
                issue="No HTTP to HTTPS redirect",
                severity="medium",
                evidence="listen 80 without redirect",
                risk="HTTP traffic can be intercepted without encryption.",
                suggested_fix="Redirect HTTP traffic to HTTPS.",
                detector="rule",
                source="nginx_rules",
            )

    if "server_tokens on" in lower:
        evidence = _line_evidence(lines, "server_tokens on")
        _add_finding(
            findings,
            file_path=str(path),
            file_name=path.name,
            config_type="nginx",
            issue_id="NGINX_SERVER_TOKENS_ENABLED",
            issue="Server tokens enabled",
            severity="low",
            evidence=evidence,
            risk="Reveals server version information.",
            suggested_fix="Set server_tokens off.",
            detector="rule",
            source="nginx_rules",
        )

    return findings


def _extract_ports(port_value: str) -> list[str]:
    parts = re.split(r"[:/\s]+", port_value)
    return [part for part in parts if part.isdigit()]


def scan_docker(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen_port_findings: set[tuple[str, str]] = set()
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        data = {}

    services = data.get("services", {}) if isinstance(data, dict) else {}
    for service_name, service in services.items() if isinstance(services, dict) else []:
        if not isinstance(service, dict):
            continue

        if service.get("privileged") is True:
            _add_finding(
                findings,
                file_path=str(path),
                file_name=path.name,
                config_type="docker",
                issue_id="DOCKER_PRIVILEGED_CONTAINER",
                issue="Privileged container",
                severity="high",
                evidence=f"{service_name}: privileged true",
                risk="Privileged containers disable important isolation controls.",
                suggested_fix="Avoid privileged containers unless strictly required.",
                detector="rule",
                source="docker_rules",
            )

        if service.get("network_mode") == "host":
            _add_finding(
                findings,
                file_path=str(path),
                file_name=path.name,
                config_type="docker",
                issue_id="DOCKER_HOST_NETWORK_MODE",
                issue="Host network mode",
                severity="high",
                evidence=f"{service_name}: network_mode host",
                risk="Host networking bypasses container network isolation.",
                suggested_fix="Use isolated Docker networks instead of host networking.",
                detector="rule",
                source="docker_rules",
            )

        if service.get("read_only") is not True:
            _add_finding(
                findings,
                file_path=str(path),
                file_name=path.name,
                config_type="docker",
                issue_id="DOCKER_CONTAINER_NOT_READ_ONLY",
                issue="Container filesystem is not read-only",
                severity="info",
                evidence=f"{service_name}: read_only not set",
                risk="Writable filesystems increase the impact of container compromise.",
                suggested_fix="Consider read_only: true where possible.",
                detector="rule",
                source="docker_rules",
            )

        for port in service.get("ports", []) if isinstance(service.get("ports", []), list) else []:
            evidence = f"{service_name}: {port}"
            port_values = set(_extract_ports(str(port)))

            if port_values & DB_PORTS:
                key = ("DOCKER_PUBLIC_DATABASE_PORT", evidence)
                if key not in seen_port_findings:
                    seen_port_findings.add(key)
                    _add_finding(
                        findings,
                        file_path=str(path),
                        file_name=path.name,
                        config_type="docker",
                        issue_id="DOCKER_PUBLIC_DATABASE_PORT",
                        issue="Public database port exposure",
                        severity="high",
                        evidence=evidence,
                        risk="Publishing database ports increases exposure to attacks.",
                        suggested_fix="Do not publish database ports publicly; use internal networks.",
                        detector="rule",
                        source="docker_rules",
                    )

            admin_ports = [port_value for port_value in port_values if port_value in ADMIN_PORTS]
            if admin_ports:
                severity = "high" if any(ADMIN_PORTS[value] == "high" for value in admin_ports) else "medium"
                key = ("DOCKER_EXPOSED_ADMIN_PORT", evidence)
                if key not in seen_port_findings:
                    seen_port_findings.add(key)
                    _add_finding(
                        findings,
                        file_path=str(path),
                        file_name=path.name,
                        config_type="docker",
                        issue_id="DOCKER_EXPOSED_ADMIN_PORT",
                        issue="Exposed admin port",
                        severity=severity,
                        evidence=evidence,
                        risk="Admin interfaces should not be publicly exposed.",
                        suggested_fix="Bind admin interfaces to localhost or private networks.",
                        detector="rule",
                        source="docker_rules",
                    )

    if not services:
        lower = text.lower()
        if "privileged: true" in lower:
            _add_finding(
                findings,
                file_path=str(path),
                file_name=path.name,
                config_type="docker",
                issue_id="DOCKER_PRIVILEGED_CONTAINER",
                issue="Privileged container",
                severity="high",
                evidence="privileged: true",
                risk="Privileged containers disable important isolation controls.",
                suggested_fix="Avoid privileged containers unless strictly required.",
                detector="rule",
                source="docker_rules",
            )
    return findings


def scan_kubernetes(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        docs = []

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        spec = doc.get("spec", {}) if isinstance(doc.get("spec", {}), dict) else {}

        if spec.get("hostNetwork") is True:
            _add_finding(
                findings,
                file_path=str(path),
                file_name=path.name,
                config_type="kubernetes",
                issue_id="K8S_HOST_NETWORK_ENABLED",
                issue="hostNetwork enabled",
                severity="high",
                evidence="hostNetwork: true",
                risk="Host networking bypasses pod network isolation.",
                suggested_fix="Avoid hostNetwork unless strictly required.",
                detector="rule",
                source="k8s_rules",
            )

        containers = spec.get("containers", []) if isinstance(spec.get("containers", []), list) else []
        for container in containers:
            security_context = container.get("securityContext", {}) if isinstance(container, dict) else {}
            if security_context.get("privileged") is True:
                _add_finding(
                    findings,
                    file_path=str(path),
                    file_name=path.name,
                    config_type="kubernetes",
                    issue_id="K8S_PRIVILEGED_CONTAINER",
                    issue="Privileged container",
                    severity="high",
                    evidence="securityContext.privileged: true",
                    risk="Privileged containers can access host-level resources.",
                    suggested_fix="Set privileged: false and use least-privilege securityContext.",
                    detector="rule",
                    source="k8s_rules",
                )
            if security_context.get("allowPrivilegeEscalation") is True:
                _add_finding(
                    findings,
                    file_path=str(path),
                    file_name=path.name,
                    config_type="kubernetes",
                    issue_id="K8S_PRIVILEGE_ESCALATION_ALLOWED",
                    issue="Privilege escalation allowed",
                    severity="medium",
                    evidence="allowPrivilegeEscalation: true",
                    risk="Allows processes to gain additional privileges.",
                    suggested_fix="Set allowPrivilegeEscalation: false.",
                    detector="rule",
                    source="k8s_rules",
                )

        if doc.get("kind") == "NetworkPolicy":
            ingress = spec.get("ingress", []) if isinstance(spec.get("ingress", []), list) else []
            for rule in ingress:
                if rule == {}:
                    _add_finding(
                        findings,
                        file_path=str(path),
                        file_name=path.name,
                        config_type="kubernetes",
                        issue_id="K8S_ALLOW_ALL_INGRESS",
                        issue="Allow all ingress",
                        severity="high",
                        evidence="ingress: - {}",
                        risk="Allows traffic from any source.",
                        suggested_fix="Restrict ingress with podSelector, namespaceSelector, or ipBlock.",
                        detector="rule",
                        source="k8s_rules",
                    )
                from_blocks = rule.get("from", []) if isinstance(rule, dict) else []
                for block in from_blocks:
                    ip_block = block.get("ipBlock", {}) if isinstance(block, dict) else {}
                    cidr = ip_block.get("cidr")
                    if isinstance(cidr, str) and cidr.strip() == "0.0.0.0/0":
                        _add_finding(
                            findings,
                            file_path=str(path),
                            file_name=path.name,
                            config_type="kubernetes",
                            issue_id="K8S_PUBLIC_INGRESS_CIDR",
                            issue="Public ingress CIDR",
                            severity="high",
                            evidence="ipBlock.cidr: 0.0.0.0/0",
                            risk="Allows ingress from all IP addresses.",
                            suggested_fix="Restrict ingress CIDR ranges.",
                            detector="rule",
                            source="k8s_rules",
                        )

    return findings


def run_rule_checker(config_files: Iterable[Path], output_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in config_files:
        config_type = infer_config_type(path)
        text = read_text_file(path)
        if config_type == "ssh":
            findings.extend(scan_ssh(path, text))
        elif config_type == "firewall":
            findings.extend(scan_firewall(path, text))
        elif config_type == "nginx":
            findings.extend(scan_nginx(path, text))
        elif config_type == "docker":
            findings.extend(scan_docker(path, text))
        elif config_type == "kubernetes":
            findings.extend(scan_kubernetes(path, text))

    headers = [
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
    write_csv(output_path, findings_to_rows(findings), headers)
    return findings
