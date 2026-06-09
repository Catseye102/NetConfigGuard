from pathlib import Path

from src.rule_checker import scan_docker, scan_kubernetes, scan_nginx, scan_ssh


def test_ssh_permit_root_login_detected(tmp_path: Path) -> None:
    content = "PermitRootLogin yes\n"
    findings = scan_ssh(tmp_path / "sshd_config", content)
    assert any(f.issue_id == "SSH_ROOT_LOGIN_ENABLED" for f in findings)


def test_ssh_password_auth_detected(tmp_path: Path) -> None:
    content = "PasswordAuthentication yes\n"
    findings = scan_ssh(tmp_path / "sshd_config", content)
    assert any(f.issue_id == "SSH_PASSWORD_AUTH_ENABLED" for f in findings)


def test_docker_privileged_detected(tmp_path: Path) -> None:
    content = """version: '3.8'
services:
  db:
    image: mysql:8
    privileged: true
"""
    findings = scan_docker(tmp_path / "docker-compose.yml", content)
    assert any(f.issue_id == "DOCKER_PRIVILEGED_CONTAINER" for f in findings)


def test_nginx_missing_csp_detected(tmp_path: Path) -> None:
    content = """server {
    listen 443 ssl;
}
"""
    findings = scan_nginx(tmp_path / "nginx.conf", content)
    assert any(f.issue_id == "NGINX_MISSING_CSP" for f in findings)


def test_k8s_host_network_detected(tmp_path: Path) -> None:
    content = """apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx
"""
    findings = scan_kubernetes(tmp_path / "pod.yml", content)
    assert any(f.issue_id == "K8S_HOST_NETWORK_ENABLED" for f in findings)


def test_docker_port_mapping_not_duplicated(tmp_path: Path) -> None:
        content = """version: '3.8'
services:
    db:
        image: postgres:15
        ports:
            - "5432:5432"
"""
        findings = scan_docker(tmp_path / "docker-compose.yml", content)
        matches = [f for f in findings if f.issue_id == "DOCKER_PUBLIC_DATABASE_PORT"]
        assert len(matches) == 1
