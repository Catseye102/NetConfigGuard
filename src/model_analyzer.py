from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Iterable

from .schemas import Finding, coerce_finding, findings_to_rows
from .utils import ensure_dir, infer_config_type, read_text_file, safe_json_load, write_csv

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


def _build_prompt(config_type: str, file_name: str, content: str) -> str:
    return (
        "You are a security reviewer. Analyze the configuration and return JSON findings.\n"
        "Return ONLY valid JSON (a list of objects) with these fields:\n"
        "file_path, file_name, config_type, issue_id, issue, severity, evidence, risk, suggested_fix, detector, source.\n"
        "Allowed config_type values: ssh, nginx, docker, firewall, kubernetes, unknown.\n"
        "Allowed severity values: critical, high, medium, low, info.\n"
        "Detector should be 'model'. Source should be 'prompt'.\n\n"
        f"Config type: {config_type}\n"
        f"File name: {file_name}\n"
        "Configuration:\n"
        f"{content}\n"
    )


def _build_gemini_prompt(config_type: str, file_name: str, file_path: str, content: str) -> str:
    return (
        "You are a network security configuration analyzer for a project called NetConfigGuard.\n\n"
        "Analyze the following configuration file for insecure network/security settings.\n\n"
        f"Config type: {config_type}\n"
        f"File name: {file_name}\n\n"
        "Configuration:\n"
        f"{content}\n\n"
        "Return only valid JSON. Do not include Markdown. Do not include explanations outside JSON.\n\n"
        "Return a JSON array. Each object must use this schema:\n"
        "[\n"
        "  {\n"
        "    \"file_path\": \"relative/path/to/file\",\n"
        "    \"file_name\": \"example.conf\",\n"
        "    \"config_type\": \"ssh\",\n"
        "    \"issue_id\": \"STABLE_ISSUE_ID\",\n"
        "    \"issue\": \"Short issue title\",\n"
        "    \"severity\": \"critical|high|medium|low|info\",\n"
        "    \"evidence\": \"Exact line or snippet from the config\",\n"
        "    \"risk\": \"Short explanation of why this is risky\",\n"
        "    \"suggested_fix\": \"Practical mitigation recommendation\",\n"
        "    \"detector\": \"model\",\n"
        "    \"source\": \"gemini\"\n"
        "  }\n"
        "]\n\n"
        "Only report real configuration security issues. Focus on SSH authentication risks, public service exposure, "
        "overly permissive firewall/network rules, missing Nginx security headers, unsafe Docker privileges or exposed "
        "ports, and insecure Kubernetes networking/securityContext settings.\n\n"
        "If no issues are found, return [].\n\n"
        f"File path: {file_path}\n"
    )


def _strip_code_fences(text: str) -> str:
    stripped = (text or "").strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return stripped


def _write_empty_results(output_path: Path) -> None:
    write_csv(output_path, [], HEADERS)


def prompt_mode(config_files: Iterable[Path], results_dir: Path) -> list[Finding]:
    prompt_dir = results_dir / "model_prompts"
    ensure_dir(prompt_dir)
    for path in config_files:
        config_type = infer_config_type(path)
        content = read_text_file(path)
        prompt = _build_prompt(config_type, path.name, content)
        prompt_path = prompt_dir / f"{path.stem}_prompt.txt"
        prompt_path.write_text(prompt, encoding="utf-8")

    _write_empty_results(results_dir / "model_findings.csv")
    return []


def manual_mode(manual_json_path: Path, results_dir: Path) -> list[Finding]:
    data = safe_json_load(manual_json_path)
    findings: list[Finding] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                findings.append(coerce_finding(item, detector_default="model", source_default="manual"))
    else:
        print("Warning: manual model findings missing or invalid. Writing empty model_findings.csv.")

    write_csv(results_dir / "model_findings.csv", findings_to_rows(findings), HEADERS)
    return findings


def api_mode(config_files: Iterable[Path], results_dir: Path) -> list[Finding]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Warning: OPENAI_API_KEY not set. Skipping API mode and writing empty model_findings.csv.")
        _write_empty_results(results_dir / "model_findings.csv")
        return []

    try:
        import openai
    except ImportError:
        print("Warning: openai package not installed. Skipping API mode and writing empty model_findings.csv.")
        _write_empty_results(results_dir / "model_findings.csv")
        return []

    findings: list[Finding] = []
    for path in config_files:
        config_type = infer_config_type(path)
        content = read_text_file(path)
        prompt = _build_prompt(config_type, path.name, content)
        try:
            if hasattr(openai, "OpenAI"):
                client = openai.OpenAI(api_key=api_key)
                response = client.responses.create(
                    model="gpt-4o-mini",
                    input=prompt,
                    temperature=0,
                )
                output_text = getattr(response, "output_text", None)
                if not output_text and getattr(response, "output", None):
                    output_text = json.dumps(response.output)
            else:
                openai.api_key = api_key
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0,
                )
                output_text = response["choices"][0]["message"]["content"]

            parsed = json.loads(output_text)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        findings.append(coerce_finding(item, detector_default="model", source_default="api"))
        except Exception as exc:
            print(f"Warning: API call failed for {path.name}: {exc}")

    write_csv(results_dir / "model_findings.csv", findings_to_rows(findings), HEADERS)
    return findings


def gemini_mode(
    config_files: Iterable[Path],
    results_dir: Path,
    gemini_model: str,
    gemini_delay: float,
    gemini_limit: int | None,
) -> list[Finding]:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("Warning: GEMINI_API_KEY not set. Writing empty model_findings.csv.")
        _write_empty_results(results_dir / "model_findings.csv")
        return []

    try:
        from google import genai
    except ImportError:
        print("Warning: google-genai package not installed. Writing empty model_findings.csv.")
        _write_empty_results(results_dir / "model_findings.csv")
        return []

    findings: list[Finding] = []
    config_list = list(config_files)
    if gemini_limit is not None:
        config_list = config_list[:gemini_limit]

    client = genai.Client(api_key=api_key)
    source = f"gemini:{gemini_model}"

    for path in config_list:
        config_type = infer_config_type(path)
        content = read_text_file(path)
        prompt = _build_gemini_prompt(config_type, path.name, path.as_posix(), content)
        try:
            response = client.models.generate_content(model=gemini_model, contents=prompt)
            output_text = getattr(response, "text", None) or ""
            cleaned = _strip_code_fences(output_text)
            parsed = json.loads(cleaned) if cleaned else []
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        finding = coerce_finding(item, detector_default="model", source_default=source)
                        finding.detector = "model"
                        finding.source = source
                        findings.append(finding)
            else:
                print(f"Warning: Gemini response was not a JSON list for {path.name}.")
        except Exception as exc:
            print(f"Warning: Gemini call failed for {path.name}: {exc}")

        if gemini_delay and gemini_delay > 0:
            time.sleep(gemini_delay)

    write_csv(results_dir / "model_findings.csv", findings_to_rows(findings), HEADERS)
    return findings


def run_model_analyzer(
    config_files: Iterable[Path],
    results_dir: Path,
    mode: str,
    manual_json_path: Path,
    gemini_model: str | None = None,
    gemini_delay: float = 1.0,
    gemini_limit: int | None = None,
) -> list[Finding]:
    mode = mode.lower()
    if mode == "prompt":
        return prompt_mode(config_files, results_dir)
    if mode == "manual":
        return manual_mode(manual_json_path, results_dir)
    if mode == "api":
        return api_mode(config_files, results_dir)
    if mode == "gemini":
        return gemini_mode(
            config_files,
            results_dir,
            gemini_model or "gemini-1.5-flash",
            gemini_delay,
            gemini_limit,
        )

    print(f"Warning: Unknown model mode '{mode}'. Defaulting to prompt mode.")
    return prompt_mode(config_files, results_dir)
