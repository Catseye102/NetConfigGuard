from __future__ import annotations

import argparse
from pathlib import Path

from .evaluate import run_evaluation
from .hybrid_detector import run_hybrid_detector
from .model_analyzer import run_model_analyzer
from .rule_checker import run_rule_checker
from .utils import discover_config_files, ensure_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NetConfigGuard: model-assisted config verification")
    parser.add_argument("--configs", default="data/configs", help="Path to configuration root")
    parser.add_argument("--results", default="results", help="Path to output results directory")
    parser.add_argument(
        "--model-mode",
        default="prompt",
        choices=["prompt", "manual", "api", "gemini"],
        help="Model analyzer mode",
    )
    parser.add_argument(
        "--manual-model-json",
        default="data/model_outputs/manual_model_findings.json",
        help="Path to manual model findings JSON",
    )
    parser.add_argument(
        "--gemini-model",
        default="gemini-1.5-flash",
        help="Gemini model name (used when --model-mode gemini)",
    )
    parser.add_argument(
        "--gemini-delay",
        type=float,
        default=1.0,
        help="Delay in seconds between Gemini API calls",
    )
    parser.add_argument(
        "--gemini-limit",
        type=int,
        default=None,
        help="Limit number of config files analyzed in Gemini mode",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config_root = Path(args.configs)
    results_dir = Path(args.results)
    ensure_dir(results_dir)

    config_files = discover_config_files(config_root)

    rule_findings = run_rule_checker(config_files, results_dir / "rule_findings.csv")
    model_findings = run_model_analyzer(
        config_files,
        results_dir,
        args.model_mode,
        Path(args.manual_model_json),
        args.gemini_model,
        args.gemini_delay,
        args.gemini_limit,
    )
    hybrid_findings = run_hybrid_detector(
        rule_findings,
        model_findings,
        results_dir / "hybrid_findings.csv",
    )

    run_evaluation(results_dir, config_root)

    print("NetConfigGuard run complete.")
    print(f"Configs scanned: {len(config_files)}")
    print(f"Rule findings: {len(rule_findings)}")
    print(f"Model findings: {len(model_findings)}")
    print(f"Hybrid findings: {len(hybrid_findings)}")
    print("Outputs:")
    print(f"- {results_dir / 'rule_findings.csv'}")
    print(f"- {results_dir / 'model_findings.csv'}")
    print(f"- {results_dir / 'hybrid_findings.csv'}")
    print(f"- {results_dir / 'summary.csv'}")
    print(f"- {results_dir / 'issues_by_config_type.png'}")
    print(f"- {results_dir / 'issues_by_severity.png'}")
    if args.model_mode == "prompt":
        print(f"- {results_dir / 'model_prompts'}")


if __name__ == "__main__":
    main()
