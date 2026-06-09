NetConfigGuard
Model-Assisted Verification and Repair of LLM-Generated Network Security Configurations

Overview
NetConfigGuard is a Python research prototype for scanning LLM-generated network/security configuration files. It checks SSH, firewall, Nginx, Docker Compose, and Kubernetes configurations for insecure settings using a rule-based verifier and an optional model-assisted analyzer.

Requirements
- Python 3.10+
- Install dependencies with:

pip install -r requirements.txt

Main Commands

Run the default prompt mode:
python -m src.main --model-mode prompt

Run manual model-output mode:
python -m src.main --model-mode manual

Run Gemini API mode with the model used in the final report:
python -m src.main --model-mode gemini --gemini-model gemini-2.5-flash

Run Gemini API mode on only a few files:
python -m src.main --model-mode gemini --gemini-model gemini-2.5-flash --gemini-limit 3

Regenerate summary tables and charts:
python -m src.evaluate

Run tests:
python -m pytest tests

Gemini API Setup
Gemini mode requires a Gemini API key stored in the GEMINI_API_KEY environment variable.

Windows PowerShell:
$env:GEMINI_API_KEY="your_api_key_here"

macOS/Linux:
export GEMINI_API_KEY="your_api_key_here"

Note: Gemini API mode is optional. If the key, quota, or model is unavailable, prompt mode and manual mode still work.

Important Note on Model
The final report uses Gemini 2.5 Flash. Do not use gemini-1.5-flash unless it is available in the current Gemini API, because it was not available during the final project run.

Project Structure
data/configs/                 Sample configuration files
data/prompts/prompts.csv       Baseline and security-aware prompts
data/model_outputs/            Manual model-output JSON file
src/                           Source code
tests/                         Rule-checker tests
results/                       Generated CSV files, charts, and prompts
README.txt                     This file
requirements.txt               Python dependencies

Output Files
After running the project, outputs are written to the results/ folder:

results/rule_findings.csv
results/model_findings.csv
results/hybrid_findings.csv
results/summary.csv
results/issues_by_config_type.png
results/issues_by_severity.png

Recommended Run for Grading
From the project root, run:

pip install -r requirements.txt
python -m src.main --model-mode manual
python -m src.evaluate
python -m pytest tests

Optional Gemini verification:

python -m src.main --model-mode gemini --gemini-model gemini-2.5-flash --gemini-limit 1
python -m src.evaluate

Expected Project Behavior
- Scans 30 sample configuration files.
- Generates rule-based findings.
- Loads manual model findings or uses Gemini API mode if configured.
- Produces hybrid findings with de-duplication.
- Generates summary CSV and two result charts.
- Tests should pass.
