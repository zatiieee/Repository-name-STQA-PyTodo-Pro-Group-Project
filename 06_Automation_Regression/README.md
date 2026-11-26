# Automation & Regression Testing (Week 6)

**Owner:** Member 2 (Consolidated for Group Project)  
**Target Application:** PyTodo Pro (`../pytodo_pro_student_original`)  
**Tested Environment:** Windows 11, Python 3.14.0, PyTest 9.2.0, Selenium 4.54.0 (Headless Google Chrome), Flask 3.0.3

## Contents
- `Week6_Automation_Regression_Report.docx` — Week 6 report (Basic English, black typography) covering automation candidate selection, manual-to-automated mapping, Page Object & PyTest setup, pass/fail results (CI gate vs. full regression), UI & defect screenshots, benefits, limitations, and next steps.
- `Week6_Automation_Regression.xlsx` — Multi-sheet workbook (`Overview`, `Automation Candidates`, `Manual-to-Auto Traceability`, `Regression Test Cases` using the 12-field assignment template, `Execution Summary` parsed from `evidence/junit_regression.xml`).
- `pytest.ini` — Registers PyTest markers (`ui`, `api`, `unit`, `known_bug`) with strict marker checking and disables `.pytest_cache` clutter.
- `requirements-regression.txt` — Pinned dependencies (`Flask==3.0.3`, `requests==2.34.2`, `pytest==9.2.0`, `selenium==4.54.0`, `openpyxl==3.1.5`, `python-docx==1.2.0`).
- `pages.py` — Lightweight Page Object Models (`AuthPage`, `TasksPage`, `TaskFormPage`, `DashboardPage`).
- `conftest.py` — Isolated PyTodo Pro subprocess fixture (`tempfile.TemporaryDirectory`), server `stderr` logging, explicit-only waits (`implicitly_wait(0)`), alert-safe teardown, `unique_user()` helper, and automatic screenshot-on-failure hook.
- `test_selenium_ui_regression.py` — 14 Selenium UI tests (22 parametrized executions, `@pytest.mark.ui`).
- `test_api_regression.py` — 7 REST API regression tests (`@pytest.mark.api`).
- `test_unit_regression.py` — 1 pure unit regression guard for `helpers.py` (`@pytest.mark.unit`).
- `evidence/` — Reproducible outputs (`ci_gate_execution_log.txt`, `regression_execution_log.txt`, `junit_regression.xml`, `regression_results.json`, `server_errors.log`, `selenium_tasks.png`, `selenium_dashboard.png`, and `failures/*.png`).

## Setup & Running the Regression Suite

**Prerequisites:** Google Chrome installed (or set `CHROME_BINARY` environment variable) and Python 3.10+.

```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r 06_Automation_Regression\requirements-regression.txt

cd 06_Automation_Regression

# 1. CI Gate (baseline working features — exits 0 cleanly):
pytest -v -m "not known_bug"

# 2. Full Regression Suite (includes 8 known open-defect guards — exits 1 while bugs remain unpatched):
pytest -v --junitxml=evidence\junit_regression.xml
```

To save the CLI log on Windows PowerShell, pipe with `2>&1 | Tee-Object -FilePath evidence\regression_execution_log.txt`. Both suites use temporary SQLite databases and `sys.dont_write_bytecode = True`, leaving `pytodo_pro_student_original/` completely untouched.
