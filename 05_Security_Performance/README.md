# Security & Performance Testing (Week 5)

**Owner:** Member 4  
**Target Application:** PyTodo Pro (`../pytodo_pro_student_original`)  
**Tested Environment:** Windows 11, Python 3.14.0, Flask 3.0.3, Werkzeug 3.1.9, Jinja2 3.1.6, SQLite 3

## Contents
- `Week5_Security_Performance_Report.docx` — Full Week 5 report covering ethical boundaries, STRIDE threat model, security testing & defect-chaining analysis, Week 2 continuity, ISO/IEC 25010 quality mapping, controlled subprocess performance methodology (endpoints, multi-tenant seed, SLA thresholds, charts), limitations, and prioritised P0–P3 recommendations.
- `Week5_Security_Performance.xlsx` — Multi-sheet workbook containing:
  - `Overview` (combined Security + Performance KPIs and severity distribution)
  - `STRIDE Threat Table` (`STR-01` to `STR-14`, mapped to CWE & OWASP)
  - `Security Test Cases` (`TC-SEC-001` to `TC-SEC-026`, 12-field assignment template)
  - `Performance Test Cases` (`TC-PERF-001` to `TC-PERF-006`, 12-field assignment template with pre-execution SLA targets)
  - `Performance Results` (20 benchmark runs across `GET /api/tasks`, `GET /api/dashboard`, `GET /`, `POST /api/tasks`, `Mixed 70R/20D/10W`, and `POST /api/login`)
  - `Defect Log` (`DEF-SP-001` to `DEF-SP-020`, 12-field assignment template + CWE, OWASP Top 10 / API Top 10, CVSS v3.1)
- `security_tests.py` — Automated, safe, non-destructive security verification suite (`TC-SEC-001`–`026`) with regression-ready dynamic assertions and masked cookie artifacts.
- `performance_test.py` — Automated stepped-load benchmark (`TC-PERF-001`–`006`) spawning PyTodo Pro in an isolated external subprocess (eliminating shared client/server CPython GIL bias).
- `requirements-test.txt` — Pinned dependencies needed to execute scripts and regenerate deliverables.
- `evidence/` — Reproducible execution outputs (overwritten upon script re-execution):
  - `security_results.json` & `security_execution_log.txt`
  - `performance_results.json`, `performance_results.csv`, `performance_execution_log.txt`, & `server_errors.log`
  - `perf_response_time.png` & `perf_throughput_error.png`

## Setup & Running Automated Week 5 Tests

Create a virtual environment outside `pytodo_pro_student_original/` (or in the repo root) and install `requirements-test.txt`:

```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r 05_Security_Performance\requirements-test.txt

cd 05_Security_Performance
python security_tests.py      # ~10 seconds
python performance_test.py    # ~65 seconds
```

```bash
# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
pip install -r 05_Security_Performance/requirements-test.txt

cd 05_Security_Performance
python security_tests.py
python performance_test.py
```

> **Note:** Both scripts spin up an isolated temporary SQLite database via `tempfile.TemporaryDirectory()` and set `sys.dont_write_bytecode = True`, leaving `pytodo_pro_student_original/` unmodified. Re-running the scripts overwrites files inside `evidence/`.
