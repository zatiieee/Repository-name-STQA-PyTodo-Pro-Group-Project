# STQA Group Project — PyTodo Pro Quality Evaluation

Repository for **TEB3433 / TFB3433 — Software Testing and Quality Assurance** (Lecturer: Dr. Abdullateef). Evaluates **PyTodo Pro** (`pytodo_pro_student_original/`, Flask 3.0.3 + SQLite 3) across Weeks 1–8 without modifying the original target application source code.

## Team Roster & Governance Roles
- **Member 1 (Izzati)** — QA / Test Lead (`01_Black_Box`, `07_Test_Management`)
- **Member 2 (Hafizah)** — Automation & Tool Coordinator (`02_White_Box_Coverage`, `06_Automation_Regression` — completed collaboratively)
- **Member 3 (Hanif)** — Test Design Coordinator (`03_Special_Testing`, `04_Web_API`)
- **Member 4 (Syarafuddin)** — Defect & Metrics Coordinator (`05_Security_Performance`, `08_Final_QA_Report`)

## Repository Structure
| Folder | Phase / Deliverable Scope | Key Metrics |
|---|---|---|
| `00_Project_Guideline/` | Official course project guideline & templates (`Group Project (6).pdf`) | 8 testing/QA phases |
| `pytodo_pro_student_original/` | Untouched Flask 3.0.3 + SQLite 3 target app (`app.py`, `helpers.py`, `templates/`, `static/`) | Read-only baseline |
| `01_Black_Box/` | Manual EP, BVA, Decision Table & State Transition tests | 25 tests (`23P / 2F`), 2 defects |
| `02_White_Box_Coverage/` | PyTest + `pytest-cov` unit tests on `helpers.py` | 23 tests (`20P / 3F`), `100%` module cov, 3 defects |
| `03_Special_Testing/` | GUI, Cross-Browser, Nielsen Usability, WCAG 2.1 AA & Mobile audits | 25 table checks + `W3-CMP-04`, 3 defects |
| `04_Web_API/` | Web workflow & JSON REST API integration tests | 14 cases (`7P / 7F`), 5 defects |
| `05_Security_Performance/` | STRIDE security probes & stepped-load concurrency benchmarks (1–50 VUs) | 26 security (`5P / 21F`) + 6 SLAs (`4P / 2F`), 20 defects |
| `06_Automation_Regression/` | POM Selenium + PyTest API & unit CI regression suite | 22 logical (`30` PyTest items: `22P / 8F`); CI gate `22/22` |
| `07_Test_Management/` | IEEE 29119-3 Software Test Plan, 18-row RTM, 142-test & 33->28 defect master | `142` entries (`93P / 49F = 65.5%`); `28` distinct issues |
| `08_Final_QA_Report/` | Capstone Final QA Report, formula metrics workbook & charts | Overall Verdict: **`NO-GO`** (4 P0, 10 P1, 9 P2, 5 P3) |

## Environment Setup & Running Automated Tests (Windows PowerShell)
```powershell
# 1. Create & activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install runtime & test dependencies
pip install flask==3.0.3 pytest==9.2.0 pytest-cov requests selenium

# 3. Run Week 5 Security & Performance suites (isolated subprocess server)
cd 05_Security_Performance
python security_tests.py
python performance_test.py

# 4. Run Week 6 CI Smoke Gate (22/22 stable regression tests)
cd ..\06_Automation_Regression
pytest -v -m "not known_bug"

# 5. Run Full Week 6 Regression Suite (includes 8 @known_bug guards -> 22P / 8F)
pytest -v
```
