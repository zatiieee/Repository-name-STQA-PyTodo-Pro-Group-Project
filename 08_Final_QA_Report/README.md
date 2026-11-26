# Final QA Report

Owner: Member 4 (Syarafuddin) — Team: Izzati (Member 1), Hafizah (Member 2), Hanif (Member 3), Syarafuddin (Member 4)

## Contents
- `Week8_Final_QA_Report.docx` — Capstone Final QA & Quality Evaluation Report (Basic English, pure black `#000000` Times New Roman, no headers/footers, no commit hashes):
  - Evidence-based `NO-GO` production verdict (testing exposes bugs, never proves zero hidden bugs)
  - Team governance roles (`Izzati`, `Hafizah`, `Hanif`, `Syarafuddin`) and **Quality Evolution Across Weeks 1–8**
  - Planned (`142`), Executed (`142`, `100%`), Passed (`93`, `65.5%`), Failed (`49`, `34.5%`), Blocked (`0`), Not Run (`0`), plus **Defect Detection Rate** by phase (`62.5%` W5, `35.7%` W4 vs. `8.0%` W1)
  - Severity-aligned defect breakdown (`33` raw -> `28` net distinct: `4` Crit `P0`, `10` Maj `P1`, `9` Mod `P2`, `5` Min `P3`) across `6` application modules
  - Coverage & CI automation interpretation (`helpers.py` `100%` branch-coverage paradox vs. `482` `app.py` lines; `22/22` CI smoke vs. `8` `@known_bug` guards)
  - Unified `7` ISO/IEC 25010 evaluations, `RR-01`–`RR-05` residual risks, `UT-01`–`UT-05` untested areas, `QC` vs. `QA` preventive controls, and Final Submission Checklist readiness
- `Week8_Final_QA_Metrics.xlsx` — Formula-driven executive metrics workbook (`4` landscape A4 tabs, zero clipped cells, Data Validation dropdowns)
- `evidence/qa_phase_metrics.png` — Phase execution outcomes & pass rate chart (`Weeks 1–6`)
- `evidence/qa_defect_distribution.png` — Net distinct defect distribution by Severity and sorted Module (`n = 28`)

## Quick Verification Commands
```powershell
# Verify Week 6 automated CI smoke gate (22/22 Pass)
cd ..\06_Automation_Regression
pytest -v -m "not known_bug"

# Verify full regression suite (22 Pass / 8 Known-Bug Fail across 30 items)
pytest -v

# Re-run Week 5 Security & Performance suites
cd ..\05_Security_Performance
python security_tests.py
python performance_test.py
```
