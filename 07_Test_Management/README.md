# Test Management

Owner: Member 1 (Izzati) — Consolidated across Weeks 1–6 by Group Test Leads

## Team Governance Roster
- **Member 1 (Izzati)** — QA / Test Lead (`01_Black_Box`, `07_Test_Management`)
- **Member 2 (Hafizah)** — Automation & Tool Coordinator (`02_White_Box_Coverage`, `06_Automation_Regression` — finished collaboratively)
- **Member 3 (Hanif)** — Test Design Coordinator (`03_Special_Testing`, `04_Web_API`)
- **Member 4 (Syarafuddin)** — Defect & Metrics Coordinator (`05_Security_Performance`, `08_Final_QA_Report`)

## Contents
- `Week7_Software_Test_Plan.docx` — IEEE 29119-3 aligned Software Test Plan & Consolidated Report (Basic English, black `#000000` Times New Roman): objectives, in/out-of-scope boundaries, multi-phase strategy, Severity x Priority SLAs, defect lifecycle & bug-fix retest protocol, environments/data/tools, RACI & Week 1–8 schedule, Entry/Suspension/Resumption/Exit criteria, 18-requirement RTM digest, deduplication reconciliations, and Product/Project Risk Register.
- `Week7_Test_Management_Master.xlsx` — Live formula-driven Excel workbook (`4` sheets):
  1. `Overview` — Dynamic `=SUM`, `=IFERROR`, and `=COUNTIFS` KPIs (`142` entries: `93 Pass / 49 Fail = 65.5%`), plus Raw (`33`) vs. Net Deduplicated (`28`) severity/priority breakdown and Week 6 CI bridge (`14P/8F` logical = `22P/8F` PyTest items).
  2. `Updated RTM` — Assertion-verified `18`-row traceability matrix (`REQ-01`–`REQ-18`) using the exact 6-field course template, mapping `100%` of the `142` tests and `33` defect records with zero orphaned IDs.
  3. `Master Test Repository` — All `142` normalized entries (`25` W1 + `23` W2 + `26` W3 incl. `W3-CMP-04` + `14` W4 + `32` W5 + `22` logical W6) in the 12-field course template + `Source Phase & Owner`.
  4. `Consolidated Defect Log` — All `33` raw defect records (`DEF-001..002`, `DEF-WB-001..003`, `DEF-004..006`, `DEF-API-001..005`, `DEF-SP-001..020`) in the 12-field template + `Source Week`, `Duplicate Group`, `Record Role`, and `Cross-Week Reconciliation`.

## Key Reconciliation & Verification Commands
- **Deduplication Summary:** `5` duplicates grouped (`GRP-01`..`GRP-05`), reducing `33` raw defects (`4 Crit, 11 Maj, 12 Mod, 6 Min`) to **`28` net distinct issues** (`4 Crit, 10 Maj, 9 Mod, 5 Min` — `26 Confirmed + 2 Retest`).
- **Disputed Findings Queued for `Retest`:** `DEF-004` (W3 delete prompt claim vs. `templates/index.html:50` & W6 `TC-REG-010`) and `DEF-API-002` (W4 `GET` IDOR claim vs. `app.py:394` & W5/W6 `404`, distinct from real `DELETE` IDOR `DEF-SP-013` at `app.py:459`).
- **Re-Run Automated Regression & CI Gate (Verification):**
  ```powershell
  # CI Smoke Gate (passes 22/22 in 34.55s)
  cd 06_Automation_Regression
  pytest -v -m "not known_bug"

  # Full Regression Suite (22 Pass / 8 Known-Bug Fail across 30 items in 39.52s)
  pytest -v

  # Re-run Week 5 Security & Performance Benchmarks
  cd ..\05_Security_Performance
  python security_tests.py
  python performance_test.py
  ```
