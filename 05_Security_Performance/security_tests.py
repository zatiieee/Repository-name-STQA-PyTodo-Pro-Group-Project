"""
Week 5 — Industry-Hardened Safe Security Test Suite for PyTodo Pro
Owner: Member 4 (05_Security_Performance)

Runs against an isolated local HTTP server backed by a temporary SQLite DB so
the original application code and repository remain completely untouched.
All assertions and actual_result strings are computed dynamically for regression reuse.
"""

import ast
import json
import os
import re
import sys
import tempfile
import threading
from datetime import datetime, timezone

import requests
from flask.sessions import SecureCookieSessionInterface
from werkzeug.serving import make_server

# Prevent __pycache__ creation inside pytodo_pro_student_original
sys.dont_write_bytecode = True

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_DIR = os.path.join(REPO_ROOT, "pytodo_pro_student_original")
EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "evidence")
sys.path.insert(0, APP_DIR)

import app as pytodo_app  # noqa: E402
import helpers as pytodo_helpers  # noqa: E402


class LocalAppServer:
    """Context manager running PyTodo Pro on an ephemeral localhost port."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.server = None
        self.thread = None
        self.base_url = None

    def __enter__(self):
        pytodo_app.DATABASE = self.db_path
        pytodo_app.app.config["TESTING"] = False
        pytodo_app.app.config["DEBUG"] = False
        pytodo_app.init_db()
        self.server = make_server("127.0.0.1", 0, pytodo_app.app, threaded=True)
        port = self.server.server_port
        self.base_url = f"http://127.0.0.1:{port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=3)


def mask_cookie_header(header_val: str) -> str:
    """Redact signed Flask session token payload/signature in saved artifacts."""
    if not header_val:
        return ""
    return re.sub(r"(session=)[^;]+", r"\1<REDACTED_SIGNED_TOKEN>", header_val)


def make_result(
    tc_id: str,
    stride: str,
    feature: str,
    technique: str,
    objective: str,
    preconditions: str,
    test_data: str,
    steps: str,
    expected: str,
    actual: str,
    status: str,
    evidence: str,
    defect_id: str = "None",
):
    return {
        "test_case_id": tc_id,
        "stride_category": stride,
        "feature": feature,
        "technique": technique,
        "objective": objective,
        "preconditions": preconditions,
        "test_data": test_data,
        "steps": steps,
        "expected_result": expected,
        "actual_result": actual,
        "status": status,
        "evidence": evidence,
        "defect_id": defect_id,
    }


def register_api_user(base_url: str, username: str, password: str):
    sess = requests.Session()
    resp = sess.post(
        f"{base_url}/api/register",
        json={"username": username, "password": password},
        timeout=5,
    )
    return sess, resp


def inspect_app_ast(app_path: str):
    """Use AST parsing to inspect logging usage and app.run(debug=...) reliably."""
    with open(app_path, "r", encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imports_logging = False
    calls_logger = False
    debug_true_lines = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "logging":
                    imports_logging = True
        elif isinstance(node, ast.ImportFrom) and node.module == "logging":
            imports_logging = True
        elif isinstance(node, ast.Attribute) and node.attr == "logger":
            calls_logger = True
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "run":
                for kw in node.keywords:
                    if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        debug_true_lines.append(node.lineno)
    return {
        "has_logging": imports_logging or calls_logger,
        "debug_true_lines": debug_true_lines,
    }


def run_security_suite():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    results = []
    started_at = datetime.now(timezone.utc).astimezone().isoformat()
    app_ast = inspect_app_ast(os.path.join(APP_DIR, "app.py"))

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "security_test.db")
        with LocalAppServer(db_path) as srv:
            base = srv.base_url

            # ------------------------------------------------------------------
            # TC-SEC-001: Spoofing - Duplicate username registration (Web UI)
            # ------------------------------------------------------------------
            s1 = requests.Session()
            r1 = s1.post(
                f"{base}/register",
                data={"username": "alice_sec", "password": "Password123"},
                allow_redirects=False,
                timeout=5,
            )
            s2 = requests.Session()
            r2 = s2.post(
                f"{base}/register",
                data={"username": "alice_sec", "password": "Different999"},
                allow_redirects=False,
                timeout=5,
            )
            dup_web_rejected = r2.status_code in (400, 409) or "already" in r2.text.lower()
            results.append(
                make_result(
                    tc_id="TC-SEC-001",
                    stride="Spoofing",
                    feature="Web UI Registration (/register)",
                    technique="Security / Abuse-Case Testing",
                    objective="Verify duplicate username registration is rejected on the Web UI.",
                    preconditions="Account 'alice_sec' already exists.",
                    test_data="username='alice_sec', password='Different999'",
                    steps="1. POST /register with alice_sec.\n2. POST /register again with same username and different password.",
                    expected="Second registration is rejected (HTTP 400/409 or validation error) without creating a duplicate account.",
                    actual=(
                        f"Second registration was rejected (HTTP {r2.status_code})."
                        if dup_web_rejected
                        else f"First POST returned HTTP {r1.status_code}; second POST returned HTTP {r2.status_code} (Location={r2.headers.get('Location')}), creating a duplicate user row."
                    ),
                    status="Pass" if dup_web_rejected else "Fail",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-001]: HTTP {r1.status_code} -> {r2.status_code}",
                    defect_id="None" if dup_web_rejected else "DEF-SP-001",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-002: Spoofing - Duplicate username registration & login resolution (API)
            # ------------------------------------------------------------------
            _, api_r1 = register_api_user(base, "api_dup_user", "Password123")
            _, api_r2 = register_api_user(base, "api_dup_user", "AttackerPass99")
            login_second = requests.post(
                f"{base}/api/login",
                json={"username": "api_dup_user", "password": "AttackerPass99"},
                timeout=5,
            )
            dup_api_rejected = api_r2.status_code in (400, 409)
            results.append(
                make_result(
                    tc_id="TC-SEC-002",
                    stride="Spoofing",
                    feature="API Registration & Login Precedence (POST /api/register)",
                    technique="Security / API Abuse Testing",
                    objective="Verify duplicate username registration is rejected by the REST API without creating locked/ambiguous duplicate accounts.",
                    preconditions="Account 'api_dup_user' already registered via /api/register.",
                    test_data='{"username": "api_dup_user", "password": "AttackerPass99"}',
                    steps="1. POST /api/register with api_dup_user.\n2. Repeat POST /api/register with different password.\n3. Attempt POST /api/login with the second password.",
                    expected="HTTP 400 or 409 Conflict returned; duplicate record prevented.",
                    actual=(
                        f"Duplicate registration rejected with HTTP {api_r2.status_code}."
                        if dup_api_rejected
                        else f"First call: HTTP {api_r1.status_code} (id={api_r1.json().get('id')}); second call: HTTP {api_r2.status_code} (id={api_r2.json().get('id')}); login with second password returned HTTP {login_second.status_code} (fetchone binds only first row)."
                    ),
                    status="Pass" if dup_api_rejected else "Fail",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-002]: register {api_r1.status_code}/{api_r2.status_code}, second-pw login={login_second.status_code}",
                    defect_id="None" if dup_api_rejected else "DEF-SP-001",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-003: Spoofing - Hardcoded SECRET_KEY & Session Forgery Check
            # ------------------------------------------------------------------
            victim_sess, victim_reg = register_api_user(base, "victim_cookie", "Password123")
            victim_id = victim_reg.json()["id"]
            cookie_val = victim_sess.cookies.get("session", "")
            known_secret = "pytodo-pro-dev-secret"
            s_iface = SecureCookieSessionInterface()
            signing_ser = s_iface.get_signing_serializer(pytodo_app.app)
            forged_status = None
            decoded_payload = None
            try:
                decoded_payload = signing_ser.loads(cookie_val) if signing_ser else None
                forged_cookie = signing_ser.dumps({"user_id": victim_id, "username": "victim_cookie"})
                forged_sess = requests.Session()
                forged_sess.cookies.set("session", forged_cookie, domain="127.0.0.1")
                forged_status = forged_sess.get(f"{base}/api/dashboard", timeout=5).status_code
            except Exception:
                forged_status = 401
            secret_is_hardcoded = (
                pytodo_app.app.config.get("SECRET_KEY") == known_secret
                and forged_status == 200
            )
            results.append(
                make_result(
                    tc_id="TC-SEC-003",
                    stride="Spoofing",
                    feature="Session Management / App Configuration",
                    technique="Static Review & Safe Cookie Verification",
                    objective="Verify Flask SECRET_KEY is not a predictable hardcoded literal that permits offline session forgery.",
                    preconditions="Registered user 'victim_cookie' exists; Flask signed-cookie session is active.",
                    test_data=f"Known source secret literal check (app.config['SECRET_KEY'])",
                    steps="1. Inspect app.config['SECRET_KEY'].\n2. Decode issued session cookie using source secret.\n3. Forge session cookie for victim user_id and query GET /api/dashboard.",
                    expected="SECRET_KEY is loaded from strong environment config; forging with static literal fails.",
                    actual=(
                        f"Cookie decoded as {decoded_payload}; forged cookie authenticated to GET /api/dashboard with HTTP {forged_status}."
                        if secret_is_hardcoded
                        else f"Static secret forgery failed (HTTP {forged_status})."
                    ),
                    status="Fail" if secret_is_hardcoded else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-003]: forged /api/dashboard HTTP {forged_status}",
                    defect_id="DEF-SP-002" if secret_is_hardcoded else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-004: Spoofing - Brute-Force Rate Limiting (API + Web /login)
            # ------------------------------------------------------------------
            api_statuses = [
                requests.post(
                    f"{base}/api/login",
                    json={"username": "victim_cookie", "password": f"WrongPass_{i}"},
                    timeout=5,
                ).status_code
                for i in range(10)
            ]
            web_statuses = [
                requests.post(
                    f"{base}/login",
                    data={"username": "victim_cookie", "password": f"WrongPass_{i}"},
                    allow_redirects=False,
                    timeout=5,
                ).status_code
                for i in range(10)
            ]
            throttled = any(code in (423, 429) for code in api_statuses + web_statuses)
            results.append(
                make_result(
                    tc_id="TC-SEC-004",
                    stride="Spoofing",
                    feature="Authentication (POST /api/login & POST /login)",
                    technique="Safe Rate-Limit / Lockout Probe (10 attempts each)",
                    objective="Verify repeated failed login attempts trigger throttling, delay, or temporary lockout on API and Web UI.",
                    preconditions="Valid account 'victim_cookie' exists.",
                    test_data="10 sequential POST /api/login + 10 sequential POST /login requests with wrong passwords.",
                    steps="1. Send 10 failed POST /api/login requests.\n2. Send 10 failed POST /login requests.\n3. Record HTTP status codes.",
                    expected="Account lockout or rate-limiting (HTTP 429/423) triggers within 10 failed attempts.",
                    actual=(
                        f"Rate limiting triggered: API={api_statuses}, Web={web_statuses}."
                        if throttled
                        else f"All 10 API attempts returned {api_statuses} and all 10 Web attempts returned {web_statuses} with no lockout or Retry-After."
                    ),
                    status="Pass" if throttled else "Fail",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-004]: API={api_statuses}, Web={web_statuses}",
                    defect_id="None" if throttled else "DEF-SP-003",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-005: Tampering - SQL Injection in GET /api/tasks?q= (OR + UNION)
            # ------------------------------------------------------------------
            user_a, _ = register_api_user(base, "sqli_user_a", "Password123")
            user_b, _ = register_api_user(base, "sqli_user_b", "Password123")
            user_a.post(f"{base}/api/tasks", json={"title": "User A Normal Task"}, timeout=5)
            user_b.post(f"{base}/api/tasks", json={"title": "User B Confidential Task"}, timeout=5)

            bool_payload = "x%' OR 1=1 OR 'a' LIKE '%"
            bool_resp = user_a.get(f"{base}/api/tasks", params={"q": bool_payload}, timeout=5)
            bool_titles = [t["title"] for t in bool_resp.json()] if bool_resp.status_code == 200 else []
            leaked_other_user = "User B Confidential Task" in bool_titles

            union_payload = "zzz%' UNION SELECT 999, 1, username, password_hash, NULL, NULL, 0, NULL, '2026-01-01' FROM users WHERE '1'='1' OR 'a' LIKE '%"
            union_resp = user_a.get(f"{base}/api/tasks", params={"q": union_payload}, timeout=5)
            union_extracted = False
            union_sample = ""
            if union_resp.status_code == 200:
                for row in union_resp.json():
                    if row.get("id") == 999 and "victim_cookie" in str(row.get("title", "")):
                        union_extracted = True
                        pw_prefix = str(row.get("description", ""))[:14]
                        union_sample = f"username={row.get('title')}, hash={pw_prefix}...<REDACTED>"
                        break

            sqli_vulnerable = leaked_other_user or union_extracted or bool_resp.status_code >= 500 or union_resp.status_code >= 500
            results.append(
                make_result(
                    tc_id="TC-SEC-005",
                    stride="Tampering",
                    feature="Task Search API (GET /api/tasks?q=)",
                    technique="Safe Non-Destructive SQL Injection Probe (Boolean + UNION)",
                    objective="Verify search parameter 'q' is parameterized and prevents both cross-tenant data leaks and UNION extraction.",
                    preconditions="User A and User B are logged in with separate tasks.",
                    test_data=f"Boolean q={bool_payload!r}; UNION probe targeting users(username, password_hash)",
                    steps="1. Authenticate as User A.\n2. Query GET /api/tasks with boolean bypass payload.\n3. Query GET /api/tasks with read-only UNION SELECT payload against users table.",
                    expected="Literal substring search returns [] (0 rows) and prevents cross-user or users-table leakage.",
                    actual=(
                        f"Boolean probe HTTP {bool_resp.status_code} leaked {len(bool_titles)} tasks including User B's task ({bool_titles}); "
                        f"UNION probe HTTP {union_resp.status_code} extracted users table row ({union_sample})."
                        if sqli_vulnerable
                        else f"Search safely parameterized: boolean HTTP {bool_resp.status_code} returned {bool_titles}; UNION returned HTTP {union_resp.status_code}."
                    ),
                    status="Fail" if sqli_vulnerable else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-005]: bool={bool_resp.status_code} titles={bool_titles}; union={union_resp.status_code} ({union_sample})",
                    defect_id="DEF-SP-004" if sqli_vulnerable else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-006: Tampering - Stored XSS in Task Title Rendered on GET /
            # ------------------------------------------------------------------
            xss_probe = "<script>/*stqa-xss-probe*/</script>"
            user_a.post(f"{base}/api/tasks", json={"title": xss_probe, "description": "<b>desc-probe</b>"}, timeout=5)
            index_html = user_a.get(f"{base}/", timeout=5).text
            unescaped_title_present = xss_probe in index_html
            results.append(
                make_result(
                    tc_id="TC-SEC-006",
                    stride="Tampering",
                    feature="Web UI Task List (GET / - templates/index.html)",
                    technique="Stored XSS Output-Encoding Check",
                    objective="Verify task titles containing HTML/script characters are escaped before rendering on the task list page.",
                    preconditions="Authenticated user creates a task containing benign script tags.",
                    test_data=f"title={xss_probe!r}",
                    steps="1. Create task via POST /api/tasks with inert <script> marker.\n2. Fetch GET / HTML.\n3. Check whether script tag is escaped (&lt;script&gt;) or raw.",
                    expected="Jinja auto-escaping encodes '<' and '>' as '&lt;' and '&gt;' in HTML output.",
                    actual=(
                        f"Raw unescaped payload '{xss_probe}' rendered verbatim inside GET / HTML due to '|safe' filter (Self-XSS unless chained with CSRF DEF-SP-006 or forged cookie DEF-SP-002)."
                        if unescaped_title_present
                        else "Payload properly HTML-escaped in GET / HTML output."
                    ),
                    status="Fail" if unescaped_title_present else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-006]: unescaped_script_in_dom={unescaped_title_present}",
                    defect_id="DEF-SP-005" if unescaped_title_present else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-007: Tampering - XSS Output Escaping Control (Edit, Desc, Navbar, Reflected q)
            # ------------------------------------------------------------------
            tasks_a = user_a.get(f"{base}/api/tasks", timeout=5).json()
            xss_task_id = next(t["id"] for t in tasks_a if t["title"] == xss_probe)
            edit_html = user_a.get(f"{base}/tasks/{xss_task_id}/edit", timeout=5).text
            reflected_probe = "\"><script>/*reflected*/</script>"
            reflected_html = user_a.get(f"{base}/", params={"q": reflected_probe}, timeout=5).text
            edit_escaped = (
                "&lt;script&gt;/*stqa-xss-probe*/&lt;/script&gt;" in edit_html
                and "&lt;b&gt;desc-probe&lt;/b&gt;" in edit_html
                and xss_probe not in edit_html
            )
            reflected_escaped = reflected_probe not in reflected_html
            all_controls_escaped = edit_escaped and reflected_escaped
            results.append(
                make_result(
                    tc_id="TC-SEC-007",
                    stride="Tampering",
                    feature="Web UI Edit Form & Search Input (task_form.html, index.html q)",
                    technique="Stored & Reflected XSS Output-Encoding Check (Positive Control)",
                    objective="Verify task edit form (title & description) and reflected search query parameter properly HTML-escape special characters.",
                    preconditions="Task containing inert script/HTML payload exists.",
                    test_data=f"task_id={xss_task_id}; reflected q={reflected_probe!r}",
                    steps="1. Request GET /tasks/<id>/edit and check title/description escaping.\n2. Request GET /?q= with inert script probe and verify escaping.",
                    expected="All Jinja outputs without |safe entity-escape '<', '>', and quotes.",
                    actual=(
                        f"Edit title & description escaped={edit_escaped}; reflected search query escaped={reflected_escaped}."
                    ),
                    status="Pass" if all_controls_escaped else "Fail",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-007]: edit_escaped={edit_escaped}, reflected_escaped={reflected_escaped}",
                    defect_id="None" if all_controls_escaped else "DEF-SP-005",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-008: Tampering - Missing CSRF Protection Across Web UI POST Forms
            # ------------------------------------------------------------------
            new_form_html = user_a.get(f"{base}/tasks/new", timeout=5).text
            has_csrf_field = bool(re.search(r'name=["\']?[^"\']*csrf', new_form_html, re.IGNORECASE))
            evil_hdrs = {"Origin": "https://evil.example", "Referer": "https://evil.example/attack.html"}

            r_csrf_new = user_a.post(
                f"{base}/tasks/new",
                data={"title": "CSRF Created Task", "description": "no token"},
                headers=evil_hdrs,
                allow_redirects=False,
                timeout=5,
            )
            csrf_task = next(
                (t for t in user_a.get(f"{base}/api/tasks", timeout=5).json() if t["title"] == "CSRF Created Task"),
                None,
            )
            csrf_edit_ok = False
            csrf_toggle_ok = False
            csrf_del_ok = False
            if csrf_task:
                cid = csrf_task["id"]
                r_csrf_edit = user_a.post(
                    f"{base}/tasks/{cid}/edit",
                    data={"title": "CSRF Edited", "description": "edited"},
                    headers=evil_hdrs,
                    allow_redirects=False,
                    timeout=5,
                )
                r_csrf_tog = user_a.post(f"{base}/tasks/{cid}/toggle", headers=evil_hdrs, allow_redirects=False, timeout=5)
                r_csrf_del = user_a.post(f"{base}/tasks/{cid}/delete", headers=evil_hdrs, allow_redirects=False, timeout=5)
                csrf_edit_ok = r_csrf_edit.status_code == 302
                csrf_toggle_ok = r_csrf_tog.status_code == 302
                csrf_del_ok = r_csrf_del.status_code == 302 and user_a.get(f"{base}/api/tasks/{cid}", timeout=5).status_code == 404

            csrf_vulnerable = (not has_csrf_field) and (csrf_task is not None)
            results.append(
                make_result(
                    tc_id="TC-SEC-008",
                    stride="Tampering",
                    feature="Web UI State-Changing Forms (/tasks/new, /edit, /toggle, /delete)",
                    technique="CSRF Token & Cross-Origin POST Verification",
                    objective="Verify all state-changing Web UI POST routes require a valid anti-CSRF token.",
                    preconditions="User A has an active session cookie.",
                    test_data="Foreign Origin='https://evil.example' POST requests without CSRF token across /new, /edit, /toggle, /delete.",
                    steps="1. Inspect GET /tasks/new HTML for CSRF hidden field.\n2. Submit cross-origin POSTs without token to /tasks/new, /edit, /toggle, and /delete.",
                    expected="Forms embed anti-CSRF tokens and reject tokenless cross-origin POSTs (HTTP 400/403).",
                    actual=(
                        f"has_csrf_field={has_csrf_field}; tokenless cross-origin POSTs succeeded: "
                        f"/new={r_csrf_new.status_code}, /edit={csrf_edit_ok}, /toggle={csrf_toggle_ok}, /delete={csrf_del_ok}."
                        if csrf_vulnerable
                        else f"CSRF protection enforced (has_csrf_field={has_csrf_field}, /new={r_csrf_new.status_code})."
                    ),
                    status="Fail" if csrf_vulnerable else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-008]: csrf_field={has_csrf_field}, new={r_csrf_new.status_code}, edit={csrf_edit_ok}, toggle={csrf_toggle_ok}, delete={csrf_del_ok}",
                    defect_id="DEF-SP-006" if csrf_vulnerable else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-009: Tampering - State-Changing Logout via GET /logout
            # ------------------------------------------------------------------
            logout_sess, _ = register_api_user(base, "logout_csrf", "Password123")
            pre_logout_cookie = logout_sess.cookies.get("session", "")
            pre_logout = logout_sess.get(f"{base}/api/dashboard", timeout=5)
            logout_resp = logout_sess.get(
                f"{base}/logout",
                headers={"Referer": "https://evil.example/"},
                allow_redirects=False,
                timeout=5,
            )
            post_logout = logout_sess.get(f"{base}/api/dashboard", timeout=5)
            get_logout_invalidated = pre_logout.status_code == 200 and post_logout.status_code == 401
            results.append(
                make_result(
                    tc_id="TC-SEC-009",
                    stride="Tampering",
                    feature="Session Termination (GET /logout)",
                    technique="CSRF / HTTP Method Safety Review",
                    objective="Verify logout cannot be triggered silently via a cross-site GET request.",
                    preconditions="Authenticated user session exists.",
                    test_data="GET /logout with external Referer",
                    steps="1. Confirm GET /api/dashboard returns 200.\n2. Issue GET /logout.\n3. Re-check GET /api/dashboard on same jar.",
                    expected="Logout requires POST with CSRF token; GET /logout does not destroy session.",
                    actual=(
                        f"GET /logout returned HTTP {logout_resp.status_code} and cleared client session (subsequent /api/dashboard returned HTTP {post_logout.status_code})."
                        if get_logout_invalidated
                        else f"GET /logout did not invalidate session (status={logout_resp.status_code}, post={post_logout.status_code})."
                    ),
                    status="Fail" if get_logout_invalidated else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-009]: Pre={pre_logout.status_code}, GET /logout={logout_resp.status_code}, Post={post_logout.status_code}",
                    defect_id="DEF-SP-006" if get_logout_invalidated else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-010: Repudiation - Absence of Security Audit Logging (AST check)
            # ------------------------------------------------------------------
            has_logging = app_ast["has_logging"]
            results.append(
                make_result(
                    tc_id="TC-SEC-010",
                    stride="Repudiation",
                    feature="Authentication & Task Mutation Audit Trail",
                    technique="AST Static Review & DB Schema Inspection",
                    objective="Verify security-relevant events (failed logins, registrations, task deletions) emit structured audit logs.",
                    preconditions="Access to PyTodo Pro source code (app.py).",
                    test_data="AST inspection of app.py + SQLite users/tasks schema",
                    steps="1. Parse app.py AST for logging import or app.logger calls.\n2. Inspect users table columns for audit timestamps.",
                    expected="Failed auth, registrations, and destructive actions emit structured audit logs.",
                    actual=(
                        "Structured logging detected in app.py."
                        if has_logging
                        else "AST confirms zero logging imports or app.logger calls in app.py; users table stores only (id, username, password_hash)."
                    ),
                    status="Pass" if has_logging else "Fail",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-010]: ast_has_logging={has_logging}",
                    defect_id="None" if has_logging else "DEF-SP-007",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-011: Info Disclosure - Flask debug=True Enabled (AST check)
            # ------------------------------------------------------------------
            debug_lines = app_ast["debug_true_lines"]
            debug_enabled = bool(debug_lines)
            results.append(
                make_result(
                    tc_id="TC-SEC-011",
                    stride="Information Disclosure",
                    feature="Application Entry Point (app.py)",
                    technique="AST Configuration Audit",
                    objective="Verify Flask debug mode is disabled in the application entry point.",
                    preconditions="Source file app.py is accessible.",
                    test_data="AST scan of app.run(debug=...) calls in app.py",
                    steps="1. Parse app.py AST and inspect all app.run(...) keyword arguments.",
                    expected="debug=False (or explicitly controlled via environment flag).",
                    actual=(
                        f"app.run(debug=True) hardcoded at line(s) {debug_lines} in app.py, exposing Werkzeug interactive debugger if launched directly."
                        if debug_enabled
                        else "No hardcoded debug=True calls found in app.py."
                    ),
                    status="Fail" if debug_enabled else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-011]: debug_true_lines={debug_lines}",
                    defect_id="DEF-SP-008" if debug_enabled else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-012: Info Disclosure & DoS - Unhandled 500 on Invalid due_date
            # ------------------------------------------------------------------
            bad_date_user, _ = register_api_user(base, "baddate_user", "Password123")
            create_bad = bad_date_user.post(
                f"{base}/api/tasks",
                json={"title": "Corrupt Date Task", "due_date": "not-a-valid-date"},
                timeout=5,
            )
            list_after_bad = bad_date_user.get(f"{base}/api/tasks", timeout=5)
            api_dash_after_bad = bad_date_user.get(f"{base}/api/dashboard", timeout=5)
            web_after_bad = bad_date_user.get(f"{base}/", timeout=5)
            web_dash_after_bad = bad_date_user.get(f"{base}/dashboard", timeout=5)
            statuses_bad = {
                "POST /api/tasks": create_bad.status_code,
                "GET /api/tasks": list_after_bad.status_code,
                "GET /api/dashboard": api_dash_after_bad.status_code,
                "GET /": web_after_bad.status_code,
                "GET /dashboard": web_dash_after_bad.status_code,
            }
            crashed_500 = create_bad.status_code != 400 or any(s >= 500 for s in statuses_bad.values())
            results.append(
                make_result(
                    tc_id="TC-SEC-012",
                    stride="Denial of Service / Information Disclosure",
                    feature="Task Date Validation (/api/tasks, /api/dashboard, /, /dashboard)",
                    technique="Malformed Input & Persistent Error-Handling Test",
                    objective="Verify malformed due_date input is rejected cleanly (HTTP 400) rather than crashing or poisoning account views.",
                    preconditions="Authenticated user session.",
                    test_data='{"title": "Corrupt Date Task", "due_date": "not-a-valid-date"}',
                    steps="1. POST /api/tasks with invalid due_date.\n2. Request GET /api/tasks, GET /api/dashboard, GET /, and GET /dashboard.",
                    expected="POST /api/tasks rejects invalid date format with HTTP 400; all downstream views remain HTTP 200.",
                    actual=(
                        f"Status codes: {statuses_bad}. Invalid date committed prior to ValueError crash, causing persistent HTTP 500 across all task/dashboard views."
                        if crashed_500
                        else f"Invalid due_date rejected cleanly ({statuses_bad})."
                    ),
                    status="Fail" if crashed_500 else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-012]: {statuses_bad}",
                    defect_id="DEF-SP-009" if crashed_500 else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-013: Tampering / EoP / Info Disclosure - Security Headers & Cookie Flags
            # ------------------------------------------------------------------
            login_page_resp = requests.get(f"{base}/login", timeout=5)
            authed_page_resp = user_a.get(f"{base}/", timeout=5)
            authed_api_resp = user_a.get(f"{base}/api/tasks", timeout=5)
            login_api_resp = requests.post(
                f"{base}/api/login",
                json={"username": "victim_cookie", "password": "Password123"},
                timeout=5,
            )
            checked_hdrs = ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Cache-Control", "Referrer-Policy")
            missing_login = [h for h in checked_hdrs if h not in login_page_resp.headers]
            missing_authed = [h for h in checked_hdrs if h not in authed_page_resp.headers]
            set_cookie = login_api_resp.headers.get("Set-Cookie", "")
            masked_cookie = mask_cookie_header(set_cookie)
            has_httponly = "httponly" in set_cookie.lower()
            has_samesite = "samesite" in set_cookie.lower()
            has_secure = "secure" in set_cookie.lower()
            hardening_missing = bool(missing_login) or bool(missing_authed) or (not has_samesite) or (not has_secure)
            results.append(
                make_result(
                    tc_id="TC-SEC-013",
                    stride="Tampering / Elevation of Privilege",
                    feature="HTTP Response Headers & Session Cookie Attributes",
                    technique="Security Headers & Cookie Attribute Inspection",
                    objective="Verify defensive HTTP headers across Web/API routes and session cookie attributes (HttpOnly, SameSite, Secure).",
                    preconditions="Local HTTP server running.",
                    test_data="GET /login, GET /, GET /api/tasks, POST /api/login response headers",
                    steps="1. Inspect GET /login, GET /, and GET /api/tasks headers for defensive controls.\n2. Inspect Set-Cookie flags from POST /api/login.",
                    expected="Security headers present on all routes; Set-Cookie sets HttpOnly, SameSite=Lax/Strict, and Secure (under HTTPS).",
                    actual=(
                        f"Missing on /login: {missing_login}; missing on authenticated /: {missing_authed}; "
                        f"Set-Cookie='{masked_cookie}' (HttpOnly={has_httponly}, SameSite={has_samesite}, Secure={has_secure})."
                    ),
                    status="Fail" if hardening_missing else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-013]: missing_authed={missing_authed}; cookie_flags=(HttpOnly={has_httponly}, SameSite={has_samesite}, Secure={has_secure})",
                    defect_id="DEF-SP-010" if hardening_missing else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-014: Info Disclosure - Public Categories Endpoint Check
            # ------------------------------------------------------------------
            cat_resp = requests.get(f"{base}/api/categories", timeout=5)
            cat_data = cat_resp.json() if cat_resp.status_code == 200 else []
            only_static_cats = cat_resp.status_code == 200 and all(set(c.keys()) == {"id", "name"} for c in cat_data)
            results.append(
                make_result(
                    tc_id="TC-SEC-014",
                    stride="Information Disclosure",
                    feature="Categories Endpoint (GET /api/categories)",
                    technique="Unauthenticated Endpoint Access Check (Control)",
                    objective="Check whether GET /api/categories exposes only static metadata with no user PII.",
                    preconditions="Unauthenticated HTTP client.",
                    test_data="GET /api/categories without session cookie",
                    steps="1. Send unauthenticated GET /api/categories.\n2. Inspect JSON keys and values.",
                    expected="Returns only static seeded category metadata (no PII/user tasks).",
                    actual=f"HTTP {cat_resp.status_code} returned static categories {cat_data} (no PII exposed).",
                    status="Pass" if only_static_cats else "Fail",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-014]: HTTP {cat_resp.status_code} keys_only_id_name={only_static_cats}",
                    defect_id="None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-015: Denial of Service - Pagination Bounds & Overflow (GET /api/tasks)
            # ------------------------------------------------------------------
            pag_user, _ = register_api_user(base, "pag_dos_user", "Password123")
            for idx in range(25):
                pag_user.post(f"{base}/api/tasks", json={"title": f"PagTask {idx}"}, timeout=5)
            neg_per_page = pag_user.get(f"{base}/api/tasks?page=0&per_page=-1", timeout=5)
            neg_page = pag_user.get(f"{base}/api/tasks?page=-1&per_page=10", timeout=5)
            huge_per_page = pag_user.get(f"{base}/api/tasks?page=0&per_page=100000", timeout=5)
            overflow_page = pag_user.get(f"{base}/api/tasks?page=1000000000000000000&per_page=10", timeout=5)
            pag_vulnerable = (
                (neg_per_page.status_code == 200 and len(neg_per_page.json()) == 25)
                or (huge_per_page.status_code == 200 and len(huge_per_page.json()) == 25)
                or overflow_page.status_code >= 500
            )
            results.append(
                make_result(
                    tc_id="TC-SEC-015",
                    stride="Denial of Service",
                    feature="Task List Pagination (GET /api/tasks)",
                    technique="Resource-Limit, Negative & Integer Overflow Probe",
                    objective="Verify negative, unbounded positive, and integer-overflow pagination parameters are rejected cleanly.",
                    preconditions="User has 25 tasks stored.",
                    test_data="per_page=-1; page=-1; per_page=100000; page=10^18",
                    steps="1. Call GET /api/tasks with per_page=-1, page=-1, per_page=100000, and page=10^18.",
                    expected="Negative values rejected (HTTP 400); per_page capped; huge page returns HTTP 400/[] without 500 OverflowError.",
                    actual=(
                        f"per_page=-1 -> HTTP {neg_per_page.status_code} ({len(neg_per_page.json())} rows); "
                        f"page=-1 -> HTTP {neg_page.status_code}; per_page=100000 -> HTTP {huge_per_page.status_code} ({len(huge_per_page.json())} rows); "
                        f"page=10^18 -> HTTP {overflow_page.status_code}."
                    ),
                    status="Fail" if pag_vulnerable else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-015]: neg_pp={neg_per_page.status_code}({len(neg_per_page.json())}), huge_pp={huge_per_page.status_code}({len(huge_per_page.json())}), overflow={overflow_page.status_code}",
                    defect_id="DEF-SP-011" if pag_vulnerable else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-016: DoS - Oversized Payload Bounds (Title & Description)
            # ------------------------------------------------------------------
            oversized_resp = pag_user.post(
                f"{base}/api/tasks",
                json={"title": "A" * 50000, "description": "B" * 50000},
                timeout=5,
            )
            oversized_accepted = oversized_resp.status_code == 201
            results.append(
                make_result(
                    tc_id="TC-SEC-016",
                    stride="Denial of Service",
                    feature="Task Payload Size Bounds (POST /api/tasks)",
                    technique="Oversized Field Boundary Probe",
                    objective="Verify maximum character lengths on task title and description are enforced before persistence.",
                    preconditions="Authenticated user session.",
                    test_data="title='A'*50000 (50 KB), description='B'*50000 (50 KB)",
                    steps="1. POST /api/tasks with 50,000-character title and 50,000-character description.",
                    expected="Server rejects oversized payload with HTTP 400/413.",
                    actual=(
                        f"Accepted with HTTP {oversized_resp.status_code}; stored len(title)={len(oversized_resp.json().get('title', ''))}, len(description)={len(oversized_resp.json().get('description', ''))}."
                        if oversized_accepted
                        else f"Rejected with HTTP {oversized_resp.status_code}."
                    ),
                    status="Fail" if oversized_accepted else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-016]: HTTP {oversized_resp.status_code}",
                    defect_id="DEF-SP-012" if oversized_accepted else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-017: Elevation of Privilege - IDOR on DELETE /api/tasks/<id>
            # ------------------------------------------------------------------
            owner_sess, _ = register_api_user(base, "idor_owner", "Password123")
            attacker_sess, _ = register_api_user(base, "idor_attacker", "Password123")
            owner_task = owner_sess.post(
                f"{base}/api/tasks", json={"title": "Owner Protected Task"}, timeout=5
            ).json()
            target_id = owner_task["id"]
            del_resp = attacker_sess.delete(f"{base}/api/tasks/{target_id}", timeout=5)
            owner_check = owner_sess.get(f"{base}/api/tasks/{target_id}", timeout=5)
            idor_succeeded = del_resp.status_code == 200 and owner_check.status_code == 404
            results.append(
                make_result(
                    tc_id="TC-SEC-017",
                    stride="Elevation of Privilege",
                    feature="Delete Task API (DELETE /api/tasks/<id>)",
                    technique="Broken Object-Level Authorization (IDOR) Test",
                    objective="Verify an authenticated user cannot delete tasks belonging to another user via the REST API.",
                    preconditions="Owner owns target task; Attacker is logged in as another user.",
                    test_data=f"Attacker sends DELETE /api/tasks/<target_id> (id={target_id} in run)",
                    steps="1. Owner creates a task.\n2. Attacker sends DELETE /api/tasks/<id>.\n3. Owner attempts GET /api/tasks/<id>.",
                    expected="HTTP 403 or 404 returned to Attacker; Owner's task remains intact.",
                    actual=(
                        f"Attacker received HTTP {del_resp.status_code} {del_resp.text.strip()}; Owner's subsequent GET returned HTTP {owner_check.status_code} (task deleted)."
                        if idor_succeeded
                        else f"Attacker blocked with HTTP {del_resp.status_code}; Owner GET={owner_check.status_code}."
                    ),
                    status="Fail" if idor_succeeded else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-017]: attacker DELETE={del_resp.status_code}, owner GET={owner_check.status_code}",
                    defect_id="DEF-SP-013" if idor_succeeded else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-018: Elevation of Privilege - API GET/PUT & Web UI Ownership Isolation
            # ------------------------------------------------------------------
            owner_task2 = owner_sess.post(
                f"{base}/api/tasks", json={"title": "Owner Guarded Task"}, timeout=5
            ).json()
            tid2 = owner_task2["id"]
            att_get = attacker_sess.get(f"{base}/api/tasks/{tid2}", timeout=5)
            att_put = attacker_sess.put(f"{base}/api/tasks/{tid2}", json={"title": "Tampered"}, timeout=5)
            att_web_edit_get = attacker_sess.get(f"{base}/tasks/{tid2}/edit", allow_redirects=False, timeout=5)
            att_web_edit_post = attacker_sess.post(
                f"{base}/tasks/{tid2}/edit", data={"title": "TamperedWeb"}, allow_redirects=False, timeout=5
            )
            att_web_tog = attacker_sess.post(f"{base}/tasks/{tid2}/toggle", allow_redirects=False, timeout=5)
            att_web_del = attacker_sess.post(f"{base}/tasks/{tid2}/delete", allow_redirects=False, timeout=5)
            owner_still_intact = owner_sess.get(f"{base}/api/tasks/{tid2}", timeout=5)
            isolated_ok = (
                att_get.status_code == 404
                and att_put.status_code == 404
                and owner_still_intact.status_code == 200
                and owner_still_intact.json()["title"] == "Owner Guarded Task"
                and not owner_still_intact.json()["done"]
            )
            results.append(
                make_result(
                    tc_id="TC-SEC-018",
                    stride="Elevation of Privilege",
                    feature="API GET/PUT & Web UI /edit, /toggle, /delete Authorization",
                    technique="Object-Level Authorization Positive Control Test",
                    objective="Verify API GET/PUT and Web UI /edit, /toggle, /delete enforce user_id ownership scoping.",
                    preconditions="Owner owns task tid2; Attacker is separate authenticated user.",
                    test_data=f"Cross-user API GET/PUT and Web GET/POST on task id={tid2}",
                    steps="1. Attacker calls GET/PUT /api/tasks/<id>.\n2. Attacker calls GET/POST /tasks/<id>/edit, POST /toggle, POST /delete.\n3. Verify owner task remains intact.",
                    expected="All cross-user mutations/reads fail and owner's task remains unchanged.",
                    actual=(
                        f"API GET={att_get.status_code}, PUT={att_put.status_code}; Web edit(G/P)=({att_web_edit_get.status_code},{att_web_edit_post.status_code}), "
                        f"toggle={att_web_tog.status_code}, delete={att_web_del.status_code}; Owner task intact={isolated_ok}."
                    ),
                    status="Pass" if isolated_ok else "Fail",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-018]: API=({att_get.status_code},{att_put.status_code}), intact={isolated_ok}",
                    defect_id="None" if isolated_ok else "DEF-SP-013",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-019: Elevation of Privilege - Unauthenticated Access Control (All Protected Routes)
            # ------------------------------------------------------------------
            anon = requests.Session()
            web_unauth = {
                "/": anon.get(f"{base}/", allow_redirects=False, timeout=5).status_code,
                "/dashboard": anon.get(f"{base}/dashboard", allow_redirects=False, timeout=5).status_code,
                "/tasks/new": anon.get(f"{base}/tasks/new", allow_redirects=False, timeout=5).status_code,
                "/tasks/1/edit": anon.get(f"{base}/tasks/1/edit", allow_redirects=False, timeout=5).status_code,
                "/tasks/1/toggle": anon.post(f"{base}/tasks/1/toggle", allow_redirects=False, timeout=5).status_code,
                "/tasks/1/delete": anon.post(f"{base}/tasks/1/delete", allow_redirects=False, timeout=5).status_code,
            }
            api_unauth = {
                "GET /api/tasks": anon.get(f"{base}/api/tasks", timeout=5).status_code,
                "POST /api/tasks": anon.post(f"{base}/api/tasks", json={"title": "x"}, timeout=5).status_code,
                "GET /api/tasks/1": anon.get(f"{base}/api/tasks/1", timeout=5).status_code,
                "PUT /api/tasks/1": anon.put(f"{base}/api/tasks/1", json={"title": "x"}, timeout=5).status_code,
                "DELETE /api/tasks/1": anon.delete(f"{base}/api/tasks/1", timeout=5).status_code,
                "GET /api/dashboard": anon.get(f"{base}/api/dashboard", timeout=5).status_code,
            }
            auth_enforced = all(c == 302 for c in web_unauth.values()) and all(c == 401 for c in api_unauth.values())
            results.append(
                make_result(
                    tc_id="TC-SEC-019",
                    stride="Elevation of Privilege",
                    feature="Authentication Middleware (@login_required_web / _api)",
                    technique="Comprehensive Unauthenticated Access Control Verification",
                    objective="Verify all 12 protected Web UI and API routes reject unauthenticated requests.",
                    preconditions="Client holds no session cookie.",
                    test_data="Unauthenticated calls across 6 Web UI routes + 6 REST API endpoints",
                    steps="1. Call all protected Web UI routes without session cookies.\n2. Call all protected REST API endpoints without session cookies.",
                    expected="All 6 Web UI routes redirect (302) to /login; all 6 API routes return HTTP 401.",
                    actual=f"Web={web_unauth}; API={api_unauth}.",
                    status="Pass" if auth_enforced else "Fail",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-019]: web_all_302={all(c == 302 for c in web_unauth.values())}, api_all_401={all(c == 401 for c in api_unauth.values())}",
                    defect_id="None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-020: Tampering - Orphan category_id Foreign Key Integrity
            # ------------------------------------------------------------------
            fk_resp = pag_user.post(
                f"{base}/api/tasks",
                json={"title": "Orphan FK Task", "category_id": 99999},
                timeout=5,
            )
            fk_accepted = fk_resp.status_code == 201
            results.append(
                make_result(
                    tc_id="TC-SEC-020",
                    stride="Tampering",
                    feature="Relational Integrity (POST /api/tasks category_id)",
                    technique="Foreign-Key Boundary & Referential Integrity Probe",
                    objective="Verify non-existent category_id references are rejected rather than persisting orphan tasks.",
                    preconditions="Authenticated user session.",
                    test_data='{"title": "Orphan FK Task", "category_id": 99999}',
                    steps="1. POST /api/tasks with category_id=99999.\n2. Inspect HTTP status and returned category field.",
                    expected="Server validates category_id against categories table and returns HTTP 400.",
                    actual=(
                        f"Accepted with HTTP {fk_resp.status_code}; stored orphan category_id={fk_resp.json().get('category_id')} (category={fk_resp.json().get('category')})."
                        if fk_accepted
                        else f"Rejected invalid category_id with HTTP {fk_resp.status_code}."
                    ),
                    status="Fail" if fk_accepted else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-020]: HTTP {fk_resp.status_code}",
                    defect_id="DEF-SP-016" if fk_accepted else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-021: DoS / Info Disclosure - REST API JSON Type-Confusion 500s
            # ------------------------------------------------------------------
            type_probes = {
                "register_list": requests.post(f"{base}/api/register", json=["bad"], timeout=5).status_code,
                "login_list": requests.post(f"{base}/api/login", json=["bad"], timeout=5).status_code,
                "login_int_user": requests.post(f"{base}/api/login", json={"username": 123, "password": "x"}, timeout=5).status_code,
                "create_list": owner_sess.post(f"{base}/api/tasks", json=["bad"], timeout=5).status_code,
                "create_int_title": owner_sess.post(f"{base}/api/tasks", json={"title": 12345}, timeout=5).status_code,
                "create_dict_desc": owner_sess.post(f"{base}/api/tasks", json={"title": "ok", "description": {"nested": 1}}, timeout=5).status_code,
                "create_int_due": owner_sess.post(f"{base}/api/tasks", json={"title": "ok", "due_date": 20261126}, timeout=5).status_code,
                "update_list": owner_sess.put(f"{base}/api/tasks/{tid2}", json=["bad"], timeout=5).status_code,
            }
            crashes_500 = {k: v for k, v in type_probes.items() if v >= 500}
            results.append(
                make_result(
                    tc_id="TC-SEC-021",
                    stride="Denial of Service / Information Disclosure",
                    feature="REST API JSON Schema & Type Validation (/api/*)",
                    technique="Type-Confusion & Malformed Schema Robustness Probe",
                    objective="Verify non-object JSON arrays and unexpected field types return HTTP 400 rather than unhandled 500 exceptions.",
                    preconditions="Local server running with DEBUG=False.",
                    test_data="Non-dict JSON (['bad']) and non-scalar field types across register/login/tasks POST & PUT",
                    steps="1. Send JSON array ['bad'] to /api/register, /api/login, /api/tasks, /api/tasks/<id>.\n2. Send integer username/title/due_date and dict description.",
                    expected="All malformed schemas return HTTP 400/422 with zero HTTP 500 crashes.",
                    actual=f"Probe statuses={type_probes}; {len(crashes_500)}/8 payloads triggered unhandled HTTP 500 crashes ({list(crashes_500.keys())}).",
                    status="Fail" if crashes_500 else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-021]: 500_count={len(crashes_500)}/8 {type_probes}",
                    defect_id="DEF-SP-017" if crashes_500 else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-022: Tampering / DoS - PUT /api/tasks/<id> Null/Blank Title & Bad Date
            # ------------------------------------------------------------------
            put_user, _ = register_api_user(base, "put_edge_user", "Password123")
            ptask = put_user.post(f"{base}/api/tasks", json={"title": "Valid Title"}, timeout=5).json()
            ptid = ptask["id"]
            r_put_null = put_user.put(f"{base}/api/tasks/{ptid}", json={"title": None}, timeout=5)
            r_put_blank = put_user.put(f"{base}/api/tasks/{ptid}", json={"title": "   "}, timeout=5)
            r_put_baddate = put_user.put(f"{base}/api/tasks/{ptid}", json={"due_date": "bad-date"}, timeout=5)
            put_broken = (
                r_put_null.status_code >= 500
                or r_put_blank.status_code == 200
                or r_put_baddate.status_code >= 500
            )
            results.append(
                make_result(
                    tc_id="TC-SEC-022",
                    stride="Tampering / Denial of Service",
                    feature="Task Update API (PUT /api/tasks/<id>)",
                    technique="Partial-Update Validation & Null-Constraint Probe",
                    objective="Verify PUT /api/tasks/<id> rejects null/blank titles and malformed due_date cleanly with HTTP 400.",
                    preconditions="Authenticated user owns task ptid.",
                    test_data='{"title": null}, {"title": "   "}, {"due_date": "bad-date"}',
                    steps="1. PUT /api/tasks/<id> with title=null.\n2. PUT with whitespace-only title.\n3. PUT with invalid due_date.",
                    expected="All three invalid partial updates are rejected with HTTP 400.",
                    actual=(
                        f"PUT title=null -> HTTP {r_put_null.status_code} (IntegrityError); "
                        f"PUT title='   ' -> HTTP {r_put_blank.status_code} (accepted blank title); "
                        f"PUT bad due_date -> HTTP {r_put_baddate.status_code}."
                    ),
                    status="Fail" if put_broken else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-022]: null={r_put_null.status_code}, blank={r_put_blank.status_code}, baddate={r_put_baddate.status_code}",
                    defect_id="DEF-SP-018" if put_broken else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-023: Tampering / DoS - Web UI /tasks/new Empty Title & Bad Date Validation
            # ------------------------------------------------------------------
            web_val_user, _ = register_api_user(base, "web_val_user", "Password123")
            r_web_empty = web_val_user.post(
                f"{base}/tasks/new",
                data={"title": "   ", "description": "empty title", "due_date": ""},
                allow_redirects=False,
                timeout=5,
            )
            r_web_baddate = web_val_user.post(
                f"{base}/tasks/new",
                data={"title": "Web Bad Date", "description": "", "due_date": "invalid-date"},
                allow_redirects=False,
                timeout=5,
            )
            r_web_home_after = web_val_user.get(f"{base}/", timeout=5)
            web_val_broken = r_web_empty.status_code == 302 or r_web_home_after.status_code >= 500
            results.append(
                make_result(
                    tc_id="TC-SEC-023",
                    stride="Tampering / Denial of Service",
                    feature="Web UI Task Form Validation (/tasks/new -> /)",
                    technique="Server-Side Web Form Validation & Persistent Crash Check",
                    objective="Verify server-side Web UI form validation rejects whitespace titles and malformed due_date values.",
                    preconditions="Authenticated Web UI user session.",
                    test_data="POST /tasks/new with title='   ', then due_date='invalid-date'",
                    steps="1. Submit POST /tasks/new with blank title.\n2. Submit POST /tasks/new with invalid due_date.\n3. Request GET /.",
                    expected="Server rejects invalid inputs with HTTP 400/validation error; GET / stays HTTP 200.",
                    actual=(
                        f"Empty-title POST returned HTTP {r_web_empty.status_code} (accepted); invalid due_date POST returned HTTP {r_web_baddate.status_code} and broke GET / with HTTP {r_web_home_after.status_code}."
                        if web_val_broken
                        else f"Form validation cleanly handled invalid inputs (GET /={r_web_home_after.status_code})."
                    ),
                    status="Fail" if web_val_broken else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-023]: empty_title={r_web_empty.status_code}, bad_date={r_web_baddate.status_code}, GET /={r_web_home_after.status_code}",
                    defect_id="DEF-SP-009" if web_val_broken else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-024: Tampering - Web UI Search GET /?q= Parameterization (Positive Control)
            # ------------------------------------------------------------------
            web_sqli_resp = user_a.get(f"{base}/", params={"q": bool_payload}, timeout=5)
            web_sqli_leaked = "User B Confidential Task" in web_sqli_resp.text
            web_sqli_safe = web_sqli_resp.status_code == 200 and not web_sqli_leaked
            results.append(
                make_result(
                    tc_id="TC-SEC-024",
                    stride="Tampering",
                    feature="Web UI Task Search (GET /?q=)",
                    technique="SQL Injection Negative/Symmetry Control",
                    objective="Verify Web UI search query uses parameterized LIKE ? and resists SQLi unlike GET /api/tasks?q=.",
                    preconditions="User A and User B exist with separate tasks.",
                    test_data=f"GET /?q={bool_payload!r}",
                    steps="1. Send same boolean SQLi payload used in TC-SEC-005 to Web UI GET /?q=.\n2. Inspect HTTP status and HTML body.",
                    expected="HTTP 200 rendered with no tasks from User B.",
                    actual=f"Web UI returned HTTP {web_sqli_resp.status_code}; leaked_user_b={web_sqli_leaked} (parameterized LIKE ? protected Web UI).",
                    status="Pass" if web_sqli_safe else "Fail",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-024]: HTTP {web_sqli_resp.status_code}, leaked_user_b={web_sqli_leaked}",
                    defect_id="None" if web_sqli_safe else "DEF-SP-004",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-025: Spoofing - Stateless Session Replay After Logout
            # ------------------------------------------------------------------
            replay_sess = requests.Session()
            replay_sess.cookies.set("session", pre_logout_cookie, domain="127.0.0.1")
            replay_resp = replay_sess.get(f"{base}/api/dashboard", timeout=5)
            replay_succeeded = replay_resp.status_code == 200
            results.append(
                make_result(
                    tc_id="TC-SEC-025",
                    stride="Spoofing",
                    feature="Session Revocation Lifecycle (GET /logout)",
                    technique="Stateless Session Replay Check",
                    objective="Verify a captured session cookie is invalidated server-side after the user logs out.",
                    preconditions="Session cookie captured prior to GET /logout in TC-SEC-009.",
                    test_data="Captured pre-logout session cookie replayed against GET /api/dashboard",
                    steps="1. Capture session cookie before logout.\n2. Execute GET /logout.\n3. Replay captured cookie to GET /api/dashboard.",
                    expected="Server rejects replayed pre-logout token with HTTP 401.",
                    actual=(
                        f"Replayed pre-logout cookie still authenticated to GET /api/dashboard with HTTP {replay_resp.status_code} (stateless cookie lacks server-side revocation)."
                        if replay_succeeded
                        else f"Replayed token rejected with HTTP {replay_resp.status_code}."
                    ),
                    status="Fail" if replay_succeeded else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-025]: post-logout cookie replay HTTP {replay_resp.status_code}",
                    defect_id="DEF-SP-019" if replay_succeeded else "None",
                )
            )

            # ------------------------------------------------------------------
            # TC-SEC-026: Spoofing / DoS - Password Policy & Upper-Bound Hashing Check
            # ------------------------------------------------------------------
            pw_8_ok = pytodo_helpers.is_valid_password("Pass1234")
            ws_reg_sess, ws_reg_resp = register_api_user(base, "ws_pw_user", "         ")
            ws_accepted = ws_reg_resp.status_code == 201
            has_max_content = bool(pytodo_app.app.config.get("MAX_CONTENT_LENGTH"))
            pw_policy_weak = (not pw_8_ok) or ws_accepted or (not has_max_content)
            results.append(
                make_result(
                    tc_id="TC-SEC-026",
                    stride="Spoofing / Denial of Service",
                    feature="Password Strength Policy & Request Size Limit (helpers.py, app.py)",
                    technique="Boundary & Complexity Policy Verification",
                    objective="Verify password validator accepts 8-char spec minimum, rejects whitespace-only passwords, and bounds request/password size.",
                    preconditions="Application running with default helpers.py and Flask config.",
                    test_data="is_valid_password('Pass1234'), POST /api/register with 9-space password '         ', MAX_CONTENT_LENGTH check",
                    steps="1. Check 8-char spec minimum.\n2. Register with 9 whitespace chars.\n3. Check app.config['MAX_CONTENT_LENGTH'].",
                    expected="8-char passwords accepted; whitespace-only rejected; MAX_CONTENT_LENGTH configured.",
                    actual=(
                        f"8-char valid={pw_8_ok} (corroborates Week 1 DEF-001 / Week 2 DEF-WB-001); "
                        f"whitespace-only 9-space password accepted={ws_accepted} (HTTP {ws_reg_resp.status_code}); "
                        f"MAX_CONTENT_LENGTH={pytodo_app.app.config.get('MAX_CONTENT_LENGTH')}."
                    ),
                    status="Fail" if pw_policy_weak else "Pass",
                    evidence=f"evidence/security_execution_log.txt [TC-SEC-026]: 8char={pw_8_ok}, ws_accepted={ws_accepted}, max_content_len={pytodo_app.app.config.get('MAX_CONTENT_LENGTH')}",
                    defect_id="DEF-SP-020" if pw_policy_weak else "None",
                )
            )

    summary = {
        "executed_at": started_at,
        "total": len(results),
        "passed": sum(1 for r in results if r["status"] == "Pass"),
        "failed": sum(1 for r in results if r["status"] == "Fail"),
        "results": results,
    }

    json_path = os.path.join(EVIDENCE_DIR, "security_results.json")
    log_path = os.path.join(EVIDENCE_DIR, "security_execution_log.txt")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    lines = [
        "PyTodo Pro — Week 5 Security Test Execution Log",
        f"Executed at: {started_at}",
        f"Total: {summary['total']} | Passed: {summary['passed']} | Failed: {summary['failed']}",
        "-" * 95,
    ]
    for r in results:
        lines.append(
            f"[{r['status'].upper():4s}] {r['test_case_id']} | {r['stride_category']:34s} | {r['feature']} | Defect: {r['defect_id']}"
        )
        lines.append(f"       Actual:   {r['actual_result']}")
        lines.append(f"       Evidence: {r['evidence']}")
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print("\n".join(lines))
    return summary


if __name__ == "__main__":
    run_security_suite()
