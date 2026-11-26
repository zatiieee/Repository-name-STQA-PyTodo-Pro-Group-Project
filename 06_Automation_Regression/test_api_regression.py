"""
Week 6 — Fast PyTest REST API & Security/Validation Regression Suite for PyTodo Pro
Maps to Week 4 (API/WF/INV/PAR) and Week 5 (TC-SEC-*) test suites.
"""

import pytest
import requests

from conftest import unique_user


def api_register_session(base_url: str, username: str, password: str):
    sess = requests.Session()
    resp = sess.post(f"{base_url}/api/register", json={"username": username, "password": password}, timeout=5)
    return sess, resp


@pytest.mark.api
def test_reg_015_unauthenticated_access_blocked(live_server_url):
    """TC-REG-015 (maps API-01/STS-01/TC-SEC-019): Protected Web & API routes block unauthenticated requests."""
    assert requests.get(f"{live_server_url}/", allow_redirects=False, timeout=5).status_code == 302
    assert requests.get(f"{live_server_url}/dashboard", allow_redirects=False, timeout=5).status_code == 302
    assert requests.get(f"{live_server_url}/api/tasks", timeout=5).status_code == 401
    assert requests.post(f"{live_server_url}/api/tasks", json={"title": "x"}, timeout=5).status_code == 401
    assert requests.get(f"{live_server_url}/api/dashboard", timeout=5).status_code == 401
    assert requests.get(f"{live_server_url}/api/tasks/999999", timeout=5).status_code == 401


@pytest.mark.api
def test_reg_016_api_crud_lifecycle_and_ui_parity(live_server_url):
    """TC-REG-016 (maps API-03, PAR-01, PUT/List/Login): Auth login, full CRUD lifecycle, filters, and UI parity."""
    uname = unique_user("crudapi")
    sess, reg = api_register_session(live_server_url, uname, "ValidPass123")
    assert reg.status_code == 201

    # Login endpoint check (200 valid, 401 wrong password)
    bad_login = requests.post(f"{live_server_url}/api/login", json={"username": uname, "password": "Wrong999"}, timeout=5)
    assert bad_login.status_code == 401
    good_sess = requests.Session()
    good_login = good_sess.post(f"{live_server_url}/api/login", json={"username": uname, "password": "ValidPass123"}, timeout=5)
    assert good_login.status_code == 200

    # Blank title rejected cleanly (INV-01)
    assert good_sess.post(f"{live_server_url}/api/tasks", json={"title": "   "}, timeout=5).status_code == 400

    # Create
    created = good_sess.post(
        f"{live_server_url}/api/tasks",
        json={"title": "API Regression Task", "description": "Created via API", "category_id": 1},
        timeout=5,
    )
    assert created.status_code == 201
    cjson = created.json()
    tid = cjson["id"]
    assert cjson["category"] == "Work" and cjson["done"] is False

    # List + query filter + single GET + UI parity
    listed = good_sess.get(f"{live_server_url}/api/tasks", params={"category": "Work", "status": "open", "q": "Regression"}, timeout=5)
    assert listed.status_code == 200 and any(t["id"] == tid for t in listed.json())
    assert good_sess.get(f"{live_server_url}/api/tasks/{tid}", timeout=5).status_code == 200
    assert "API Regression Task" in good_sess.get(f"{live_server_url}/", timeout=5).text

    # Missing ID returns 404 on GET/PUT
    assert good_sess.get(f"{live_server_url}/api/tasks/999999", timeout=5).status_code == 404
    assert good_sess.put(f"{live_server_url}/api/tasks/999999", json={"title": "x"}, timeout=5).status_code == 404

    # Partial update Done=True then revert Done=False (completed_at cleared)
    upd_done = good_sess.put(f"{live_server_url}/api/tasks/{tid}", json={"done": True, "description": "Updated desc"}, timeout=5)
    assert upd_done.status_code == 200 and upd_done.json()["done"] is True and upd_done.json()["completed_at"] is not None
    upd_reopen = good_sess.put(f"{live_server_url}/api/tasks/{tid}", json={"done": False}, timeout=5)
    assert upd_reopen.status_code == 200 and upd_reopen.json()["done"] is False and upd_reopen.json()["completed_at"] is None

    # Delete & verify 404 + UI disappearance
    assert good_sess.delete(f"{live_server_url}/api/tasks/{tid}", timeout=5).status_code == 200
    assert good_sess.get(f"{live_server_url}/api/tasks/{tid}", timeout=5).status_code == 404
    assert "API Regression Task" not in good_sess.get(f"{live_server_url}/", timeout=5).text


@pytest.mark.api
def test_reg_017_api_categories_and_dashboard(live_server_url):
    """TC-REG-017 (maps API-02 & API-04): Seeded categories and all 5 /api/dashboard counters match task state."""
    from datetime import date, timedelta

    cats = requests.get(f"{live_server_url}/api/categories", timeout=5)
    assert cats.status_code == 200
    assert {c["name"] for c in cats.json()} == {"Work", "Personal", "Study", "Urgent"}

    sess, _ = api_register_session(live_server_url, unique_user("dashapi"), "ValidPass123")
    today = date.today()
    sess.post(f"{live_server_url}/api/tasks", json={"title": "Past Task", "due_date": (today - timedelta(days=1)).strftime("%Y-%m-%d")}, timeout=5)
    sess.post(f"{live_server_url}/api/tasks", json={"title": "Soon Task", "due_date": (today + timedelta(days=1)).strftime("%Y-%m-%d")}, timeout=5)
    t3 = sess.post(f"{live_server_url}/api/tasks", json={"title": "Done Task"}, timeout=5).json()
    sess.put(f"{live_server_url}/api/tasks/{t3['id']}", json={"done": True}, timeout=5)

    dash = sess.get(f"{live_server_url}/api/dashboard", timeout=5)
    assert dash.status_code == 200
    body = dash.json()
    assert body == {"total": 3, "open": 2, "overdue": 1, "due_soon": 1, "completed_this_week": 1}


@pytest.mark.api
@pytest.mark.known_bug
def test_reg_019_duplicate_username_rejected_guard(live_server_url):
    """TC-REG-019 (maps INV-05/DEF-API-003/DEF-SP-001): Duplicate username registration must return 400 or 409."""
    dup_name = unique_user("dupreg")
    _, r1 = api_register_session(live_server_url, dup_name, "ValidPass123")
    _, r2 = api_register_session(live_server_url, dup_name, "OtherPass999")
    assert r1.status_code == 201
    assert r2.status_code in (400, 409), f"DEF-SP-001/DEF-API-003 still open: duplicate register returned {r2.status_code}"


@pytest.mark.api
@pytest.mark.known_bug
def test_reg_020_invalid_due_date_rejected_guard(live_server_url):
    """TC-REG-020 (maps INV-02/DEF-API-001/DEF-SP-009): Malformed due_date must return HTTP 400 without 500."""
    sess, _ = api_register_session(live_server_url, unique_user("baddate"), "ValidPass123")
    resp = sess.post(
        f"{live_server_url}/api/tasks",
        json={"title": "Bad Date Guard", "due_date": "2026-02-30"},
        timeout=5,
    )
    assert resp.status_code == 400, f"DEF-SP-009/DEF-API-001 still open: bad due_date returned HTTP {resp.status_code}"


@pytest.mark.api
@pytest.mark.known_bug
def test_reg_021_api_search_sqli_guard(live_server_url):
    """TC-REG-021 (maps TC-SEC-005/DEF-SP-004): SQLi in GET /api/tasks?q= must not leak User B tasks."""
    ua, _ = api_register_session(live_server_url, unique_user("sqlia"), "ValidPass123")
    ub, _ = api_register_session(live_server_url, unique_user("sqlib"), "ValidPass123")
    ua.post(f"{live_server_url}/api/tasks", json={"title": "A Safe Task"}, timeout=5)
    ub.post(f"{live_server_url}/api/tasks", json={"title": "B Private Task"}, timeout=5)

    resp = ua.get(f"{live_server_url}/api/tasks", params={"q": "x%' OR title = 'B Private Task' OR 'a' = 'b"}, timeout=5)
    assert resp.status_code == 200, f"Unexpected HTTP {resp.status_code} on SQLi check"
    titles = [t["title"] for t in resp.json()]
    assert "B Private Task" not in titles, f"DEF-SP-004 still open: SQLi leaked cross-user task {titles}"


@pytest.mark.api
@pytest.mark.known_bug
def test_reg_022_api_delete_idor_guard(live_server_url):
    """TC-REG-022 (maps TC-SEC-017/DEF-SP-013): User B cannot DELETE User A's task; GET/PUT stay isolated."""
    ua, _ = api_register_session(live_server_url, unique_user("idorown"), "ValidPass123")
    ub, _ = api_register_session(live_server_url, unique_user("idoratt"), "ValidPass123")
    tid = ua.post(f"{live_server_url}/api/tasks", json={"title": "Owner Task"}, timeout=5).json()["id"]

    # Positive control: GET and PUT blocked
    assert ub.get(f"{live_server_url}/api/tasks/{tid}", timeout=5).status_code == 404
    assert ub.put(f"{live_server_url}/api/tasks/{tid}", json={"title": "Hijacked"}, timeout=5).status_code == 404

    del_resp = ub.delete(f"{live_server_url}/api/tasks/{tid}", timeout=5)
    assert del_resp.status_code in (403, 404), f"DEF-SP-013 still open: cross-user DELETE returned {del_resp.status_code}"
    assert ua.get(f"{live_server_url}/api/tasks/{tid}", timeout=5).status_code == 200
