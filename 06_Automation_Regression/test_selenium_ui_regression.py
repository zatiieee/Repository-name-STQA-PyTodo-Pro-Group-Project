"""
Week 6 — Selenium WebDriver UI Regression Suite for PyTodo Pro
Refactored with lightweight Page Objects, unique users, stale-safe filter checks,
complete status-filter & invalid-input coverage, and failure screenshot hooks.
"""

import os
import uuid
from datetime import date, timedelta

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from conftest import unique_user
from pages import AuthPage, DashboardPage, TaskFormPage, TasksPage

EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "evidence")


@pytest.mark.ui
def test_reg_001_valid_registration_redirects_to_tasks(browser, live_server_url):
    """TC-REG-001 (maps TC-BB-001): Valid account creation logs in and opens My Tasks."""
    uname = unique_user("regok")
    AuthPage(browser, live_server_url).register(uname, "ValidPass123")
    WebDriverWait(browser, 5).until(EC.url_to_be(f"{live_server_url}/"))
    tasks = TasksPage(browser, live_server_url)
    assert "My Tasks" in browser.page_source
    assert uname in tasks.nav_username()


@pytest.mark.ui
@pytest.mark.parametrize("bad_username", ["   ", "user@1", "a b", "bad!name"])
def test_reg_002_blank_and_invalid_username_rejected(browser, live_server_url, bad_username):
    """TC-REG-002 (maps TC-BB-002, TC-BB-003): Blank and special-char usernames are rejected."""
    auth = AuthPage(browser, live_server_url)
    auth.register(bad_username, "ValidPass123")
    assert "/register" in browser.current_url
    assert "3-20 characters" in auth.error_text()


@pytest.mark.ui
@pytest.mark.parametrize(
    "uname_len,expect_ok",
    [(2, False), (3, True), (4, True), (19, True), (20, True), (21, False)],
)
def test_reg_003_username_length_boundaries(browser, live_server_url, uname_len, expect_ok):
    """TC-REG-003 (maps TC-BB-005..010): Username boundaries 2, 3, 4, 19, 20, and 21 characters."""
    tag = uuid.uuid4().hex
    uname = f"u{tag}"[:uname_len]
    auth = AuthPage(browser, live_server_url)
    auth.register(uname, "ValidPass123")
    if expect_ok:
        WebDriverWait(browser, 5).until(EC.url_to_be(f"{live_server_url}/"))
        assert uname in TasksPage(browser, live_server_url).nav_username()
    else:
        assert "/register" in browser.current_url
        assert "3-20 characters" in auth.error_text()


@pytest.mark.ui
def test_reg_004_password_below_and_above_min_boundaries(browser, live_server_url):
    """TC-REG-004 (maps TC-BB-004, TC-BB-011, TC-BB-013): 3 & 7 char passwords fail; 9 chars pass."""
    auth = AuthPage(browser, live_server_url)
    for bad_pw in ("abc", "Abc1234"):
        auth.register(unique_user("pwbad"), bad_pw)
        assert "/register" in browser.current_url
        assert "at least 8" in auth.error_text()

    auth.register(unique_user("pw9ok"), "Abc123456")
    WebDriverWait(browser, 5).until(EC.url_to_be(f"{live_server_url}/"))
    assert "My Tasks" in browser.page_source


@pytest.mark.ui
@pytest.mark.known_bug
def test_reg_005_password_exact_8_chars_boundary(browser, live_server_url):
    """TC-REG-005 (maps TC-BB-012, WB-002 / DEF-001, DEF-WB-001): 8-char password minimum must pass."""
    auth = AuthPage(browser, live_server_url)
    auth.register(unique_user("pw8"), "Pass1234")
    assert browser.current_url.rstrip("/") == live_server_url.rstrip("/"), (
        "DEF-001/DEF-WB-001 still open: 8-char password 'Pass1234' rejected on /register"
    )


@pytest.mark.ui
def test_reg_006_login_decision_table_and_logout(browser, live_server_url):
    """TC-REG-006 (maps TC-BB-014..017): All 4 login decision table rules + logout enforcement."""
    uname = unique_user("dtusr")
    auth = AuthPage(browser, live_server_url)
    tasks = TasksPage(browser, live_server_url)
    auth.register(uname, "CorrectPass99")
    tasks.logout()

    for u, p in [(uname, "WrongPass99"), ("no_such_user_xyz", "CorrectPass99"), ("no_such_user_xyz", "WrongPass99")]:
        auth.login(u, p)
        assert "/login" in browser.current_url
        assert "Invalid username or password" in auth.error_text()

    auth.login(uname, "CorrectPass99")
    WebDriverWait(browser, 5).until(EC.url_to_be(f"{live_server_url}/"))
    assert uname in tasks.nav_username()

    tasks.logout()
    tasks.open()
    assert "/login" in browser.current_url


@pytest.mark.ui
def test_reg_007_create_edit_and_cancel_task_ui(browser, live_server_url):
    """TC-REG-007 (maps Task CRUD): Create task, edit title/description/category/due_date, verify Cancel."""
    AuthPage(browser, live_server_url).register(unique_user("crudui"), "ValidPass123")
    form = TaskFormPage(browser, live_server_url)
    tasks = TasksPage(browser, live_server_url)

    due_5 = (date.today() + timedelta(days=5)).strftime("%Y-%m-%d")
    due_8 = (date.today() + timedelta(days=8)).strftime("%Y-%m-%d")
    form.create_task("Selenium Draft Task", "Initial desc", "Study", due_5)
    assert "Selenium Draft Task" in tasks.row_titles()

    # Edit all fields
    tasks.click_edit("Selenium Draft Task")
    form.fill_and_submit("Selenium Edited Task", description="Updated UI desc", category_text="Work", due_yyyy_mm_dd=due_8)
    row_txt = tasks.row_text("Selenium Edited Task")
    assert "Work" in row_txt and due_8 in row_txt

    # Cancel preserves task unchanged
    tasks.click_edit("Selenium Edited Task")
    form.cancel()
    assert browser.current_url.rstrip("/") == live_server_url.rstrip("/")
    assert "Selenium Edited Task" in tasks.row_titles()


@pytest.mark.ui
def test_reg_008_filter_by_category_status_and_search(browser, live_server_url):
    """TC-REG-008 (maps Search & Filter): Search input q, category dropdown, and status dropdown (Open/Done)."""
    AuthPage(browser, live_server_url).register(unique_user("fltui"), "ValidPass123")
    form = TaskFormPage(browser, live_server_url)
    tasks = TasksPage(browser, live_server_url)

    form.create_task("Alpha Study Notes", category_text="Study")
    form.create_task("Beta Work Report", category_text="Work")
    tasks.toggle_task("Beta Work Report")  # Make Beta Done while Alpha stays Open

    # 1. Title search filter
    tasks.search_title("Alpha")
    assert tasks.row_titles() == ["Alpha Study Notes"]

    # 2. Category dropdown filter
    tasks.open()
    tasks.filter_category("Work")
    assert tasks.row_titles() == ["Beta Work Report"]

    # 3. Status dropdown filter (Done and Open)
    tasks.open()
    tasks.filter_status("Done")
    assert tasks.row_titles() == ["Beta Work Report"]
    tasks.filter_status("Open")
    assert tasks.row_titles() == ["Alpha Study Notes"]


@pytest.mark.ui
def test_reg_009_task_state_transition_open_done_open(browser, live_server_url):
    """TC-REG-009 (maps TC-BB-018, TC-BB-019): Toggle task Open -> Done -> Open via status circle."""
    AuthPage(browser, live_server_url).register(unique_user("stateui"), "ValidPass123")
    form = TaskFormPage(browser, live_server_url)
    tasks = TasksPage(browser, live_server_url)

    due_future = (date.today() + timedelta(days=5)).strftime("%Y-%m-%d")
    form.create_task("Toggle Lifecycle Task", category_text="Personal", due_yyyy_mm_dd=due_future)

    tasks.toggle_task("Toggle Lifecycle Task")
    row = tasks.find_row_by_title("Toggle Lifecycle Task")
    assert "done" in row.get_attribute("class")
    assert tasks.badge_for("Toggle Lifecycle Task") == "Done"

    tasks.toggle_task("Toggle Lifecycle Task")
    row = tasks.find_row_by_title("Toggle Lifecycle Task")
    assert "done" not in (row.get_attribute("class") or "")
    assert tasks.badge_for("Toggle Lifecycle Task") == "Upcoming"


@pytest.mark.ui
def test_reg_010_delete_task_confirm_accept_and_dismiss(browser, live_server_url):
    """TC-REG-010 (maps Task Delete / DEF-004 check): Dismiss keeps task; Accept deletes task."""
    AuthPage(browser, live_server_url).register(unique_user("delui"), "ValidPass123")
    form = TaskFormPage(browser, live_server_url)
    tasks = TasksPage(browser, live_server_url)

    form.create_task("Task To Delete", category_text="Urgent")
    alert_text = tasks.click_delete("Task To Delete", accept=False)
    assert "Delete" in alert_text
    assert "Task To Delete" in tasks.row_titles()

    tasks.click_delete("Task To Delete", accept=True)
    WebDriverWait(browser, 5).until(lambda d: "Task To Delete" not in TasksPage(d, live_server_url).row_titles())
    assert "No tasks match your filters." in browser.page_source


@pytest.mark.ui
def test_reg_011_dashboard_counters_and_screenshots(browser, live_server_url):
    """TC-REG-011 (maps Dashboard Sync): Dashboard cards match overdue, due soon, open, and done tasks."""
    AuthPage(browser, live_server_url).register(unique_user("dashui"), "ValidPass123")
    form = TaskFormPage(browser, live_server_url)
    tasks = TasksPage(browser, live_server_url)
    today = date.today()

    form.create_task("Past Due Task", category_text="Urgent", due_yyyy_mm_dd=(today - timedelta(days=2)).strftime("%Y-%m-%d"))
    form.create_task("Due Soon Task", category_text="Work", due_yyyy_mm_dd=(today + timedelta(days=1)).strftime("%Y-%m-%d"))
    form.create_task("Completed Task", category_text="Study", due_yyyy_mm_dd=(today + timedelta(days=4)).strftime("%Y-%m-%d"))
    tasks.toggle_task("Completed Task")
    browser.save_screenshot(os.path.join(EVIDENCE_DIR, "selenium_tasks.png"))

    tasks.go_dashboard()
    WebDriverWait(browser, 5).until(EC.url_contains("/dashboard"))
    browser.save_screenshot(os.path.join(EVIDENCE_DIR, "selenium_dashboard.png"))

    stats = DashboardPage(browser).stats()
    assert stats == {
        "Total Tasks": 3,
        "Open": 2,
        "Overdue": 1,
        "Due Soon": 1,
        "Completed (last 7 days)": 1,
    }


@pytest.mark.ui
def test_reg_012_urgency_classification_boundaries(browser, live_server_url):
    """TC-REG-012 (maps TC-BB-020, 022..025): Verify Overdue, Due Soon (1-2d), Upcoming (3d), and No due date."""
    AuthPage(browser, live_server_url).register(unique_user("urgui"), "ValidPass123")
    form = TaskFormPage(browser, live_server_url)
    tasks = TasksPage(browser, live_server_url)
    today = date.today()
    cases = [
        ("T_Past", (today - timedelta(days=1)).strftime("%Y-%m-%d"), "Overdue"),
        ("T_1Day", (today + timedelta(days=1)).strftime("%Y-%m-%d"), "Due Soon"),
        ("T_2Days", (today + timedelta(days=2)).strftime("%Y-%m-%d"), "Due Soon"),
        ("T_3Days", (today + timedelta(days=3)).strftime("%Y-%m-%d"), "Upcoming"),
        ("T_NoDate", "", "No due date"),
    ]
    for title, due_s, _ in cases:
        form.create_task(title, category_text="Work", due_yyyy_mm_dd=due_s)

    for title, _, expected_badge in cases:
        assert tasks.badge_for(title) == expected_badge


@pytest.mark.ui
@pytest.mark.known_bug
def test_reg_013_urgency_due_today_regression_guard(browser, live_server_url):
    """TC-REG-013 (maps TC-BB-021, WB-006 / DEF-002, DEF-WB-002): Due today must display 'Due Today'."""
    AuthPage(browser, live_server_url).register(unique_user("todayui"), "ValidPass123")
    form = TaskFormPage(browser, live_server_url)
    tasks = TasksPage(browser, live_server_url)
    form.create_task("Today Task", category_text="Urgent", due_yyyy_mm_dd=date.today().strftime("%Y-%m-%d"))
    badge = tasks.badge_for("Today Task")
    assert badge == "Due Today", f"DEF-002/DEF-WB-002 still open: due today rendered as '{badge}'"


@pytest.mark.ui
@pytest.mark.known_bug
def test_reg_014_stored_xss_dom_escaping_guard(browser, live_server_url):
    """TC-REG-014 (maps TC-SEC-006 / DEF-SP-005): Task title HTML tags must not render live DOM nodes."""
    AuthPage(browser, live_server_url).register(unique_user("xssui"), "ValidPass123")
    TaskFormPage(browser, live_server_url).create_task("<span id='stqa-xss-injected'>XSS</span>", category_text="Work")
    injected = browser.find_elements(By.ID, "stqa-xss-injected")
    assert len(injected) == 0, "DEF-SP-005 still open: |safe in index.html rendered unescaped HTML element in DOM"
