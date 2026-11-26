"""
Week 6 — Hardened PyTest & Selenium Fixtures for PyTodo Pro Regression Suite
Uses isolated temp SQLite DB, stderr capture, zero implicit wait mixing,
alert-safe teardown, unique username helper, and screenshot-on-failure hook.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

import pytest
from selenium import webdriver
from selenium.common.exceptions import NoAlertPresentException
from selenium.webdriver.chrome.options import Options

sys.dont_write_bytecode = True

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_DIR = os.path.join(REPO_ROOT, "pytodo_pro_student_original")
EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "evidence")
FAILURES_DIR = os.path.join(EVIDENCE_DIR, "failures")

CHROME_PATHS = [
    os.environ.get("CHROME_BINARY", ""),
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]

SERVER_RUNNER_CODE = r"""
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import app as pytodo_app
from werkzeug.serving import make_server

pytodo_app.DATABASE = sys.argv[2]
pytodo_app.app.config["TESTING"] = False
pytodo_app.app.config["DEBUG"] = False
pytodo_app.init_db()
srv = make_server("127.0.0.1", 0, pytodo_app.app, threaded=True)
print(f"READY:{srv.server_port}", flush=True)
srv.serve_forever()
"""


def unique_user(prefix: str = "reg") -> str:
    """Return a valid 3-20 char unique username for order-independent tests."""
    clean = re.sub(r"[^A-Za-z0-9_]", "_", prefix)[:10]
    return f"{clean}_{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="session")
def live_server_url():
    """Start an isolated PyTodo Pro subprocess and capture stderr logs."""
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    if os.path.exists(FAILURES_DIR):
        shutil.rmtree(FAILURES_DIR)
    os.makedirs(FAILURES_DIR, exist_ok=True)
    stderr_path = os.path.join(EVIDENCE_DIR, "server_errors.log")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "week6_regression.db")
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        stderr_file = open(stderr_path, "w", encoding="utf-8")
        proc = subprocess.Popen(
            [sys.executable, "-B", "-c", SERVER_RUNNER_CODE, APP_DIR, db_path],
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            text=True,
            env=env,
        )
        base_url = None
        deadline = time.time() + 15
        while time.time() < deadline:
            line = proc.stdout.readline().strip()
            if line.startswith("READY:"):
                port = int(line.split(":", 1)[1])
                base_url = f"http://127.0.0.1:{port}"
                break
            if proc.poll() is not None:
                stderr_file.close()
                raise RuntimeError(f"Server exited early ({proc.returncode}); see {stderr_path}")
        if base_url is None:
            proc.kill()
            stderr_file.close()
            raise TimeoutError("Timed out starting PyTodo Pro subprocess")
        try:
            yield base_url
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            stderr_file.close()


@pytest.fixture(scope="module")
def _chrome_driver():
    """Launch headless Chrome once per module with explicit-only waits (implicit=0)."""
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1366,900")
    for candidate in CHROME_PATHS:
        if candidate and os.path.exists(candidate):
            opts.binary_location = candidate
            break
    driver = webdriver.Chrome(options=opts)
    driver.implicitly_wait(0)
    try:
        yield driver
    finally:
        driver.quit()


def _dismiss_stray_alert(driver):
    try:
        driver.switch_to.alert.dismiss()
    except NoAlertPresentException:
        pass


@pytest.fixture(scope="function")
def browser(_chrome_driver, live_server_url, request):
    """Provide clean session state per test and guard against stray alerts."""
    _dismiss_stray_alert(_chrome_driver)
    _chrome_driver.get(f"{live_server_url}/logout")
    _chrome_driver.delete_all_cookies()
    yield _chrome_driver
    _dismiss_stray_alert(_chrome_driver)


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Automatically capture a browser screenshot when any UI test fails."""
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "call" and rep.failed and "browser" in item.fixturenames:
        driver = item.funcargs.get("browser")
        if driver is not None:
            _dismiss_stray_alert(driver)
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", item.name)
            try:
                driver.save_screenshot(os.path.join(FAILURES_DIR, f"{safe_name}.png"))
            except Exception:
                pass
