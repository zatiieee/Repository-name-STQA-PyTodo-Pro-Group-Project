"""
Week 6 — Pure Unit Regression Suite for PyTodo Pro Helpers
Maps to Week 2 White-Box Test Cases (WB-017, WB-023) without server/DB startup.
"""

import os
import sys
from datetime import datetime, timedelta

import pytest

sys.dont_write_bytecode = True
APP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "pytodo_pro_student_original"))
sys.path.insert(0, APP_DIR)
import helpers  # noqa: E402


@pytest.mark.unit
@pytest.mark.known_bug
def test_reg_018_exact_seven_day_completion_regression_guard():
    """TC-REG-018 (maps WB-017 / DEF-WB-003): Exact 7-day completion and same-second boundary must count."""
    now = datetime(2026, 11, 27, 12, 0, 0)
    seven_days_ago = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    assert helpers.completed_in_last_n_days(seven_days_ago, n=7, now=now) is True, (
        "DEF-WB-003 still open: completed_in_last_n_days uses '< n' instead of '<= n'"
    )
    same_second = now.strftime("%Y-%m-%d %H:%M:%S")
    assert helpers.completed_in_last_n_days(same_second, n=7, now=now) is True
