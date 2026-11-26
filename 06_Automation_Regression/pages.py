"""
Week 6 — Lightweight Page Object Models for PyTodo Pro Web UI
Centralizes locators, safe SSR form waits, and stale-safe filter waits.
"""

from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait


def submit_and_wait(driver, clickable, timeout: int = 6):
    """Click a submit button/link and wait for full page reload + readyState."""
    driver.execute_script("window.__stqa_page_mark = 1;")
    clickable.click()
    WebDriverWait(driver, timeout).until(
        lambda d: d.execute_script("return window.__stqa_page_mark === undefined && document.readyState === 'complete';")
    )


class AuthPage:
    USERNAME = (By.NAME, "username")
    PASSWORD = (By.NAME, "password")
    SUBMIT = (By.CSS_SELECTOR, "button[type='submit']")
    ERROR = (By.CSS_SELECTOR, "p.error")

    def __init__(self, driver, base_url: str):
        self.driver = driver
        self.base_url = base_url

    def register(self, username: str, password: str):
        self.driver.get(f"{self.base_url}/register")
        u_el = self.driver.find_element(*self.USERNAME)
        p_el = self.driver.find_element(*self.PASSWORD)
        u_el.clear()
        u_el.send_keys(username)
        p_el.clear()
        p_el.send_keys(password)
        submit_and_wait(self.driver, self.driver.find_element(*self.SUBMIT))

    def login(self, username: str, password: str):
        self.driver.get(f"{self.base_url}/login")
        self.driver.find_element(*self.USERNAME).send_keys(username)
        self.driver.find_element(*self.PASSWORD).send_keys(password)
        submit_and_wait(self.driver, self.driver.find_element(*self.SUBMIT))

    def error_text(self) -> str:
        return self.driver.find_element(*self.ERROR).text


class TasksPage:
    NAV_USER = (By.CSS_SELECTOR, ".nav-user")
    LOGOUT_LINK = (By.LINK_TEXT, "Log out")
    DASHBOARD_LINK = (By.LINK_TEXT, "Dashboard")
    TABLE_BODY = (By.CSS_SELECTOR, "table.task-table tbody")
    TABLE_ROWS = (By.CSS_SELECTOR, "table.task-table tbody tr")
    CATEGORY_SELECT = (By.NAME, "category")
    STATUS_SELECT = (By.NAME, "status")
    SEARCH_INPUT = (By.NAME, "q")
    FILTER_BTN = (By.CSS_SELECTOR, "form.filters button[type='submit']")

    def __init__(self, driver, base_url: str):
        self.driver = driver
        self.base_url = base_url

    def open(self):
        self.driver.get(f"{self.base_url}/")

    def nav_username(self) -> str:
        return self.driver.find_element(*self.NAV_USER).text

    def logout(self):
        submit_and_wait(self.driver, self.driver.find_element(*self.LOGOUT_LINK))

    def go_dashboard(self):
        submit_and_wait(self.driver, self.driver.find_element(*self.DASHBOARD_LINK))

    def find_row_by_title(self, title: str):
        for tr in self.driver.find_elements(*self.TABLE_ROWS):
            try:
                if tr.find_element(By.CSS_SELECTOR, "td.title-cell").text.strip() == title:
                    return tr
            except NoSuchElementException:
                continue
        raise AssertionError(f"Task row not found for title={title!r}")

    def row_titles(self):
        titles = []
        for tr in self.driver.find_elements(*self.TABLE_ROWS):
            cells = tr.find_elements(By.CSS_SELECTOR, "td.title-cell")
            if cells:
                titles.append(cells[0].text.strip())
        return titles

    def toggle_task(self, title: str):
        row = self.find_row_by_title(title)
        submit_and_wait(self.driver, row.find_element(By.CSS_SELECTOR, "button.check-btn"))

    def click_edit(self, title: str):
        row = self.find_row_by_title(title)
        submit_and_wait(self.driver, row.find_element(By.LINK_TEXT, "Edit"))

    def click_delete(self, title: str, accept: bool = True) -> str:
        row = self.find_row_by_title(title)
        row.find_element(By.CSS_SELECTOR, "button.link-btn").click()
        alert = WebDriverWait(self.driver, 5).until(EC.alert_is_present())
        text = alert.text
        if accept:
            alert.accept()
            WebDriverWait(self.driver, 5).until(
                lambda d: d.execute_script("return document.readyState === 'complete';")
            )
        else:
            alert.dismiss()
        return text

    def search_title(self, query: str):
        box = self.driver.find_element(*self.SEARCH_INPUT)
        box.clear()
        box.send_keys(query)
        submit_and_wait(self.driver, self.driver.find_element(*self.FILTER_BTN))

    def _select_autosubmit(self, locator, visible_text: str):
        old_body = self.driver.find_element(*self.TABLE_BODY)
        Select(self.driver.find_element(*locator)).select_by_visible_text(visible_text)
        WebDriverWait(self.driver, 5).until(EC.staleness_of(old_body))
        WebDriverWait(self.driver, 5).until(
            lambda d: d.execute_script("return document.readyState === 'complete';")
        )

    def filter_category(self, category_name: str):
        self._select_autosubmit(self.CATEGORY_SELECT, category_name)

    def filter_status(self, status_label: str):
        self._select_autosubmit(self.STATUS_SELECT, status_label)

    def badge_for(self, title: str) -> str:
        return self.find_row_by_title(title).find_element(By.CSS_SELECTOR, "span.badge").text.strip()

    def row_text(self, title: str) -> str:
        try:
            return self.find_row_by_title(title).text
        except StaleElementReferenceException:
            return self.find_row_by_title(title).text


class TaskFormPage:
    TITLE = (By.NAME, "title")
    DESCRIPTION = (By.NAME, "description")
    CATEGORY = (By.NAME, "category_id")
    DUE_DATE = (By.NAME, "due_date")
    SUBMIT = (By.CSS_SELECTOR, "button[type='submit']")
    CANCEL = (By.LINK_TEXT, "Cancel")

    def __init__(self, driver, base_url: str):
        self.driver = driver
        self.base_url = base_url

    def create_task(self, title: str, description: str = "", category_text: str = "Work", due_yyyy_mm_dd: str = ""):
        self.driver.get(f"{self.base_url}/tasks/new")
        self.fill_and_submit(title, description=description, category_text=category_text, due_yyyy_mm_dd=due_yyyy_mm_dd)

    def fill_and_submit(self, title: str, description: str = "", category_text: str = "", due_yyyy_mm_dd: str = ""):
        t_el = self.driver.find_element(*self.TITLE)
        t_el.clear()
        t_el.send_keys(title)
        if description is not None:
            d_el = self.driver.find_element(*self.DESCRIPTION)
            d_el.clear()
            if description:
                d_el.send_keys(description)
        if category_text:
            Select(self.driver.find_element(*self.CATEGORY)).select_by_visible_text(category_text)
        if due_yyyy_mm_dd is not None:
            due_el = self.driver.find_element(*self.DUE_DATE)
            self.driver.execute_script("arguments[0].value = arguments[1];", due_el, due_yyyy_mm_dd)
        submit_and_wait(self.driver, self.driver.find_element(*self.SUBMIT))

    def cancel(self):
        submit_and_wait(self.driver, self.driver.find_element(*self.CANCEL))


class DashboardPage:
    CARDS = (By.CSS_SELECTOR, ".stat-card")

    def __init__(self, driver):
        self.driver = driver

    def stats(self) -> dict:
        result = {}
        for c in self.driver.find_elements(*self.CARDS):
            lbl = c.find_element(By.CSS_SELECTOR, ".stat-label").text.strip()
            val = int(c.find_element(By.CSS_SELECTOR, ".stat-value").text.strip())
            result[lbl] = val
        return result
