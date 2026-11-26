"""
Week 5 — Controlled Performance Test Suite for PyTodo Pro
Owner: Member 4 (05_Security_Performance)

Improvements over baseline harness:
  - Spawns PyTodo Pro in an isolated SUBPROCESS so load-generator threads
    never share a CPython GIL with the Werkzeug WSGI server.
  - Captures server stderr/tracebacks directly into evidence/server_errors.log
    and persists truncated HTTP >=400/500 bodies into evidence/performance_results.json.
  - Seeds a multi-tenant SQLite database (10 users x 150 tasks = 1,500 rows)
    to exercise unindexed user_id queries and realistic HTML rendering.
  - Executes warmup requests prior to timed measurement and keeps client lock
    bookkeeping outside time.perf_counter().
  - Evaluates explicit SLA acceptance criteria (TC-PERF-001 through TC-PERF-006)
    including POST /api/login CPU cost and mixed read/write lock contention.
"""

import concurrent.futures
import csv
import json
import os
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from datetime import date, datetime, timedelta, timezone

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import requests

sys.dont_write_bytecode = True

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_DIR = os.path.join(REPO_ROOT, "pytodo_pro_student_original")
EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "evidence")

NUM_BENCH_USERS = 10
TASKS_PER_USER = 150  # 1,500 total tasks across 10 users (unindexed user_id)
WARMUP_REQUESTS = 10

CONCURRENCY_LEVELS = [1, 10, 25, 50]
WORKLOAD_PLAN = {
    "GET /api/tasks": {1: 50, 10: 150, 25: 250, 50: 400},
    "GET /api/dashboard": {1: 50, 10: 150, 25: 250, 50: 400},
    "GET / (Web UI)": {1: 30, 10: 100, 25: 175, 50: 250},
    "POST /api/tasks": {1: 40, 10: 120, 25: 200, 50: 300},
    "Mixed (70R/20D/10W)": {25: 250, 50: 400},
    "POST /api/login": {1: 20, 10: 60},
}

# Explicit pre-execution SLA thresholds (for TC-PERF-001 .. TC-PERF-006)
SLA_RULES = {
    "TC-PERF-001": {
        "endpoint": "GET /api/tasks",
        "feature": "Paginated Task Search API (GET /api/tasks?page=0&per_page=20)",
        "objective": "Verify paginated JSON reads remain <=500ms p95 at 25 users, <=1000ms p95 at 50 users, with 0% errors.",
        "p95_25_max_ms": 500.0,
        "p95_50_max_ms": 1000.0,
        "max_err_pct": 0.0,
        "defect_if_fail": "DEF-SP-014",
    },
    "TC-PERF-002": {
        "endpoint": "GET /api/dashboard",
        "feature": "Dashboard Aggregation API (GET /api/dashboard)",
        "objective": "Verify full-user urgency aggregation remains <=500ms p95 at 25 users, <=1000ms p95 at 50 users, with 0% errors.",
        "p95_25_max_ms": 500.0,
        "p95_50_max_ms": 1000.0,
        "max_err_pct": 0.0,
        "defect_if_fail": "DEF-SP-014",
    },
    "TC-PERF-003": {
        "endpoint": "GET / (Web UI)",
        "feature": "Web UI Full Task List Render (GET /)",
        "objective": "Verify Web UI task table render remains <=1000ms p95 up to 50 concurrent users with 0% errors.",
        "p95_25_max_ms": 1000.0,
        "p95_50_max_ms": 1000.0,
        "max_err_pct": 0.0,
        "defect_if_fail": "DEF-SP-014",
    },
    "TC-PERF-004": {
        "endpoint": "POST /api/tasks",
        "feature": "Authenticated Task Creation API (POST /api/tasks)",
        "objective": "Verify concurrent task inserts remain <=1000ms p95 up to 50 users with 0% HTTP 5xx lock errors.",
        "p95_25_max_ms": 1000.0,
        "p95_50_max_ms": 1000.0,
        "max_err_pct": 0.0,
        "defect_if_fail": "DEF-SP-015",
    },
    "TC-PERF-005": {
        "endpoint": "POST /api/login",
        "feature": "Password Hashing Auth Endpoint (POST /api/login)",
        "objective": "Verify Werkzeug scrypt password authentication stays <=1000ms p95 at 10 concurrent users with 0% errors.",
        "p95_10_max_ms": 1000.0,
        "max_err_pct": 0.0,
        "defect_if_fail": "DEF-SP-015",
    },
    "TC-PERF-006": {
        "endpoint": "Mixed (70R/20D/10W)",
        "feature": "Mixed Read/Dashboard/Write Contention (70% GET, 20% Dash, 10% POST)",
        "objective": "Verify concurrent mixed reads and SQLite writes sustain <=1000ms p95 up to 50 users with 0% errors.",
        "p95_25_max_ms": 1000.0,
        "p95_50_max_ms": 1000.0,
        "max_err_pct": 0.0,
        "defect_if_fail": "DEF-SP-015",
    },
}

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


class SubprocessAppServer:
    """Runs PyTodo Pro in an isolated external Python process and captures stderr."""

    def __init__(self, db_path: str, stderr_log_path: str):
        self.db_path = db_path
        self.stderr_log_path = stderr_log_path
        self.proc = None
        self.stderr_file = None
        self.base_url = None

    def __enter__(self):
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        self.stderr_file = open(self.stderr_log_path, "w", encoding="utf-8")
        self.proc = subprocess.Popen(
            [sys.executable, "-B", "-c", SERVER_RUNNER_CODE, APP_DIR, self.db_path],
            stdout=subprocess.PIPE,
            stderr=self.stderr_file,
            text=True,
            env=env,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            line = self.proc.stdout.readline().strip()
            if line.startswith("READY:"):
                port = int(line.split(":", 1)[1])
                self.base_url = f"http://127.0.0.1:{port}"
                return self
            if self.proc.poll() is not None:
                raise RuntimeError(f"Server subprocess exited early with code {self.proc.returncode}")
        raise TimeoutError("Timed out waiting for PyTodo Pro server subprocess")

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.stderr_file is not None:
            self.stderr_file.close()


def percentile(sorted_vals, pct: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f)


def seed_multi_tenant_db(base_url: str, db_path: str):
    """Register NUM_BENCH_USERS accounts and populate TASKS_PER_USER tasks each."""
    accounts = []
    for u_idx in range(NUM_BENCH_USERS):
        uname = f"perf_user_{u_idx:02d}"
        pw = "Benchmark123"
        s = requests.Session()
        r = s.post(f"{base_url}/api/register", json={"username": uname, "password": pw}, timeout=10)
        r.raise_for_status()
        accounts.append((r.json()["id"], uname, pw))

    conn = sqlite3.connect(db_path)
    today = date.today()
    now_iso = datetime.now().isoformat()
    rows = []
    for uid, _, _ in accounts:
        for i in range(TASKS_PER_USER):
            due = (today + timedelta(days=(i % 10) - 3)).strftime("%Y-%m-%d")
            done = 1 if i % 4 == 0 else 0
            comp_at = (datetime.now() - timedelta(days=i % 5)).strftime("%Y-%m-%d %H:%M:%S") if done else None
            cat_id = (i % 4) + 1
            rows.append((uid, f"Bench U{uid} Task #{i:03d}", f"Description {i}", cat_id, due, done, comp_at, now_iso))
    conn.executemany(
        "INSERT INTO tasks (user_id, title, description, category_id, due_date, done, completed_at, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    conn.close()
    return accounts


def make_authed_sessions(base_url: str, accounts, count: int):
    sessions = []
    for idx in range(count):
        _, uname, pw = accounts[idx % len(accounts)]
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
        s.mount("http://", adapter)
        r = s.post(f"{base_url}/api/login", json={"username": uname, "password": pw}, timeout=10)
        r.raise_for_status()
        sessions.append((s, uname, pw))
    return sessions


def execute_single_request(base_url: str, endpoint_name: str, sess, uname: str, pw: str, req_idx: int):
    if endpoint_name == "GET /api/tasks":
        r = sess.get(f"{base_url}/api/tasks?page=0&per_page=20", timeout=15)
        return r, (200,)
    if endpoint_name == "GET /api/dashboard":
        r = sess.get(f"{base_url}/api/dashboard", timeout=15)
        return r, (200,)
    if endpoint_name == "GET / (Web UI)":
        r = sess.get(f"{base_url}/", timeout=15)
        return r, (200,)
    if endpoint_name == "POST /api/tasks":
        r = sess.post(
            f"{base_url}/api/tasks",
            json={
                "title": f"Load Write {req_idx}",
                "description": "Perf write",
                "category_id": 1,
                "due_date": date.today().strftime("%Y-%m-%d"),
            },
            timeout=15,
        )
        return r, (201,)
    if endpoint_name == "POST /api/login":
        r = sess.post(f"{base_url}/api/login", json={"username": uname, "password": pw}, timeout=15)
        return r, (200,)
    if endpoint_name == "Mixed (70R/20D/10W)":
        mod = req_idx % 10
        if mod < 7:
            return sess.get(f"{base_url}/api/tasks?page=0&per_page=20", timeout=15), (200,)
        if mod < 9:
            return sess.get(f"{base_url}/api/dashboard", timeout=15), (200,)
        return (
            sess.post(
                f"{base_url}/api/tasks",
                json={
                    "title": f"Mixed Write {req_idx}",
                    "description": "Mixed perf write",
                    "category_id": 2,
                    "due_date": date.today().strftime("%Y-%m-%d"),
                },
                timeout=15,
            ),
            (201,),
        )
    raise ValueError(f"Unknown endpoint {endpoint_name}")


def warmup_endpoint(base_url: str, endpoint_name: str, session_tuple):
    sess, uname, pw = session_tuple
    for i in range(WARMUP_REQUESTS):
        try:
            execute_single_request(base_url, endpoint_name, sess, uname, pw, 900000 + i)
        except Exception:
            pass


def benchmark_stage(base_url: str, endpoint_name: str, concurrency: int, total_requests: int, sessions):
    latencies_ms = []
    status_counts = Counter()
    errors = 0
    error_notes = Counter()
    error_samples = []
    agg_lock = threading.Lock()

    per_worker = [total_requests // concurrency] * concurrency
    for i in range(total_requests % concurrency):
        per_worker[i] += 1

    # Pre-assign disjoint request IDs so workers never contend on a shared lock inside timing
    offsets = []
    cur_off = 0
    for cnt in per_worker:
        offsets.append(cur_off)
        cur_off += cnt

    def worker(worker_id: int, req_count: int, start_seq: int):
        sess, uname, pw = sessions[worker_id]
        local_lats = []
        local_statuses = Counter()
        local_errs = 0
        local_err_notes = Counter()
        local_samples = []

        for step in range(req_count):
            req_id = start_seq + step
            t0 = time.perf_counter()
            try:
                r, expected_ok = execute_single_request(base_url, endpoint_name, sess, uname, pw, req_id)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                local_lats.append(elapsed_ms)
                local_statuses[str(r.status_code)] += 1
                if r.status_code not in expected_ok:
                    local_errs += 1
                    local_err_notes[f"HTTP {r.status_code}"] += 1
                    if len(local_samples) < 3:
                        snippet = re.sub(r"\s+", " ", r.text[:220]).strip()
                        local_samples.append({"status": r.status_code, "body_excerpt": snippet})
            except Exception as exc:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                local_lats.append(elapsed_ms)
                local_errs += 1
                local_statuses["EXC"] += 1
                local_err_notes[type(exc).__name__] += 1
                if len(local_samples) < 3:
                    local_samples.append({"status": "EXC", "body_excerpt": f"{type(exc).__name__}: {str(exc)[:180]}"})

        with agg_lock:
            latencies_ms.extend(local_lats)
            status_counts.update(local_statuses)
            nonlocal errors
            errors += local_errs
            error_notes.update(local_err_notes)
            if len(error_samples) < 5:
                error_samples.extend(local_samples[: 5 - len(error_samples)])

    t_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(worker, wid, per_worker[wid], offsets[wid]) for wid in range(concurrency)]
        for fut in futs:
            fut.result()
    wall_s = max(time.perf_counter() - t_start, 1e-6)

    sorted_lats = sorted(latencies_ms)
    return {
        "endpoint": endpoint_name,
        "concurrency": concurrency,
        "total_requests": total_requests,
        "success_count": total_requests - errors,
        "error_count": errors,
        "error_rate_pct": round((errors / total_requests) * 100.0, 2),
        "wall_time_s": round(wall_s, 3),
        "throughput_rps": round(total_requests / wall_s, 2),
        "min_ms": round(sorted_lats[0], 2),
        "mean_ms": round(statistics.mean(sorted_lats), 2),
        "p50_ms": round(percentile(sorted_lats, 50), 2),
        "p95_ms": round(percentile(sorted_lats, 95), 2),
        "max_ms": round(sorted_lats[-1], 2),
        "status_counts": dict(status_counts),
        "error_breakdown": dict(error_notes),
        "error_samples": error_samples,
    }


def evaluate_slas(rows):
    """Produce formal 12-field Performance Test Case outcomes against SLA_RULES."""
    tc_rows = []
    for tc_id, rule in SLA_RULES.items():
        ep = rule["endpoint"]
        ep_runs = sorted([r for r in rows if r["endpoint"] == ep], key=lambda x: x["concurrency"])
        by_c = {r["concurrency"]: r for r in ep_runs}
        max_err = max(r["error_rate_pct"] for r in ep_runs)
        passed = max_err <= rule["max_err_pct"]
        if "p95_10_max_ms" in rule and 10 in by_c:
            if by_c[10]["p95_ms"] > rule["p95_10_max_ms"]:
                passed = False
        if "p95_25_max_ms" in rule and 25 in by_c:
            if by_c[25]["p95_ms"] > rule["p95_25_max_ms"]:
                passed = False
        if "p95_50_max_ms" in rule and 50 in by_c:
            if by_c[50]["p95_ms"] > rule["p95_50_max_ms"]:
                passed = False

        summary_parts = [
            f"{c}u: mean={r['mean_ms']}ms, p50={r['p50_ms']}ms, p95={r['p95_ms']}ms, rps={r['throughput_rps']}, err={r['error_rate_pct']}%"
            for c, r in by_c.items()
        ]
        tc_rows.append(
            {
                "test_case_id": tc_id,
                "feature": rule["feature"],
                "technique": "Stepped-Load Performance Test (0ms think time)",
                "objective": rule["objective"],
                "preconditions": f"Multi-tenant DB seeded ({NUM_BENCH_USERS} users x {TASKS_PER_USER} tasks = {NUM_BENCH_USERS * TASKS_PER_USER} rows); {WARMUP_REQUESTS} warmup requests executed.",
                "test_data": f"Stages={list(by_c.keys())}, Requests={[r['total_requests'] for r in ep_runs]}",
                "steps": f"1. Start isolated PyTodo Pro subprocess.\n2. Warm up {ep}.\n3. Execute stepped concurrency load ({list(by_c.keys())} VUs).",
                "expected_result": rule["objective"],
                "actual_result": " | ".join(summary_parts),
                "status": "Pass" if passed else "Fail",
                "evidence": f"evidence/performance_results.csv & evidence/performance_results.json [{ep}]",
                "defect_id": "None" if passed else rule["defect_if_fail"],
            }
        )
    return tc_rows


def generate_charts(rows):
    primary_eps = ["GET /api/tasks", "GET /api/dashboard", "GET / (Web UI)", "POST /api/tasks"]
    colors = {
        "GET /api/tasks": "#1f77b4",
        "GET /api/dashboard": "#2ca02c",
        "GET / (Web UI)": "#ff7f0e",
        "POST /api/tasks": "#d62728",
        "Mixed (70R/20D/10W)": "#9467bd",
    }

    # Chart 1: Median (p50) vs p95 Latency (highlights tail skew on writes & N+1 on GET /)
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.9), dpi=150)
    max_p50 = max(r["p50_ms"] for r in rows if r["endpoint"] in primary_eps)
    max_p95 = max(r["p95_ms"] for r in rows if r["endpoint"] in primary_eps)

    for ep in primary_eps:
        sub = sorted([r for r in rows if r["endpoint"] == ep], key=lambda x: x["concurrency"])
        xs = [r["concurrency"] for r in sub]
        axes[0].plot(xs, [r["p50_ms"] for r in sub], marker="o", linestyle="--", linewidth=2, label=ep, color=colors[ep])
        axes[1].plot(xs, [r["p95_ms"] for r in sub], marker="s", linestyle="-", linewidth=2, label=ep, color=colors[ep])

    axes[0].set_title("Median (p50) Response Time vs. Concurrency", fontsize=11, fontweight="bold")
    axes[0].set_xlabel("Concurrent Virtual Users (0 ms think time)")
    axes[0].set_ylabel("p50 Latency (ms)")
    axes[0].set_xticks(CONCURRENCY_LEVELS)
    axes[0].set_ylim(0, max_p50 * 1.18)
    axes[0].grid(True, linestyle="--", alpha=0.4)
    axes[0].legend(fontsize=8, loc="upper left")

    axes[1].set_title("95th Percentile (p95) Response Time vs. Concurrency", fontsize=11, fontweight="bold")
    axes[1].set_xlabel("Concurrent Virtual Users (0 ms think time)")
    axes[1].set_ylabel("p95 Latency (ms)")
    axes[1].set_xticks(CONCURRENCY_LEVELS)
    axes[1].set_ylim(0, max_p95 * 1.18)
    axes[1].grid(True, linestyle="--", alpha=0.4)
    axes[1].legend(fontsize=8, loc="upper left")

    plt.tight_layout()
    rt_path = os.path.join(EVIDENCE_DIR, "perf_response_time.png")
    plt.savefig(rt_path)
    plt.close(fig)

    # Chart 2: Throughput & Error Rate with dynamic axes + Mixed workload points
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.9), dpi=150)
    plot_eps = primary_eps + ["Mixed (70R/20D/10W)"]
    max_rps = max(r["throughput_rps"] for r in rows if r["endpoint"] in plot_eps)
    max_err = max(r["error_rate_pct"] for r in rows if r["endpoint"] in plot_eps)

    for ep in plot_eps:
        sub = sorted([r for r in rows if r["endpoint"] == ep], key=lambda x: x["concurrency"])
        xs = [r["concurrency"] for r in sub]
        ys_rps = [r["throughput_rps"] for r in sub]
        ys_err = [r["error_rate_pct"] for r in sub]
        axes[0].plot(xs, ys_rps, marker="o", linewidth=2, label=ep, color=colors[ep])
        axes[1].plot(xs, ys_err, marker="^", linewidth=2, label=ep, color=colors[ep])
        for x, y, r in zip(xs, ys_err, sub):
            if y > 0:
                axes[1].annotate(
                    f"{y:.2f}% ({r['error_count']}/{r['total_requests']})",
                    xy=(x, y),
                    xytext=(-52, 6),
                    textcoords="offset points",
                    fontsize=8,
                    fontweight="bold",
                    color=colors[ep],
                )

    axes[0].set_title("Throughput (req/s) vs. Concurrency", fontsize=11, fontweight="bold")
    axes[0].set_xlabel("Concurrent Virtual Users (0 ms think time)")
    axes[0].set_ylabel("Throughput (requests/sec)")
    axes[0].set_xticks(CONCURRENCY_LEVELS)
    axes[0].set_ylim(0, max_rps * 1.38)
    axes[0].grid(True, linestyle="--", alpha=0.4)
    axes[0].legend(fontsize=8, loc="upper right")

    axes[1].set_title("Error Rate (%) vs. Concurrency", fontsize=11, fontweight="bold")
    axes[1].set_xlabel("Concurrent Virtual Users (0 ms think time)")
    axes[1].set_ylabel("Error Rate (%)")
    axes[1].set_xticks(CONCURRENCY_LEVELS)
    axes[1].set_ylim(-0.05, max(5.0, max_err * 1.35))
    axes[1].grid(True, linestyle="--", alpha=0.4)
    axes[1].legend(fontsize=8, loc="upper left")

    plt.tight_layout()
    tp_path = os.path.join(EVIDENCE_DIR, "perf_throughput_error.png")
    plt.savefig(tp_path)
    plt.close(fig)
    return rt_path, tp_path


def run_performance_experiment():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    started_at = datetime.now(timezone.utc).astimezone().isoformat()
    stderr_log_path = os.path.join(EVIDENCE_DIR, "server_errors.log")

    env_info = {
        "os": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "server": "Separate-process Werkzeug threaded WSGI server (127.0.0.1 ephemeral port, no shared client GIL)",
        "database": "SQLite 3 (temporary isolated file, default DELETE journal mode, unindexed tasks.user_id)",
        "seeded_users": NUM_BENCH_USERS,
        "tasks_per_user": TASKS_PER_USER,
        "seeded_tasks_total": NUM_BENCH_USERS * TASKS_PER_USER,
        "warmup_requests_per_endpoint": WARMUP_REQUESTS,
        "think_time_ms": 0,
        "concurrency_levels": CONCURRENCY_LEVELS,
        "executed_at": started_at,
    }

    rows = []
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "perf_test.db")
        with SubprocessAppServer(db_path, stderr_log_path) as srv:
            base_url = srv.base_url
            accounts = seed_multi_tenant_db(base_url, db_path)
            sessions = make_authed_sessions(base_url, accounts, max(CONCURRENCY_LEVELS))

            for ep, plan in WORKLOAD_PLAN.items():
                warmup_endpoint(base_url, ep, sessions[0])
                for conc, req_cnt in plan.items():
                    res = benchmark_stage(base_url, ep, conc, req_cnt, sessions)
                    rows.append(res)
                    print(
                        f"{ep:22s} | users={conc:2d} | req={res['total_requests']:3d} | "
                        f"mean={res['mean_ms']:7.2f}ms | p50={res['p50_ms']:7.2f}ms | p95={res['p95_ms']:7.2f}ms | "
                        f"rps={res['throughput_rps']:7.2f} | err={res['error_rate_pct']:5.2f}% {res['error_breakdown']}"
                    )

    sla_test_cases = evaluate_slas(rows)

    json_path = os.path.join(EVIDENCE_DIR, "performance_results.json")
    csv_path = os.path.join(EVIDENCE_DIR, "performance_results.csv")
    log_path = os.path.join(EVIDENCE_DIR, "performance_execution_log.txt")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"environment": env_info, "results": rows, "sla_test_cases": sla_test_cases}, f, indent=2)

    fieldnames = [
        "endpoint",
        "concurrency",
        "total_requests",
        "success_count",
        "error_count",
        "error_rate_pct",
        "wall_time_s",
        "throughput_rps",
        "min_ms",
        "mean_ms",
        "p50_ms",
        "p95_ms",
        "max_ms",
        "status_counts",
        "error_breakdown",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r[k] for k in fieldnames})

    rt_chart, tp_chart = generate_charts(rows)

    log_lines = [
        "PyTodo Pro — Week 5 Controlled Performance Test Log",
        f"Executed at: {started_at}",
        f"Environment: {env_info['os']} | Python {env_info['python_version']} | CPUs={env_info['cpu_count']}",
        f"Server Mode: {env_info['server']}",
        f"Seeded DB: {NUM_BENCH_USERS} users x {TASKS_PER_USER} tasks = {NUM_BENCH_USERS * TASKS_PER_USER} rows | Warmup={WARMUP_REQUESTS} reqs | Think time=0 ms",
        "-" * 115,
    ]
    for r in rows:
        log_lines.append(
            f"{r['endpoint']:22s} | users={r['concurrency']:2d} | req={r['total_requests']:3d} | "
            f"min={r['min_ms']:6.2f}ms mean={r['mean_ms']:7.2f}ms p50={r['p50_ms']:7.2f}ms "
            f"p95={r['p95_ms']:7.2f}ms max={r['max_ms']:7.2f}ms | rps={r['throughput_rps']:7.2f} | "
            f"err={r['error_rate_pct']:5.2f}% ({r['status_counts']})"
        )
        if r["error_samples"]:
            log_lines.append(f"   Error sample(s): {r['error_samples']}")
    log_lines.append("-" * 115)
    log_lines.append("SLA TEST CASE EVALUATIONS (TC-PERF-001 .. TC-PERF-006):")
    for tc in sla_test_cases:
        log_lines.append(f"[{tc['status'].upper():4s}] {tc['test_case_id']} | {tc['feature']} | Defect: {tc['defect_id']}")
        log_lines.append(f"       Actual: {tc['actual_result']}")
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")

    print(f"Charts saved: {rt_chart}, {tp_chart}")
    print(f"Server stderr log saved: {stderr_log_path}")
    return env_info, rows, sla_test_cases


if __name__ == "__main__":
    run_performance_experiment()
