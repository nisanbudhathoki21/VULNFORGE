#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="./.venv/bin/python"
PYTEST="./.venv/bin/pytest"
VULNFORGE="./.venv/bin/vulnforge"

PASS=0
FAIL=0
SKIP=0

pass_check() {
    printf "  [PASS] %-58s\n" "$1"
    PASS=$((PASS + 1))
}

fail_check() {
    printf "  [FAIL] %-58s\n" "$1"
    FAIL=$((FAIL + 1))
}

skip_check() {
    printf "  [SKIP] %-58s\n" "$1"
    SKIP=$((SKIP + 1))
}

section() {
    echo
    echo "======================================================================"
    echo " $1"
    echo "======================================================================"
}

echo
echo "██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗"
echo "██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝"
echo "██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  "
echo "╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  "
echo " ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗"
echo "  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝"
echo
echo "              EVIDENCE-FIRST SECURITY ASSESSMENT PLATFORM"
echo

START_TIME=$(date +%s)

section "ENVIRONMENT"

echo "  Project       : $ROOT"
echo "  Python        : $($PYTHON --version 2>&1)"
echo "  Pytest        : $($PYTEST --version 2>&1 | head -1)"
echo "  VulnForge     : $($VULNFORGE --version 2>&1 || echo 'version command unavailable')"
echo "  Database      : ${VULNFORGE_SCAN_DB_PATH:-data/vulnforge.db}"
echo "  Git branch    : $(git branch --show-current 2>/dev/null || echo unknown)"
echo "  Git commit    : $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

section "SOURCE / MODULE INTEGRITY"

MODULES=(
    "vulnforge/engine/live.py"
    "vulnforge/engine/orchestrator.py"
    "vulnforge/engine/vulnerability_registry.py"
    "vulnforge/core/scan_status.py"
    "vulnforge/core/store.py"
    "vulnforge/cli.py"
    "vulnforge/dashboard.py"
)

for module in "${MODULES[@]}"; do
    if [ -f "$module" ]; then
        printf "  [PASS] %-58s\n" "$module"
        PASS=$((PASS + 1))
    else
        printf "  [FAIL] %-58s\n" "$module"
        FAIL=$((FAIL + 1))
    fi
done

section "PYTHON COMPILE VALIDATION"

if "$PYTHON" -m compileall -q vulnforge; then
    pass_check "Python source compilation"
else
    fail_check "Python source compilation"
fi

section "VULNERABILITY REGISTRY"

"$PYTHON" - <<'PY'
from vulnforge.engine.vulnerability_registry import VULNERABILITY_CLASSES

required = {
    "bola",
    "cors",
    "open_redirect",
    "sqli",
    "xss",
    "security_headers",
    "cookie_session",
}

missing = required - set(VULNERABILITY_CLASSES)

print(f"  Registered vulnerability classes : {len(VULNERABILITY_CLASSES)}")
print(f"  Required validation classes      : {len(required)}")

if missing:
    print(f"  Missing classes                  : {sorted(missing)}")
    raise SystemExit(1)

for name in sorted(required):
    item = VULNERABILITY_CLASSES[name]
    print(
        f"  {name:<22} "
        f"supported={item.get('supported')} "
        f"can_confirm={item.get('can_confirm')} "
        f"verification={item.get('verification_level')}"
    )
PY

if [ "$?" -eq 0 ]; then
    pass_check "Required vulnerability registry integrity"
else
    fail_check "Required vulnerability registry integrity"
fi

section "UNIT / INTEGRATION / REGRESSION TESTS"

echo
echo "  Running complete automated test suite..."
echo

TEST_START=$(date +%s)

"$PYTEST" -q

TEST_RC=$?

TEST_END=$(date +%s)
TEST_TIME=$((TEST_END - TEST_START))

echo
echo "  Test execution time : ${TEST_TIME}s"

if [ "$TEST_RC" -eq 0 ]; then
    pass_check "Complete automated test suite"
else
    fail_check "Complete automated test suite"
fi

section "LIVE STATE CLASSIFICATION"

"$PYTHON" - <<'PY'
from vulnforge.engine.live import classify_live_state

cases = [
    ("200 response", classify_live_state(200), "LIVE"),
    ("401 response", classify_live_state(401), "LIVE_AUTH_REQUIRED"),
    ("403 response", classify_live_state(403), "LIVE_FORBIDDEN"),
    ("429 response", classify_live_state(429), "LIVE_RATE_LIMITED"),
    ("500 response", classify_live_state(500), "LIVE_SERVER_ERROR"),
    ("connection refused", classify_live_state(
        0, "Connection refused"
    ), "DEAD"),
    ("connection failed", classify_live_state(
        0, "ConnectError: All connection attempts failed"
    ), "DEAD"),
    ("timeout", classify_live_state(
        0, "request timed out"
    ), "TIMEOUT"),
]

failed = False

for name, actual, expected in cases:
    status = "PASS" if actual == expected else "FAIL"
    print(f"  [{status}] {name:<30} -> {actual}")
    if actual != expected:
        failed = True

raise SystemExit(1 if failed else 0)
PY

if [ "$?" -eq 0 ]; then
    pass_check "Live-state classification and unreachable detection"
else
    fail_check "Live-state classification and unreachable detection"
fi

section "SCAN STATUS CLASSIFICATION"

"$PYTHON" - <<'PY'
from types import SimpleNamespace
from vulnforge.core.scan_status import (
    target_unreachable,
    scan_status,
    assessment_status,
    status_reason,
)

context = SimpleNamespace(
    stats=SimpleNamespace(
        pages_crawled=0,
        crawl_errors=1,
        crawl_timeouts=0,
    ),
    endpoints={},
    live_state_counts={"DEAD": 1},
    stop_reason="",
)

scan = SimpleNamespace(
    context=context,
    aborted=False,
)

print(f"  target_unreachable : {target_unreachable(context)}")
print(f"  scan_status        : {scan_status(scan)}")
print(f"  assessment_status  : {assessment_status(scan)}")
print(f"  reason             : {status_reason(context)}")

assert target_unreachable(context) is True
assert scan_status(scan) == "target_unreachable"
assert assessment_status(scan) == "not_assessed"
assert status_reason(context) == "Connection refused"
PY

if [ "$?" -eq 0 ]; then
    pass_check "Target unreachable → NOT ASSESSED classification"
else
    fail_check "Target unreachable → NOT ASSESSED classification"
fi

section "DATABASE INTEGRITY"

DB_PATH="${VULNFORGE_SCAN_DB_PATH:-data/vulnforge.db}"

if [ -f "$DB_PATH" ]; then
    echo "  Database file       : $DB_PATH"
    echo "  Database size       : $(du -h "$DB_PATH" | cut -f1)"

    "$PYTHON" - "$DB_PATH" <<'PY'
import sqlite3
import sys

db = sys.argv[1]

required = {
    "scans",
    "requests",
    "responses",
    "test_runs",
    "research_trace_links",
}

con = sqlite3.connect(db)

try:
    integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
    print(f"  SQLite integrity    : {integrity}")

    tables = {
        row[0]
        for row in con.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table'"
        )
    }

    print(f"  Tables detected     : {len(tables)}")

    for table in sorted(required):
        state = "PASS" if table in tables else "FAIL"
        print(f"  [{state}] table: {table}")

    if integrity != "ok":
        raise SystemExit(1)

    if not required.issubset(tables):
        raise SystemExit(1)

finally:
    con.close()
PY

    if [ "$?" -eq 0 ]; then
        pass_check "SQLite integrity and required schema"
    else
        fail_check "SQLite integrity and required schema"
    fi
else
    fail_check "Canonical database exists"
fi

section "UNREACHABLE TARGET HANDLING"

TMP_OUTPUT="$(mktemp)"

"$VULNFORGE" scan url http://127.0.0.1:59999 --full \
    >"$TMP_OUTPUT" 2>&1

UNREACHABLE_RC=$?

if grep -q "TARGET UNREACHABLE" "$TMP_OUTPUT" &&
   grep -q "NOT ASSESSED" "$TMP_OUTPUT" &&
   grep -q "Connection refused" "$TMP_OUTPUT"; then

    pass_check "Unreachable target classified without false finding"
else
    fail_check "Unreachable target classified without false finding"
    echo
    echo "  Actual output:"
    sed -n '1,120p' "$TMP_OUTPUT"
fi

rm -f "$TMP_OUTPUT"

section "LOCAL LAB / END-TO-END TEST"

if command -v ss >/dev/null 2>&1 &&
   ss -ltn 2>/dev/null | grep -q ':9002 '; then

    echo "  Local lab detected : 127.0.0.1:9002"
    echo "  Starting controlled end-to-end scan..."
    echo

    E2E_OUTPUT="$(mktemp)"

    "$VULNFORGE" scan url http://127.0.0.1:9002 --full \
        --verbose >"$E2E_OUTPUT" 2>&1

    E2E_RC=$?

    if [ "$E2E_RC" -eq 0 ]; then
        pass_check "Controlled local end-to-end security scan"

        echo
        echo "  ---- E2E SCAN SUMMARY ----"

        grep -E \
            "Scan ID|Endpoints|Parameters|Requests|Hypotheses|Tests|Confirmed|Unconfirmed|Skipped|Killed|Live state|VULNFORGE" \
            "$E2E_OUTPUT" | tail -40 || true

    else
        fail_check "Controlled local end-to-end security scan"

        echo
        echo "  ---- E2E FAILURE OUTPUT ----"
        tail -80 "$E2E_OUTPUT"
    fi

    rm -f "$E2E_OUTPUT"

else
    skip_check "Controlled local E2E scan — local lab 127.0.0.1:9002 not running"
fi

section "DASHBOARD MODULE"

"$PYTHON" - <<'PY'
import importlib

modules = [
    "vulnforge.dashboard",
]

failed = False

for name in modules:
    try:
        importlib.import_module(name)
        print(f"  [PASS] import {name}")
    except Exception as exc:
        print(f"  [FAIL] import {name}: {exc}")
        failed = True

raise SystemExit(1 if failed else 0)
PY

if [ "$?" -eq 0 ]; then
    pass_check "Dashboard module import"
else
    fail_check "Dashboard module import"
fi

section "EVIDENCE-FIRST PIPELINE"

PIPELINE=(
    "OBSERVATION"
    "HYPOTHESIS"
    "TESTING"
    "CONTROL"
    "DIFFERENTIAL"
    "REPRODUCTION"
    "IMPACT"
    "FINAL CLASSIFICATION"
)

for ((i=0; i<${#PIPELINE[@]}; i++)); do
    if [ "$i" -lt $((${#PIPELINE[@]} - 1)) ]; then
        echo "  ${PIPELINE[$i]}"
        echo "       │"
        echo "       ▼"
    else
        echo "  ${PIPELINE[$i]}"
    fi
done

echo
echo "  Evidence policy:"
echo "    • Observation alone does not create a confirmed finding"
echo "    • Controlled tests provide verification evidence"
echo "    • Differential comparison reduces false positives"
echo "    • Reproduction establishes repeatability"
echo "    • Impact is recorded only after verification"
echo "    • Unreachable targets are NOT ASSESSED"

section "FINAL VALIDATION SUMMARY"

END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo
printf "  %-38s %6s\n" "PASS" "$PASS"
printf "  %-38s %6s\n" "FAIL" "$FAIL"
printf "  %-38s %6s\n" "SKIPPED" "$SKIP"
printf "  %-38s %6ss\n" "TOTAL EXECUTION TIME" "$TOTAL_TIME"

echo

if [ "$FAIL" -eq 0 ]; then
    if [ "$SKIP" -eq 0 ]; then
        echo "  ┌────────────────────────────────────────────────────────────┐"
        echo "  │                 VULNFORGE VALIDATION PASS                 │"
        echo "  │                                                            │"
        echo "  │  Unit tests        : PASS                                 │"
        echo "  │  Integration       : PASS                                 │"
        echo "  │  Regression        : PASS                                 │"
        echo "  │  Database          : PASS                                 │"
        echo "  │  Error handling    : PASS                                 │"
        echo "  │  Local E2E         : PASS                                 │"
        echo "  │  Dashboard module  : PASS                                 │"
        echo "  └────────────────────────────────────────────────────────────┘"
    else
        echo "  ┌────────────────────────────────────────────────────────────┐"
        echo "  │          VULNFORGE CORE VALIDATION PASS / E2E SKIPPED     │"
        echo "  │                                                            │"
        echo "  │  No validation checks failed.                             │"
        echo "  │  Start the local lab on 127.0.0.1:9002 to run E2E.       │"
        echo "  └────────────────────────────────────────────────────────────┘"
    fi
else
    echo "  ┌────────────────────────────────────────────────────────────┐"
    echo "  │                 VULNFORGE VALIDATION FAIL                 │"
    echo "  │                                                            │"
    echo "  │  One or more validation checks failed.                    │"
    echo "  │  Review the failure output above.                         │"
    echo "  └────────────────────────────────────────────────────────────┘"
fi

echo

exit "$FAIL"
