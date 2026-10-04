#!/usr/bin/env python3

"""
VulnForge Phase-1 research graph backfill.

Purpose:
    Materialize existing test_runs/result_json records into the Phase-1
    research graph.

Safety properties:
    - Does NOT create findings.
    - Does NOT change finding status.
    - Does NOT execute network requests.
    - Does NOT execute payloads.
    - Does NOT mutate target systems.
    - Uses one database transaction.
    - Rolls back everything if any record fails.
    - Verifies legacy finding/test counts before commit.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

# Allow execution from repository root.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnforge.core.relational import link_test_records


DB_PATH = ROOT / "data" / "vulnforge.db"


def json_load(value):
    if not value:
        return {}

    try:
        parsed = json.loads(value)
    except Exception:
        return {}

    return parsed if isinstance(parsed, dict) else {}


def snapshot(con):
    """Capture invariants that must not change during backfill."""

    test_count = con.execute(
        "SELECT COUNT(*) FROM test_runs"
    ).fetchone()[0]

    finding_count = con.execute(
        "SELECT COUNT(*) FROM findings"
    ).fetchone()[0]

    status_rows = con.execute(
        """
        SELECT COALESCE(status, ''), COUNT(*)
        FROM test_runs
        GROUP BY COALESCE(status, '')
        ORDER BY COALESCE(status, '')
        """
    ).fetchall()

    finding_status_rows = con.execute(
        """
        SELECT COALESCE(status, ''), COUNT(*)
        FROM findings
        GROUP BY COALESCE(status, '')
        ORDER BY COALESCE(status, '')
        """
    ).fetchall()

    return {
        "test_count": test_count,
        "finding_count": finding_count,
        "test_statuses": list(status_rows),
        "finding_statuses": list(finding_status_rows),
    }


def print_snapshot(label, snap):
    print(f"\n{label}")
    print("=" * 70)
    print(f"test_runs : {snap['test_count']}")
    print(f"findings  : {snap['finding_count']}")

    print("\nTest statuses:")
    for status, count in snap["test_statuses"]:
        print(f"  {status or '<empty>':20} {count}")

    print("\nFinding statuses:")
    for status, count in snap["finding_statuses"]:
        print(f"  {status or '<empty>':20} {count}")


def main():
    if not DB_PATH.exists():
        print(f"[ERROR] Database not found: {DB_PATH}")
        return 1

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row

    try:
        con.execute("PRAGMA foreign_keys=ON")

        before = snapshot(con)
        print_snapshot("BEFORE BACKFILL", before)

        rows = con.execute(
            """
            SELECT
                test_id,
                scan_id,
                status,
                result_json,
                pipeline_stage,
                scope_decision,
                endpoint,
                method,
                parameter,
                hypothesis_id,
                authentication_context_id
            FROM test_runs
            ORDER BY rowid
            """
        ).fetchall()

        print(f"\n[INFO] Tests selected for backfill: {len(rows)}")

        if not rows:
            print("[INFO] Nothing to backfill.")
            return 0

        # One transaction for the entire migration.
        con.execute("BEGIN")

        processed = 0

        for index, row in enumerate(rows, 1):
            result = json_load(row["result_json"])

            # Reconstruct the original test object while preserving
            # relational metadata that may not be inside result_json.
            test = dict(result)

            test.setdefault("test_id", row["test_id"])
            test.setdefault("scan_id", row["scan_id"])
            test.setdefault("status", row["status"])
            test.setdefault("pipeline_stage", row["pipeline_stage"])
            test.setdefault("scope_decision", row["scope_decision"])
            test.setdefault("endpoint", row["endpoint"])
            test.setdefault("method", row["method"])
            test.setdefault("parameter", row["parameter"])
            test.setdefault("hypothesis_id", row["hypothesis_id"])
            test.setdefault(
                "authentication_context_id",
                row["authentication_context_id"],
            )

            test_id = str(test.get("test_id") or f"unknown-{index}")

            print(
                f"[{index:02}/{len(rows):02}] "
                f"{test_id} "
                f"status={test.get('status')} "
                f"type={test.get('type')}"
            )

            # Process exactly one existing test.
            #
            # link_test_records() only materializes research records.
            # It does not perform HTTP requests and does not create findings.
            link_test_records(
                con,
                str(row["scan_id"]),
                [test],
            )

            processed += 1

        after = snapshot(con)

        # HARD SAFETY INVARIANTS BEFORE COMMIT
        if after["test_count"] != before["test_count"]:
            raise RuntimeError(
                "SAFETY FAILURE: test_runs count changed "
                f"{before['test_count']} -> {after['test_count']}"
            )

        if after["finding_count"] != before["finding_count"]:
            raise RuntimeError(
                "SAFETY FAILURE: findings count changed "
                f"{before['finding_count']} -> {after['finding_count']}"
            )

        if after["test_statuses"] != before["test_statuses"]:
            raise RuntimeError(
                "SAFETY FAILURE: test status distribution changed"
            )

        if after["finding_statuses"] != before["finding_statuses"]:
            raise RuntimeError(
                "SAFETY FAILURE: finding status distribution changed"
            )

        # Commit only after every invariant passes.
        con.commit()

        print("\n" + "=" * 70)
        print("[SUCCESS] Research graph backfill committed.")
        print("=" * 70)
        print(f"Processed tests: {processed}")
        print(f"test_runs      : {before['test_count']} -> {after['test_count']}")
        print(f"findings       : {before['finding_count']} -> {after['finding_count']}")

        return 0

    except Exception as exc:
        print("\n" + "=" * 70)
        print("[ROLLBACK] Backfill failed.")
        print("=" * 70)
        print(f"{type(exc).__name__}: {exc}")

        try:
            con.rollback()
        except Exception:
            pass

        print("[OK] Database transaction rolled back.")
        return 1

    finally:
        con.close()


if __name__ == "__main__":
    raise SystemExit(main())
