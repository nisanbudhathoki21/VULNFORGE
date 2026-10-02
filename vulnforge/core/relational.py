"""Relational research-workspace extensions for the canonical VulnForge store.

The original store intentionally kept the scan report document as a compatibility
projection.  This module adds the normalized tables needed by the HTTP workbench
without replacing or rewriting that projection.  All functions are deliberately
SQLite-only and idempotent so they can run when an existing database is opened.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import urllib.parse
from typing import Any, Dict, Iterable, Optional

MIGRATION_ID = "007_research_workspace_relational"
MIGRATION_DESCRIPTION = "Projects, targets, normalized HTTP traffic, testing, evidence links, reports, and audit events"
MIGRATIONS = (
    ("001_initial", "Canonical SQLite scan and inventory tables"),
    ("002_http_traffic", "Normalized requests, responses, headers, cookies, and parameters"),
    ("003_testing", "Payloads, test runs, controls, and differential analysis"),
    ("004_evidence", "Evidence and direct traceability links"),
    ("005_findings", "Finding lifecycle and reporting projections"),
    ("006_authentication", "Projects, targets, scopes, authentication contexts, and sessions"),
    (MIGRATION_ID, MIGRATION_DESCRIPTION),
)


def _column_names(con: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in con.execute(f'PRAGMA table_info("{table}")').fetchall()}


def _add_column(con: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    if column not in _column_names(con, table):
        con.execute(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {definition}')


def ensure_relational_schema(con: sqlite3.Connection) -> None:
    """Apply the additive research-workspace migration to an open connection."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            migration_id TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS projects (
            project_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS targets (
            target_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
            canonical_url TEXT NOT NULL,
            scheme TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            created_at REAL NOT NULL,
            last_seen REAL NOT NULL,
            UNIQUE(project_id, canonical_url)
        );
        CREATE TABLE IF NOT EXISTS scopes (
            scope_id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
            confirmed INTEGER NOT NULL DEFAULT 0,
            policy_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            expires_at REAL
        );
        CREATE TABLE IF NOT EXISTS scan_runs (
            scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
            project_id TEXT REFERENCES projects(project_id) ON DELETE SET NULL,
            target_id TEXT REFERENCES targets(target_id) ON DELETE SET NULL,
            profile TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at REAL,
            finished_at REAL,
            statistics_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS scan_targets (
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            target_id TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
            scope_id TEXT REFERENCES scopes(scope_id) ON DELETE SET NULL,
            PRIMARY KEY(scan_id, target_id)
        );
        CREATE TABLE IF NOT EXISTS hosts (
            host_id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            hostname TEXT NOT NULL,
            ip_address TEXT,
            source TEXT NOT NULL DEFAULT 'observed',
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ports (
            port_id TEXT PRIMARY KEY,
            host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
            port INTEGER NOT NULL,
            scheme TEXT,
            service TEXT,
            source TEXT NOT NULL DEFAULT 'observed'
        );
        CREATE TABLE IF NOT EXISTS authentication_contexts (
            authentication_context_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            label TEXT NOT NULL,
            actor TEXT,
            redacted_headers_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            authentication_context_id TEXT NOT NULL REFERENCES authentication_contexts(authentication_context_id) ON DELETE CASCADE,
            label TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'configured',
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS requests (
            request_id TEXT PRIMARY KEY,
            exchange_id TEXT UNIQUE,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            project_id TEXT REFERENCES projects(project_id) ON DELETE SET NULL,
            target_id TEXT REFERENCES targets(target_id) ON DELETE SET NULL,
            endpoint_id TEXT,
            authentication_context_id TEXT REFERENCES authentication_contexts(authentication_context_id) ON DELETE SET NULL,
            method TEXT NOT NULL,
            scheme TEXT,
            host TEXT,
            port INTEGER,
            path TEXT,
            query TEXT,
            headers_json TEXT NOT NULL DEFAULT '{}',
            cookies_json TEXT NOT NULL DEFAULT '{}',
            body TEXT NOT NULL DEFAULT '',
            timestamp REAL NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            parent_request_id TEXT,
            raw_redacted TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_requests_scan_time ON requests(scan_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_requests_method_status ON requests(method);
        CREATE TABLE IF NOT EXISTS request_headers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL REFERENCES requests(request_id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS request_parameters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL REFERENCES requests(request_id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            location TEXT NOT NULL,
            value TEXT,
            redacted INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS responses (
            response_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL REFERENCES requests(request_id) ON DELETE CASCADE,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            status_code INTEGER,
            reason TEXT,
            headers_json TEXT NOT NULL DEFAULT '{}',
            cookies_json TEXT NOT NULL DEFAULT '{}',
            body TEXT NOT NULL DEFAULT '',
            body_hash TEXT,
            content_type TEXT,
            content_length INTEGER NOT NULL DEFAULT 0,
            response_time_ms REAL,
            timestamp REAL NOT NULL,
            server TEXT,
            redirect_location TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_responses_scan_time ON responses(scan_id, timestamp);
        CREATE TABLE IF NOT EXISTS response_headers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            response_id TEXT NOT NULL REFERENCES responses(response_id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS response_cookies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            response_id TEXT NOT NULL REFERENCES responses(response_id) ON DELETE CASCADE,
            cookie_name TEXT NOT NULL,
            cookie_value TEXT NOT NULL,
            attributes_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS payloads (
            payload_id TEXT PRIMARY KEY,
            test_id TEXT REFERENCES tests(test_id) ON DELETE SET NULL,
            parameter_id INTEGER REFERENCES parameters(id) ON DELETE SET NULL,
            endpoint_id TEXT,
            authentication_context_id TEXT REFERENCES authentication_contexts(authentication_context_id) ON DELETE SET NULL,
            payload TEXT NOT NULL,
            payload_type TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS test_runs (
            test_run_id TEXT PRIMARY KEY,
            test_id TEXT REFERENCES tests(test_id) ON DELETE CASCADE,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            baseline_request_id TEXT REFERENCES requests(request_id) ON DELETE SET NULL,
            baseline_response_id TEXT REFERENCES responses(response_id) ON DELETE SET NULL,
            test_request_id TEXT REFERENCES requests(request_id) ON DELETE SET NULL,
            test_response_id TEXT REFERENCES responses(response_id) ON DELETE SET NULL,
            control_request_id TEXT REFERENCES requests(request_id) ON DELETE SET NULL,
            control_response_id TEXT REFERENCES responses(response_id) ON DELETE SET NULL,
            status TEXT NOT NULL DEFAULT 'PLANNED',
            result_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS controls (
            control_id TEXT PRIMARY KEY,
            test_run_id TEXT REFERENCES test_runs(test_run_id) ON DELETE CASCADE,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            request_id TEXT REFERENCES requests(request_id) ON DELETE SET NULL,
            response_id TEXT REFERENCES responses(response_id) ON DELETE SET NULL,
            kind TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OBSERVED',
            data_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS diffs (
            diff_id TEXT PRIMARY KEY,
            test_run_id TEXT REFERENCES test_runs(test_run_id) ON DELETE CASCADE,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            baseline_response_id TEXT REFERENCES responses(response_id) ON DELETE SET NULL,
            test_response_id TEXT REFERENCES responses(response_id) ON DELETE SET NULL,
            control_response_id TEXT REFERENCES responses(response_id) ON DELETE SET NULL,
            status_difference TEXT,
            header_difference_json TEXT NOT NULL DEFAULT '{}',
            body_difference_json TEXT NOT NULL DEFAULT '{}',
            json_difference_json TEXT NOT NULL DEFAULT '{}',
            size_difference INTEGER,
            timing_difference REAL,
            authorization_difference TEXT,
            redirect_difference TEXT,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports (
            report_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            format TEXT NOT NULL,
            path TEXT,
            generated_at REAL NOT NULL,
            redacted INTEGER NOT NULL DEFAULT 1,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT REFERENCES scans(scan_id) ON DELETE SET NULL,
            timestamp REAL NOT NULL,
            actor TEXT NOT NULL DEFAULT 'local-user',
            action TEXT NOT NULL,
            object_type TEXT,
            object_id TEXT,
            result TEXT NOT NULL DEFAULT 'recorded',
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS tool_observations (
            tool_observation_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            tool_name TEXT NOT NULL,
            observed_at REAL NOT NULL,
            endpoint_id TEXT,
            status TEXT,
            output_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS browser_events (
            browser_event_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            timestamp REAL NOT NULL,
            url TEXT,
            data_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_audit_events_scan_time ON audit_events(scan_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_request_headers_request ON request_headers(request_id);
        CREATE INDEX IF NOT EXISTS idx_response_headers_response ON response_headers(response_id);
        """
    )
    # These columns turn the pre-existing inventory tables into a relational
    # compatibility surface without rewriting old rows.
    _add_column(con, "endpoints", "endpoint_id", "TEXT")
    _add_column(con, "endpoints", "target_id", "TEXT")
    _add_column(con, "endpoints", "authentication_context_id", "TEXT")
    _add_column(con, "endpoints", "state", "TEXT NOT NULL DEFAULT 'DISCOVERED'")
    _add_column(con, "endpoints", "state_reason", "TEXT NOT NULL DEFAULT ''")
    _add_column(con, "endpoints", "first_seen", "REAL")
    _add_column(con, "endpoints", "last_seen", "REAL")
    # Test-run columns make the evidence chain queryable without unpacking the
    # compatibility JSON document. They are additive for older workspaces.
    for column, definition in (
        ("pipeline_stage", "TEXT NOT NULL DEFAULT 'TEST PLANNING'"),
        ("pipeline_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("scope_decision", "TEXT NOT NULL DEFAULT ''"),
        ("endpoint", "TEXT NOT NULL DEFAULT ''"),
        ("method", "TEXT NOT NULL DEFAULT ''"),
        ("parameter", "TEXT NOT NULL DEFAULT ''"),
        ("hypothesis_id", "TEXT"),
        ("authentication_context_id", "TEXT"),
        ("confidence_rationale", "TEXT NOT NULL DEFAULT ''"),
    ):
        _add_column(con, "test_runs", column, definition)
    _add_column(con, "parameters", "parameter_id", "TEXT")
    _add_column(con, "parameters", "endpoint_id", "TEXT")
    _add_column(con, "parameters", "observed_values", "TEXT")
    _add_column(con, "parameters", "authentication_context_id", "TEXT")
    _add_column(con, "parameters", "first_seen", "REAL")
    _add_column(con, "parameters", "last_seen", "REAL")
    _add_column(con, "parameters", "test_count", "INTEGER NOT NULL DEFAULT 0")
    _add_column(con, "parameters", "finding_count", "INTEGER NOT NULL DEFAULT 0")
    _add_column(con, "evidence", "request_id", "TEXT")
    _add_column(con, "evidence", "response_id", "TEXT")
    _add_column(con, "evidence", "diff_id", "TEXT")
    # Backfill only from already persisted scan rows. This is a relational
    # index migration, not invented scan data: no HTTP requests or findings are
    # created here.
    now = time.time()
    con.execute("INSERT INTO projects(project_id,name,description,created_at,updated_at) VALUES (?,?,?,?,?) ON CONFLICT(project_id) DO NOTHING", ("project-default", "Default project", "Canonical VulnForge workspace", now, now))
    for row in con.execute("SELECT scan_id,target,profile,status,started_at,finished_at,stats_json,scope_json FROM scans").fetchall():
        scan_id, target, profile, status, started_at, finished_at, stats_json, scope_json = row
        parsed = urllib.parse.urlsplit(str(target or ""))
        target_id = stable_id("target", str(target or "").lower().rstrip("/"))
        scope_id = stable_id("scope", str(scan_id))
        con.execute("INSERT INTO targets(target_id,project_id,canonical_url,scheme,host,port,created_at,last_seen) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(target_id) DO NOTHING", (target_id, "project-default", str(target or ""), parsed.scheme or "", parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80), started_at or now, finished_at or started_at or now))
        con.execute("INSERT OR IGNORE INTO scopes(scope_id,target_id,confirmed,policy_json,created_at) VALUES (?,?,?,?,?)", (scope_id, target_id, 0, scope_json or "{}", started_at or now))
        con.execute("INSERT OR IGNORE INTO scan_targets(scan_id,target_id,scope_id) VALUES (?,?,?)", (scan_id, target_id, scope_id))
        con.execute("INSERT OR IGNORE INTO scan_runs(scan_id,project_id,target_id,profile,status,started_at,finished_at,statistics_json) VALUES (?,?,?,?,?,?,?,?)", (scan_id, "project-default", target_id, profile or "unknown", status or "unknown", started_at, finished_at, stats_json or "{}"))
        if parsed.hostname:
            host_id = stable_id("host", f"{scan_id}:{parsed.hostname}")
            host_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            con.execute("INSERT OR IGNORE INTO hosts(host_id,target_id,scan_id,hostname,ip_address,source,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)", (host_id, target_id, scan_id, parsed.hostname, None, "target", started_at or now, finished_at or started_at or now))
            con.execute("INSERT OR IGNORE INTO ports(port_id,host_id,port,scheme,service,source) VALUES (?,?,?,?,?,?)", (stable_id("port", f"{host_id}:{host_port}"), host_id, host_port, parsed.scheme, "https" if parsed.scheme == "https" else "http", "target"))
        endpoint_rows = con.execute("SELECT id,method,url,normalized,path,status,endpoint_id FROM endpoints WHERE scan_id=?", (scan_id,)).fetchall()
        for endpoint_row in endpoint_rows:
            endpoint_id = endpoint_row[6] or stable_id("endpoint", f"{scan_id}:{endpoint_row[1]}:{endpoint_row[3] or endpoint_row[2]}")
            state = "PARAMETERS_IDENTIFIED" if con.execute("SELECT 1 FROM parameters WHERE scan_id=? AND endpoint=? LIMIT 1", (scan_id, endpoint_row[2] or endpoint_row[4] or "")).fetchone() else ("REACHABLE" if int(endpoint_row[5] or 0) > 0 else "DISCOVERED")
            con.execute("UPDATE endpoints SET endpoint_id=?,target_id=?,state=COALESCE(NULLIF(state,''),?),first_seen=COALESCE(first_seen,?),last_seen=COALESCE(last_seen,?) WHERE id=?", (endpoint_id, target_id, state, started_at or now, finished_at or started_at or now, endpoint_row[0]))
        parameter_rows = con.execute("SELECT id,method,endpoint,name,parameter_id FROM parameters WHERE scan_id=?", (scan_id,)).fetchall()
        for parameter_row in parameter_rows:
            parameter_id = parameter_row[4] or stable_id("parameter", f"{scan_id}:{parameter_row[1]}:{parameter_row[2]}:{parameter_row[3]}")
            endpoint = con.execute("SELECT endpoint_id FROM endpoints WHERE scan_id=? AND method=? AND (normalized=? OR url=? OR path=?) ORDER BY id DESC LIMIT 1", (scan_id, parameter_row[1], parameter_row[2], parameter_row[2], parameter_row[2])).fetchone()
            con.execute("UPDATE parameters SET parameter_id=?,endpoint_id=?,first_seen=COALESCE(first_seen,?),last_seen=COALESCE(last_seen,?),observed_values=COALESCE(observed_values,?) WHERE id=?", (parameter_id, endpoint[0] if endpoint else None, started_at or now, finished_at or started_at or now, "[]", parameter_row[0]))
        legacy_tests = []
        for test_row in con.execute("SELECT data_json FROM tests WHERE scan_id=?", (scan_id,)).fetchall():
            try: legacy_tests.append(json.loads(test_row[0] or "{}"))
            except (ValueError, TypeError): pass
        if legacy_tests:
            link_test_records(con, scan_id, legacy_tests)


def migration_status(con: sqlite3.Connection) -> Dict[str, Any]:
    row = con.execute("SELECT migration_id, description, applied_at FROM schema_migrations WHERE migration_id=?", (MIGRATION_ID,)).fetchone()
    applied = [dict(item) for item in con.execute("SELECT migration_id,description,applied_at FROM schema_migrations ORDER BY migration_id").fetchall()]
    return {"migration_id": MIGRATION_ID, "description": MIGRATION_DESCRIPTION,
            "applied": bool(row), "applied_at": row[2] if row else None,
            "applied_migrations": applied, "pending": [item[0] for item in MIGRATIONS if not any(row["migration_id"] == item[0] for row in applied)]}


def record_migration(con: sqlite3.Connection) -> None:
    stamp = time.time()
    for migration_id, description in MIGRATIONS:
        con.execute("INSERT OR IGNORE INTO schema_migrations(migration_id,description,applied_at) VALUES (?,?,?)", (migration_id, description, stamp))


def stable_id(prefix: str, value: str, length: int = 18) -> str:
    return f"{prefix}-{hashlib.sha256(value.encode('utf-8', 'replace')).hexdigest()[:length]}"


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, default=str)


def _header_pairs(doc: Dict[str, Any], side: str) -> list[list[str]]:
    items = doc.get(f"{side}_header_items")
    if isinstance(items, list):
        return [[str(x[0]), str(x[1])] for x in items if isinstance(x, (list, tuple)) and len(x) >= 2]
    mapping = doc.get(f"{side}_headers") or {}
    return [[str(k), str(v)] for k, v in mapping.items()] if isinstance(mapping, dict) else []


def _cookies_from_headers(pairs: Iterable[list[str]], response: bool) -> Dict[str, str]:
    wanted = "set-cookie" if response else "cookie"
    result: Dict[str, str] = {}
    for name, value in pairs:
        if name.lower() != wanted:
            continue
        for piece in str(value).split(";" if response else ";"):
            if "=" in piece:
                key, val = piece.strip().split("=", 1)
                result[key.strip()] = val.strip()
    return result


def materialize_exchange(con: sqlite3.Connection, scan_id: str, doc: Dict[str, Any], *, project_id: str = "project-default", target_id: str = "") -> None:
    """Project one canonical exchange into normalized request/response rows."""
    exchange_id = str(doc.get("exchange_id") or "")
    request_id = str(doc.get("request_id") or f"{exchange_id}:request")
    response_id = str(doc.get("response_id") or f"{exchange_id}:response")
    parsed = urllib.parse.urlsplit(str(doc.get("url") or ""))
    request_pairs = _header_pairs(doc, "request")
    response_pairs = _header_pairs(doc, "response")
    request_cookies = _cookies_from_headers(request_pairs, False)
    response_cookies = _cookies_from_headers(response_pairs, True)
    timestamp = float(doc.get("timestamp") or time.time())
    raw_body = str(doc.get("request_body") or "")
    response_body = str(doc.get("response_body") or "")
    endpoint_id = doc.get("endpoint_id") or ""
    if not endpoint_id:
        match = con.execute("SELECT endpoint_id FROM endpoints WHERE scan_id=? AND method=? AND (url=? OR path=?) ORDER BY id DESC LIMIT 1", (scan_id, str(doc.get("method") or "GET"), str(doc.get("url") or ""), parsed.path or "/")).fetchone()
        endpoint_id = match[0] if match and match[0] else None
    con.execute(
        """INSERT INTO requests(request_id,exchange_id,scan_id,project_id,target_id,endpoint_id,authentication_context_id,method,scheme,host,port,path,query,headers_json,cookies_json,body,timestamp,source,parent_request_id,raw_redacted)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(request_id) DO UPDATE SET exchange_id=excluded.exchange_id, endpoint_id=excluded.endpoint_id, authentication_context_id=excluded.authentication_context_id,
             method=excluded.method,headers_json=excluded.headers_json,cookies_json=excluded.cookies_json,body=excluded.body,source=excluded.source""",
        (request_id, exchange_id or None, scan_id, project_id, target_id or None, endpoint_id, doc.get("authentication_context_id"),
         str(doc.get("method") or "GET"), parsed.scheme, parsed.hostname, parsed.port,
         parsed.path or "/", parsed.query, _json(dict(request_pairs)), _json(request_cookies), raw_body,
         timestamp, str(doc.get("module") or doc.get("source") or ""), doc.get("parent_request_id"), doc.get("raw_request")))
    con.execute("DELETE FROM request_headers WHERE request_id=?", (request_id,))
    for position, (name, value) in enumerate(request_pairs):
        con.execute("INSERT INTO request_headers(request_id,name,value,position) VALUES (?,?,?,?)", (request_id, name, value, position))
    con.execute("DELETE FROM request_parameters WHERE request_id=?", (request_id,))
    for name, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        con.execute("INSERT INTO request_parameters(request_id,name,location,value,redacted) VALUES (?,?,?,?,1)", (request_id, name, value, "query"))
    if response_id:
        content_type = next((v for k, v in response_pairs if k.lower() == "content-type"), "")
        server = next((v for k, v in response_pairs if k.lower() == "server"), "")
        location = next((v for k, v in response_pairs if k.lower() == "location"), "")
        con.execute(
            """INSERT INTO responses(response_id,request_id,scan_id,status_code,reason,headers_json,cookies_json,body,body_hash,content_type,content_length,response_time_ms,timestamp,server,redirect_location)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(response_id) DO UPDATE SET status_code=excluded.status_code,
               headers_json=excluded.headers_json,cookies_json=excluded.cookies_json,body=excluded.body,body_hash=excluded.body_hash,
               content_length=excluded.content_length,response_time_ms=excluded.response_time_ms""",
            (response_id, request_id, scan_id, doc.get("status") or 0, doc.get("reason_phrase") or "", _json(dict(response_pairs)), _json(response_cookies), response_body,
             hashlib.sha256(response_body.encode("utf-8", "replace")).hexdigest(), content_type,
             len(response_body.encode("utf-8", "replace")), float(doc.get("duration_ms") or 0), timestamp, server, location))
        con.execute("DELETE FROM response_headers WHERE response_id=?", (response_id,))
        for position, (name, value) in enumerate(response_pairs):
            con.execute("INSERT INTO response_headers(response_id,name,value,position) VALUES (?,?,?,?)", (response_id, name, value, position))
        con.execute("DELETE FROM response_cookies WHERE response_id=?", (response_id,))
        for name, value in response_cookies.items():
            con.execute("INSERT INTO response_cookies(response_id,cookie_name,cookie_value,attributes_json) VALUES (?,?,?,?)", (response_id, name, value, "{}"))


def link_test_records(con: sqlite3.Connection, scan_id: str, tests: Iterable[Dict[str, Any]]) -> None:
    """Materialize test, lifecycle, payload, control and exchange links."""
    from ..engine.test_pipeline import build_pipeline, current_stage
    for index, test in enumerate(tests):
        if not isinstance(test, dict):
            continue
        test_id = str(test.get("test_id") or f"test-{index + 1}")
        ids = {key: test.get(key) for key in ("baseline_exchange_id", "test_exchange_id", "cross_account_exchange_id", "repeat_exchange_id", "control_exchange_id", "negative_control_exchange_id")}
        request_ids: Dict[str, Optional[str]] = {}
        response_ids: Dict[str, Optional[str]] = {}
        for label, exchange_id in ids.items():
            if exchange_id:
                row = con.execute("SELECT request_id FROM requests WHERE exchange_id=?", (str(exchange_id),)).fetchone()
                if row:
                    request_ids[label] = row[0]
                    response = con.execute("SELECT response_id FROM responses WHERE request_id=?", (row[0],)).fetchone()
                    response_ids[label] = response[0] if response else None
        # Some verifiers store exchanges inside an observations list rather
        # than named baseline/control fields. Keep those exact links too.
        nested_exchange_ids = []
        def collect_exchange_ids(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if str(key).endswith("exchange_id") and child: nested_exchange_ids.append(str(child))
                    elif str(key) == "exchange_ids" and isinstance(child, list): nested_exchange_ids.extend(str(x) for x in child if x)
                    elif isinstance(child, (dict, list)): collect_exchange_ids(child)
            elif isinstance(value, list):
                for child in value: collect_exchange_ids(child)
        collect_exchange_ids(test)
        for exchange_id in dict.fromkeys(nested_exchange_ids):
            row = con.execute("SELECT request_id FROM requests WHERE exchange_id=?", (exchange_id,)).fetchone()
            if row and row[0] not in request_ids.values():
                request_ids.setdefault("observed_exchange_id", row[0])
                response = con.execute("SELECT response_id FROM responses WHERE request_id=?", (row[0],)).fetchone()
                response_ids.setdefault("observed_exchange_id", response[0] if response else None)
        test_run_id = stable_id("testrun", f"{scan_id}:{test_id}")
        pipeline = build_pipeline(test)
        con.execute(
            """INSERT INTO test_runs(test_run_id,test_id,scan_id,baseline_request_id,baseline_response_id,test_request_id,test_response_id,control_request_id,control_response_id,status,result_json,pipeline_stage,pipeline_json,scope_decision,endpoint,method,parameter,hypothesis_id,authentication_context_id,confidence_rationale)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(test_run_id) DO UPDATE SET status=excluded.status,result_json=excluded.result_json,
               baseline_request_id=excluded.baseline_request_id,baseline_response_id=excluded.baseline_response_id,test_request_id=excluded.test_request_id,test_response_id=excluded.test_response_id,
               control_request_id=excluded.control_request_id,control_response_id=excluded.control_response_id,pipeline_stage=excluded.pipeline_stage,pipeline_json=excluded.pipeline_json,
               scope_decision=excluded.scope_decision,endpoint=excluded.endpoint,method=excluded.method,parameter=excluded.parameter,hypothesis_id=excluded.hypothesis_id,authentication_context_id=excluded.authentication_context_id,confidence_rationale=excluded.confidence_rationale""",
            (test_run_id, test_id, scan_id, request_ids.get("baseline_exchange_id"), response_ids.get("baseline_exchange_id"),
             request_ids.get("test_exchange_id") or request_ids.get("cross_account_exchange_id") or request_ids.get("observed_exchange_id"), response_ids.get("test_exchange_id") or response_ids.get("cross_account_exchange_id") or response_ids.get("observed_exchange_id"),
             request_ids.get("control_exchange_id") or request_ids.get("negative_control_exchange_id"), response_ids.get("control_exchange_id") or response_ids.get("negative_control_exchange_id"),
             str(test.get("status") or "PLANNED"), _json(test), current_stage(test), _json(pipeline), str(test.get("scope_decision") or test.get("scope_status") or ("BLOCKED_BY_POLICY" if str(test.get("status") or "").upper() in {"BLOCKED", "SKIPPED"} else "ALLOWED_IN_SCOPE")),
             str(test.get("endpoint") or ""), str(test.get("method") or "GET"), str(test.get("parameter") or ""), test.get("hypothesis_id"), test.get("authentication_context_id") or test.get("auth_context_id"),
             str(test.get("confidence_rationale") or test.get("reason") or test.get("independent_verifier") or "")))
        payload_values = test.get("payloads") or test.get("payload")
        if isinstance(payload_values, str): payload_values = [payload_values]
        if isinstance(payload_values, list):
            for pindex, payload in enumerate(payload_values):
                if isinstance(payload, (dict, list)):
                    payload_text = json.dumps(payload, ensure_ascii=False, default=str)
                    payload_type = str(payload.get("type") if isinstance(payload, dict) else "test-payload")
                else:
                    payload_text = str(payload)
                    payload_type = str(test.get("type") or "test-payload")
                payload_id = stable_id("payload", f"{scan_id}:{test_id}:{pindex}:{payload_text}")
                con.execute("INSERT OR REPLACE INTO payloads(payload_id,test_id,endpoint_id, payload, payload_type,created_at) VALUES (?,?,?,?,?,?)", (payload_id, test_id, test.get("endpoint_id"), payload_text, payload_type, time.time()))
        for key, value in test.items():
            if "control" not in str(key).lower() or value in (None, "", [], {}):
                continue
            control_id = stable_id("control", f"{scan_id}:{test_id}:{key}")
            con.execute("INSERT OR REPLACE INTO controls(control_id,test_run_id,scan_id,request_id,response_id,kind,status,data_json) VALUES (?,?,?,?,?,?,?,?)", (control_id, test_run_id, scan_id, request_ids.get("control_exchange_id"), response_ids.get("control_exchange_id"), str(key), str(test.get("status") or "OBSERVED"), _json(value)))
        diff = test.get("differential") or test.get("diff")
        if diff is not None:
            diff_id = stable_id("diff", f"{scan_id}:{test_id}")
            con.execute("INSERT OR REPLACE INTO diffs(diff_id,test_run_id,scan_id,baseline_response_id,test_response_id,control_response_id,status_difference,body_difference_json,created_at) VALUES (?,?,?,?,?,?,?,?,?)", (diff_id, test_run_id, scan_id, response_ids.get("baseline_exchange_id"), response_ids.get("test_exchange_id") or response_ids.get("cross_account_exchange_id"), response_ids.get("control_exchange_id"), str((diff or {}).get("status") if isinstance(diff, dict) else ""), _json(diff), time.time()))


def record_audit_event(con: sqlite3.Connection, *, action: str, object_type: str = "", object_id: str = "", scan_id: str = "", actor: str = "local-user", result: str = "recorded", metadata: Any = None) -> int:
    cur = con.execute("INSERT INTO audit_events(scan_id,timestamp,actor,action,object_type,object_id,result,metadata_json) VALUES (?,?,?,?,?,?,?,?)", (scan_id or None, time.time(), actor, action, object_type or None, object_id or None, result, _json(metadata or {})))
    return int(cur.lastrowid)
