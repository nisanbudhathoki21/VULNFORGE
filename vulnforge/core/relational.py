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

    ensure_phase1_research_schema(con)

def ensure_phase1_research_schema(con: sqlite3.Connection) -> None:
    """
    Advanced Phase-1 security research workspace.

    The database deliberately separates:

        observation
            -> hypothesis
            -> test plan
            -> execution
            -> evidence
            -> verification
            -> finding

    External scanner output is stored as observation/provenance only.
    Nothing in this schema automatically creates a vulnerability finding.
    """

    con.executescript(
        """
        ------------------------------------------------------------------
        -- 1. SECURITY OBSERVATIONS
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS observations (
            observation_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            asset_id TEXT,
            endpoint_id TEXT,
            exchange_id TEXT,
            actor_id TEXT,
            kind TEXT NOT NULL,
            source TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            value_json TEXT NOT NULL DEFAULT '{}',
            severity_hint TEXT NOT NULL DEFAULT 'info',
            confidence REAL NOT NULL DEFAULT 0.0,
            scope_status TEXT NOT NULL DEFAULT 'UNKNOWN',
            observed_at REAL NOT NULL,
            provenance_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_observations_scan
            ON observations(scan_id);

        CREATE INDEX IF NOT EXISTS idx_observations_endpoint
            ON observations(endpoint_id);

        CREATE INDEX IF NOT EXISTS idx_observations_exchange
            ON observations(exchange_id);

        CREATE INDEX IF NOT EXISTS idx_observations_kind
            ON observations(kind);


        ------------------------------------------------------------------
        -- 2. HYPOTHESES
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS research_hypotheses (
            hypothesis_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            observation_id TEXT,
            endpoint_id TEXT,
            actor_id TEXT,
            resource_id TEXT,
            category TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            statement TEXT NOT NULL,
            rationale TEXT NOT NULL DEFAULT '',
            security_property TEXT NOT NULL DEFAULT '',
            expected_boundary TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'OPEN',
            priority TEXT NOT NULL DEFAULT 'NORMAL',
            confidence REAL NOT NULL DEFAULT 0.0,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            provenance_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_research_hypotheses_scan
            ON research_hypotheses(scan_id);

        CREATE INDEX IF NOT EXISTS idx_research_hypotheses_endpoint
            ON research_hypotheses(endpoint_id);

        CREATE INDEX IF NOT EXISTS idx_research_hypotheses_status
            ON research_hypotheses(status);


        ------------------------------------------------------------------
        -- 3. TEST PLANS
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS research_test_plans (
            test_plan_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            hypothesis_id TEXT,
            endpoint_id TEXT,
            actor_id TEXT,
            authentication_context_id TEXT,
            name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL DEFAULT 'GET',
            parameter TEXT NOT NULL DEFAULT '',
            strategy_json TEXT NOT NULL DEFAULT '{}',
            prerequisites_json TEXT NOT NULL DEFAULT '{}',
            authorization_required INTEGER NOT NULL DEFAULT 1,
            destructive INTEGER NOT NULL DEFAULT 0,
            estimated_requests INTEGER NOT NULL DEFAULT 0,
            risk TEXT NOT NULL DEFAULT 'LOW',
            status TEXT NOT NULL DEFAULT 'PLANNED',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            provenance_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_research_test_plans_scan
            ON research_test_plans(scan_id);

        CREATE INDEX IF NOT EXISTS idx_research_test_plans_hypothesis
            ON research_test_plans(hypothesis_id);


        ------------------------------------------------------------------
        -- 4. INDIVIDUAL TEST STEPS
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS research_test_steps (
            step_id TEXT PRIMARY KEY,
            test_plan_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            sequence_no INTEGER NOT NULL,
            stage TEXT NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PLANNED',
            request_id TEXT,
            response_id TEXT,
            payload_id TEXT,
            control_id TEXT,
            diff_id TEXT,
            assertion_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT NOT NULL DEFAULT '{}',
            started_at REAL,
            finished_at REAL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_research_test_steps_plan
            ON research_test_steps(test_plan_id);

        CREATE INDEX IF NOT EXISTS idx_research_test_steps_scan
            ON research_test_steps(scan_id);

        CREATE UNIQUE INDEX IF NOT EXISTS idx_research_test_steps_sequence
            ON research_test_steps(test_plan_id, sequence_no);


        ------------------------------------------------------------------
        -- 5. REQUEST MUTATIONS / PAYLOAD APPLICATIONS
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS research_mutations (
            mutation_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            test_plan_id TEXT,
            test_id TEXT,
            parameter TEXT NOT NULL DEFAULT '',
            location TEXT NOT NULL DEFAULT '',
            original_value TEXT NOT NULL DEFAULT '',
            mutated_value TEXT NOT NULL DEFAULT '',
            mutation_type TEXT NOT NULL DEFAULT '',
            rationale TEXT NOT NULL DEFAULT '',
            payload_id TEXT,
            request_id TEXT,
            status TEXT NOT NULL DEFAULT 'PLANNED',
            created_at REAL NOT NULL,
            provenance_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_research_mutations_scan
            ON research_mutations(scan_id);

        CREATE INDEX IF NOT EXISTS idx_research_mutations_test
            ON research_mutations(test_id);


        ------------------------------------------------------------------
        -- 6. BASELINE SNAPSHOTS
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS research_baselines (
            baseline_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            test_id TEXT,
            request_id TEXT,
            response_id TEXT,
            endpoint_id TEXT,
            actor_id TEXT,
            fingerprint TEXT NOT NULL DEFAULT '',
            status_code INTEGER,
            body_hash TEXT,
            semantic_json TEXT NOT NULL DEFAULT '{}',
            headers_json TEXT NOT NULL DEFAULT '{}',
            timing_json TEXT NOT NULL DEFAULT '{}',
            established_at REAL NOT NULL,
            validity TEXT NOT NULL DEFAULT 'VALID',
            invalid_reason TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_research_baselines_test
            ON research_baselines(test_id);

        CREATE INDEX IF NOT EXISTS idx_research_baselines_endpoint
            ON research_baselines(endpoint_id);


        ------------------------------------------------------------------
        -- 7. EXPLICIT SECURITY CONTROLS
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS research_controls (
            research_control_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            test_id TEXT,
            type TEXT NOT NULL,
            purpose TEXT NOT NULL DEFAULT '',
            request_id TEXT,
            response_id TEXT,
            expected_json TEXT NOT NULL DEFAULT '{}',
            observed_json TEXT NOT NULL DEFAULT '{}',
            passed INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'NOT_RUN',
            rationale TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_research_controls_scan
            ON research_controls(scan_id);

        CREATE INDEX IF NOT EXISTS idx_research_controls_test
            ON research_controls(test_id);


        ------------------------------------------------------------------
        -- 8. SEMANTIC DIFFERENTIAL ANALYSIS
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS research_differentials (
            differential_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            test_id TEXT,
            baseline_response_id TEXT,
            control_response_id TEXT,
            mutated_response_id TEXT,
            comparison_type TEXT NOT NULL DEFAULT 'SEMANTIC',
            status TEXT NOT NULL DEFAULT 'ANALYZED',
            status_code_changed INTEGER NOT NULL DEFAULT 0,
            headers_changed INTEGER NOT NULL DEFAULT 0,
            body_changed INTEGER NOT NULL DEFAULT 0,
            semantic_changed INTEGER NOT NULL DEFAULT 0,
            authorization_boundary_changed INTEGER NOT NULL DEFAULT 0,
            meaningful INTEGER NOT NULL DEFAULT 0,
            summary TEXT NOT NULL DEFAULT '',
            diff_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_research_differentials_scan
            ON research_differentials(scan_id);

        CREATE INDEX IF NOT EXISTS idx_research_differentials_test
            ON research_differentials(test_id);


        ------------------------------------------------------------------
        -- 9. REPRODUCTION ATTEMPTS
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS reproductions (
            reproduction_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            test_id TEXT,
            attempt_no INTEGER NOT NULL DEFAULT 1,
            request_id TEXT,
            response_id TEXT,
            expected_json TEXT NOT NULL DEFAULT '{}',
            observed_json TEXT NOT NULL DEFAULT '{}',
            matched INTEGER NOT NULL DEFAULT 0,
            stability_score REAL NOT NULL DEFAULT 0.0,
            status TEXT NOT NULL DEFAULT 'NOT_RUN',
            created_at REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_reproductions_scan
            ON reproductions(scan_id);

        CREATE INDEX IF NOT EXISTS idx_reproductions_test
            ON reproductions(test_id);


        ------------------------------------------------------------------
        -- 10. IMPACT VALIDATION CONTRACTS
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS impact_validations (
            impact_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            test_id TEXT,
            contract_type TEXT NOT NULL DEFAULT '',
            security_boundary TEXT NOT NULL DEFAULT '',
            protected_resource TEXT NOT NULL DEFAULT '',
            affected_actor TEXT NOT NULL DEFAULT '',
            impact_class TEXT NOT NULL DEFAULT '',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            proven INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'NOT_PROVEN',
            rationale TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_impact_validations_scan
            ON impact_validations(scan_id);

        CREATE INDEX IF NOT EXISTS idx_impact_validations_test
            ON impact_validations(test_id);


        ------------------------------------------------------------------
        -- 11. EVIDENCE GRAPH
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS evidence_graph (
            evidence_node_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            node_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_evidence_graph_scan
            ON evidence_graph(scan_id);

        CREATE INDEX IF NOT EXISTS idx_evidence_graph_object
            ON evidence_graph(object_id);


        CREATE TABLE IF NOT EXISTS evidence_edges (
            edge_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            source_node_id TEXT NOT NULL,
            target_node_id TEXT NOT NULL,
            relation TEXT NOT NULL,
            rationale TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_evidence_edges_scan
            ON evidence_edges(scan_id);

        CREATE INDEX IF NOT EXISTS idx_evidence_edges_source
            ON evidence_edges(source_node_id);

        CREATE INDEX IF NOT EXISTS idx_evidence_edges_target
            ON evidence_edges(target_node_id);


        ------------------------------------------------------------------
        -- 12. RESEARCHER DECISIONS
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS research_decisions (
            decision_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            next_action TEXT NOT NULL DEFAULT '',
            researcher TEXT NOT NULL DEFAULT 'local-user',
            created_at REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_research_decisions_scan
            ON research_decisions(scan_id);

        CREATE INDEX IF NOT EXISTS idx_research_decisions_object
            ON research_decisions(object_type, object_id);


        ------------------------------------------------------------------
        -- 13. ATTACK-PATH GRAPH
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS attack_path_nodes (
            path_node_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            path_id TEXT NOT NULL,
            node_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 0,
            label TEXT NOT NULL DEFAULT '',
            verified INTEGER NOT NULL DEFAULT 0,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_attack_path_nodes_scan
            ON attack_path_nodes(scan_id);

        CREATE INDEX IF NOT EXISTS idx_attack_path_nodes_path
            ON attack_path_nodes(path_id);


        CREATE TABLE IF NOT EXISTS attack_path_edges (
            path_edge_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            path_id TEXT NOT NULL,
            source_node_id TEXT NOT NULL,
            target_node_id TEXT NOT NULL,
            relation TEXT NOT NULL,
            verified INTEGER NOT NULL DEFAULT 0,
            rationale TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_attack_path_edges_scan
            ON attack_path_edges(scan_id);

        CREATE INDEX IF NOT EXISTS idx_attack_path_edges_path
            ON attack_path_edges(path_id);


        ------------------------------------------------------------------
        -- 14. EXTERNAL TOOL OBSERVATIONS
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS research_tool_observations (
            observation_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            tool TEXT NOT NULL,
            tool_version TEXT NOT NULL DEFAULT '',
            command_fingerprint TEXT NOT NULL DEFAULT '',
            target TEXT NOT NULL DEFAULT '',
            output_type TEXT NOT NULL DEFAULT '',
            observation_json TEXT NOT NULL DEFAULT '{}',
            raw_output_hash TEXT NOT NULL DEFAULT '',
            scope_status TEXT NOT NULL DEFAULT 'UNKNOWN',
            created_at REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_research_tool_observations_scan
            ON research_tool_observations(scan_id);

        CREATE INDEX IF NOT EXISTS idx_research_tool_observations_tool
            ON research_tool_observations(tool);


        ------------------------------------------------------------------
        -- 15. PROVENANCE
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS research_provenance (
            provenance_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_id TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL DEFAULT 'local-user',
            created_at REAL NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_research_provenance_scan
            ON research_provenance(scan_id);

        CREATE INDEX IF NOT EXISTS idx_research_provenance_object
            ON research_provenance(object_type, object_id);


        ------------------------------------------------------------------
        -- 16. RESEARCH NOTES
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS research_notes (
            note_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            note_type TEXT NOT NULL DEFAULT 'NOTE',
            content TEXT NOT NULL,
            author TEXT NOT NULL DEFAULT 'local-user',
            created_at REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_research_notes_scan
            ON research_notes(scan_id);

        CREATE INDEX IF NOT EXISTS idx_research_notes_object
            ON research_notes(object_type, object_id);


        ------------------------------------------------------------------
        -- 17. RETEST / REMEDIATION VALIDATION
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS retest_runs (
            retest_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            original_test_id TEXT,
            original_finding_id TEXT,
            endpoint_id TEXT,
            request_id TEXT,
            response_id TEXT,
            previous_status TEXT NOT NULL DEFAULT '',
            current_status TEXT NOT NULL DEFAULT '',
            regression_detected INTEGER NOT NULL DEFAULT 0,
            evidence_json TEXT NOT NULL DEFAULT '{}',
            notes TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_retest_runs_scan
            ON retest_runs(scan_id);

        CREATE INDEX IF NOT EXISTS idx_retest_runs_test
            ON retest_runs(original_test_id);

        CREATE INDEX IF NOT EXISTS idx_retest_runs_finding
            ON retest_runs(original_finding_id);


        ------------------------------------------------------------------
        -- 18. REQUEST/RESPONSE TRACE INDEX
        --
        -- Gives the dashboard a single relationship layer for:
        -- request -> response -> test -> evidence -> finding.
        ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS research_trace_links (
            trace_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            request_id TEXT,
            response_id TEXT,
            exchange_id TEXT,
            test_id TEXT,
            hypothesis_id TEXT,
            evidence_id TEXT,
            finding_id TEXT,
            relation TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_research_trace_scan
            ON research_trace_links(scan_id);

        CREATE INDEX IF NOT EXISTS idx_research_trace_test
            ON research_trace_links(test_id);

        CREATE INDEX IF NOT EXISTS idx_research_trace_exchange
            ON research_trace_links(exchange_id);

        CREATE INDEX IF NOT EXISTS idx_research_trace_finding
            ON research_trace_links(finding_id);
        """
    )


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
    """
    Materialize test records into both the legacy compatibility model and
    the Phase-1 research workspace.

    The legacy tables remain authoritative for backwards compatibility.
    The research tables provide the normalized evidence/research graph:

        observation
          -> hypothesis
          -> test plan
          -> test steps
          -> mutations
          -> baseline/control
          -> differential
          -> reproduction
          -> impact validation
          -> decision
          -> trace links

    This function deliberately does NOT promote a test to a finding.
    Verification remains the responsibility of the central verification gate.
    """
    from ..engine.test_pipeline import build_pipeline, current_stage

    now = time.time()

    def _table_columns(table: str) -> set[str]:
        rows = con.execute(f"PRAGMA table_info({table})").fetchall()
        return {str(row[1]) for row in rows}

    def _safe_json(value: Any) -> str:
        return _json(value if value is not None else {})

    def _upsert(table: str, values: Dict[str, Any], key: str) -> Optional[str]:
        """
        Insert/update a research row while tolerating schema evolution.

        Only columns actually present in the current database are written.
        This keeps the persistence layer compatible with older Phase-1 DBs.
        """
        columns = _table_columns(table)
        if not columns:
            return None

        # Every Phase-1 research artifact must remain explicitly
        # traceable to the originating test. Derived mapper records
        # may omit test_id, so propagate the current test_id whenever
        # the destination schema supports it.
        values = dict(values)
        if (
            "test_id" in columns
            and "test_id" not in values
            and test_id
        ):
            values["test_id"] = test_id

        data = {
            k: v
            for k, v in values.items()
            if k in columns and v is not None
        }

        if key in columns and key not in data:
            return None

        # Fill NOT NULL columns that have no SQLite default.
        info = con.execute(f"PRAGMA table_info({table})").fetchall()
        existing = set(data)

        for row in info:
            name = str(row[1])
            notnull = bool(row[3])
            default = row[4]
            pk = bool(row[5])

            if not notnull or name in existing or default is not None or pk:
                continue

            col_type = str(row[2] or "").upper()

            if name.endswith("_at") or name in {
                "created_at",
                "updated_at",
                "observed_at",
                "established_at",
                "started_at",
                "finished_at",
            }:
                data[name] = now
            elif "INT" in col_type:
                data[name] = 0
            elif any(token in col_type for token in ("REAL", "FLOAT", "DOUBLE")):
                data[name] = 0.0
            else:
                data[name] = ""

        if not data:
            return None

        names = list(data)
        placeholders = ",".join("?" for _ in names)
        columns_sql = ",".join(names)

        # Prefer UPDATE+INSERT over INSERT OR REPLACE so that replacing a
        # research node cannot unexpectedly cascade-delete linked records.
        if key in data:
            existing_row = con.execute(
                f"SELECT 1 FROM {table} WHERE {key}=? LIMIT 1",
                (data[key],),
            ).fetchone()

            if existing_row:
                update_names = [n for n in names if n != key]
                if update_names:
                    assignments = ",".join(f"{n}=?" for n in update_names)
                    con.execute(
                        f"UPDATE {table} SET {assignments} WHERE {key}=?",
                        tuple(data[n] for n in update_names) + (data[key],),
                    )
                return str(data[key])

        con.execute(
            f"INSERT INTO {table} ({columns_sql}) VALUES ({placeholders})",
            tuple(data[n] for n in names),
        )
        return str(data[key]) if key in data else None

    def _lookup_exchange(exchange_id: Any) -> tuple[Optional[str], Optional[str]]:
        if not exchange_id:
            return None, None

        row = con.execute(
            "SELECT request_id FROM requests WHERE exchange_id=?",
            (str(exchange_id),),
        ).fetchone()

        if not row:
            return None, None

        request_id = str(row[0])
        response = con.execute(
            "SELECT response_id FROM responses WHERE request_id=?",
            (request_id,),
        ).fetchone()

        return request_id, str(response[0]) if response else None

    def _collect_exchange_ids(value: Any, output: list[str]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_s = str(key)

                if key_s.endswith("exchange_id") and child:
                    output.append(str(child))

                elif key_s == "exchange_ids" and isinstance(child, list):
                    output.extend(str(x) for x in child if x)

                elif isinstance(child, (dict, list)):
                    _collect_exchange_ids(child, output)

        elif isinstance(value, list):
            for child in value:
                _collect_exchange_ids(child, output)

    def _as_list(value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _extract_text(value: Any, default: str = "") -> str:
        if value is None:
            return default
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False, default=str)
        return str(value)

    for index, test in enumerate(tests):
        if not isinstance(test, dict):
            continue

        test_id = str(test.get("test_id") or f"test-{index + 1}")
        test_run_id = stable_id("testrun", f"{scan_id}:{test_id}")

        # --------------------------------------------------------------
        # Exchange resolution
        # --------------------------------------------------------------

        named_exchange_ids = {
            key: test.get(key)
            for key in (
                "baseline_exchange_id",
                "test_exchange_id",
                "cross_account_exchange_id",
                "repeat_exchange_id",
                "control_exchange_id",
                "negative_control_exchange_id",
            )
        }

        request_ids: Dict[str, Optional[str]] = {}
        response_ids: Dict[str, Optional[str]] = {}

        for label, exchange_id in named_exchange_ids.items():
            req_id, resp_id = _lookup_exchange(exchange_id)

            if req_id:
                request_ids[label] = req_id
                response_ids[label] = resp_id

        nested_exchange_ids: list[str] = []
        _collect_exchange_ids(test, nested_exchange_ids)

        for exchange_id in dict.fromkeys(nested_exchange_ids):
            req_id, resp_id = _lookup_exchange(exchange_id)

            if req_id and req_id not in request_ids.values():
                request_ids.setdefault("observed_exchange_id", req_id)
                response_ids.setdefault("observed_exchange_id", resp_id)

        # --------------------------------------------------------------
        # Existing compatibility persistence
        # --------------------------------------------------------------

        pipeline = build_pipeline(test)

        scope_decision = str(
            test.get("scope_decision")
            or test.get("scope_status")
            or (
                "BLOCKED_BY_POLICY"
                if str(test.get("status") or "").upper() in {"BLOCKED", "SKIPPED"}
                else "ALLOWED_IN_SCOPE"
            )
        )

        endpoint = str(test.get("endpoint") or "")
        method = str(test.get("method") or "GET").upper()
        parameter = str(test.get("parameter") or "")
        auth_context_id = (
            test.get("authentication_context_id")
            or test.get("auth_context_id")
        )

        con.execute(
            """INSERT INTO test_runs(
                test_run_id,
                test_id,
                scan_id,
                baseline_request_id,
                baseline_response_id,
                test_request_id,
                test_response_id,
                control_request_id,
                control_response_id,
                status,
                result_json,
                pipeline_stage,
                pipeline_json,
                scope_decision,
                endpoint,
                method,
                parameter,
                hypothesis_id,
                authentication_context_id,
                confidence_rationale
            )
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(test_run_id) DO UPDATE SET
                status=excluded.status,
                result_json=excluded.result_json,
                baseline_request_id=excluded.baseline_request_id,
                baseline_response_id=excluded.baseline_response_id,
                test_request_id=excluded.test_request_id,
                test_response_id=excluded.test_response_id,
                control_request_id=excluded.control_request_id,
                control_response_id=excluded.control_response_id,
                pipeline_stage=excluded.pipeline_stage,
                pipeline_json=excluded.pipeline_json,
                scope_decision=excluded.scope_decision,
                endpoint=excluded.endpoint,
                method=excluded.method,
                parameter=excluded.parameter,
                hypothesis_id=excluded.hypothesis_id,
                authentication_context_id=excluded.authentication_context_id,
                confidence_rationale=excluded.confidence_rationale""",
            (
                test_run_id,
                test_id,
                scan_id,
                request_ids.get("baseline_exchange_id"),
                response_ids.get("baseline_exchange_id"),
                request_ids.get("test_exchange_id")
                or request_ids.get("cross_account_exchange_id")
                or request_ids.get("observed_exchange_id"),
                response_ids.get("test_exchange_id")
                or response_ids.get("cross_account_exchange_id")
                or response_ids.get("observed_exchange_id"),
                request_ids.get("control_exchange_id")
                or request_ids.get("negative_control_exchange_id"),
                response_ids.get("control_exchange_id")
                or response_ids.get("negative_control_exchange_id"),
                str(test.get("status") or "PLANNED"),
                _json(test),
                current_stage(test),
                _json(pipeline),
                scope_decision,
                endpoint,
                method,
                parameter,
                test.get("hypothesis_id"),
                auth_context_id,
                str(
                    test.get("confidence_rationale")
                    or test.get("reason")
                    or test.get("independent_verifier")
                    or ""
                ),
            ),
        )

        # --------------------------------------------------------------
        # Payloads
        # --------------------------------------------------------------

        payload_values = test.get("payloads") or test.get("payload")
        if isinstance(payload_values, str):
            payload_values = [payload_values]

        payload_ids: list[str] = []

        if isinstance(payload_values, list):
            for pindex, payload in enumerate(payload_values):
                if isinstance(payload, (dict, list)):
                    payload_text = json.dumps(
                        payload,
                        ensure_ascii=False,
                        default=str,
                    )
                    payload_type = str(
                        payload.get("type")
                        if isinstance(payload, dict)
                        else "test-payload"
                    )
                else:
                    payload_text = str(payload)
                    payload_type = str(
                        test.get("type") or "test-payload"
                    )

                payload_id = stable_id(
                    "payload",
                    f"{scan_id}:{test_id}:{pindex}:{payload_text}",
                )
                payload_ids.append(payload_id)

                con.execute(
                    """INSERT OR REPLACE INTO payloads(
                        payload_id,
                        test_id,
                        endpoint_id,
                        payload,
                        payload_type,
                        created_at
                    )
                    VALUES (?,?,?,?,?,?)""",
                    (
                        payload_id,
                        test_id,
                        test.get("endpoint_id"),
                        payload_text,
                        payload_type,
                        now,
                    ),
                )

        # --------------------------------------------------------------
        # Existing legacy controls
        # --------------------------------------------------------------

        legacy_control_ids: list[str] = []

        for key, value in test.items():
            if (
                "control" not in str(key).lower()
                or value in (None, "", [], {})
            ):
                continue

            control_id = stable_id(
                "control",
                f"{scan_id}:{test_id}:{key}",
            )
            legacy_control_ids.append(control_id)

            con.execute(
                """INSERT OR REPLACE INTO controls(
                    control_id,
                    test_run_id,
                    scan_id,
                    request_id,
                    response_id,
                    kind,
                    status,
                    data_json
                )
                VALUES (?,?,?,?,?,?,?,?)""",
                (
                    control_id,
                    test_run_id,
                    scan_id,
                    request_ids.get("control_exchange_id"),
                    response_ids.get("control_exchange_id"),
                    str(key),
                    str(test.get("status") or "OBSERVED"),
                    _json(value),
                ),
            )

        # --------------------------------------------------------------
        # Existing legacy differential
        # --------------------------------------------------------------

        diff = test.get("differential") or test.get("diff")
        diff_id: Optional[str] = None

        if diff is not None:
            diff_id = stable_id(
                "diff",
                f"{scan_id}:{test_id}",
            )

            con.execute(
                """INSERT OR REPLACE INTO diffs(
                    diff_id,
                    test_run_id,
                    scan_id,
                    baseline_response_id,
                    test_response_id,
                    control_response_id,
                    status_difference,
                    body_difference_json,
                    created_at
                )
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    diff_id,
                    test_run_id,
                    scan_id,
                    response_ids.get("baseline_exchange_id"),
                    response_ids.get("test_exchange_id")
                    or response_ids.get("cross_account_exchange_id"),
                    response_ids.get("control_exchange_id"),
                    str(
                        diff.get("status")
                        if isinstance(diff, dict)
                        else ""
                    ),
                    _json(diff),
                    now,
                ),
            )

        # ==============================================================
        # PHASE-1 RESEARCH WORKSPACE
        # ==============================================================

        observation_ids: list[str] = []

        observations = (
            test.get("observations")
            or test.get("observation")
            or test.get("observed")
        )

        for oindex, observation in enumerate(_as_list(observations)):
            observation_id = stable_id(
                "observation",
                f"{scan_id}:{test_id}:{oindex}:{_extract_text(observation)}",
            )

            observation_ids.append(observation_id)

            if isinstance(observation, dict):
                title = str(
                    observation.get("title")
                    or observation.get("name")
                    or f"Observation {oindex + 1}"
                )
                description = str(
                    observation.get("description")
                    or observation.get("detail")
                    or observation.get("reason")
                    or ""
                )
                kind = str(
                    observation.get("kind")
                    or observation.get("type")
                    or "behavioral"
                )
                source = str(
                    observation.get("source")
                    or observation.get("module")
                    or "test"
                )
                value = observation
                severity_hint = str(
                    observation.get("severity")
                    or observation.get("severity_hint")
                    or "info"
                )
                confidence = observation.get("confidence")
            else:
                title = f"Observation {oindex + 1}"
                description = str(observation)
                kind = "behavioral"
                source = "test"
                value = observation
                severity_hint = "info"
                confidence = None

            _upsert(
                "observations",
                {
                    "observation_id": observation_id,
                    "scan_id": scan_id,
                    "asset_id": test.get("asset_id"),
                    "endpoint_id": test.get("endpoint_id"),
                    "exchange_id": (
                        test.get("observation_exchange_id")
                        or test.get("exchange_id")
                        or named_exchange_ids.get("test_exchange_id")
                        or named_exchange_ids.get("cross_account_exchange_id")
                    ),
                    "actor_id": test.get("actor_id"),
                    "kind": kind,
                    "source": source,
                    "title": title,
                    "description": description,
                    "value_json": _safe_json(value),
                    "severity_hint": severity_hint,
                    "confidence": confidence,
                    "scope_status": scope_decision,
                    "observed_at": now,
                    "provenance_json": _safe_json(
                        {
                            "test_id": test_id,
                            "test_run_id": test_run_id,
                            "source": source,
                        }
                    ),
                },
                "observation_id",
            )

        # If a verifier supplied exact exchange evidence but no explicit
        # observation object, record the traffic as an observation rather
        # than inventing a vulnerability.
        if not observation_ids and (
            request_ids.get("observed_exchange_id")
            or request_ids.get("test_exchange_id")
            or request_ids.get("cross_account_exchange_id")
        ):
            observation_id = stable_id(
                "observation",
                f"{scan_id}:{test_id}:traffic",
            )
            observation_ids.append(observation_id)

            _upsert(
                "observations",
                {
                    "observation_id": observation_id,
                    "scan_id": scan_id,
                    "asset_id": test.get("asset_id"),
                    "endpoint_id": test.get("endpoint_id"),
                    "exchange_id": (
                        named_exchange_ids.get("test_exchange_id")
                        or named_exchange_ids.get("cross_account_exchange_id")
                        or named_exchange_ids.get("baseline_exchange_id")
                    ),
                    "actor_id": test.get("actor_id"),
                    "kind": "traffic",
                    "source": str(test.get("module") or "test"),
                    "title": "Captured test traffic",
                    "description": (
                        "HTTP traffic associated with this test was "
                        "captured and linked as research evidence."
                    ),
                    "value_json": _safe_json(
                        {
                            "test_id": test_id,
                            "exchange_ids": [
                                x for x in named_exchange_ids.values()
                                if x
                            ],
                        }
                    ),
                    "severity_hint": "info",
                    "scope_status": scope_decision,
                    "observed_at": now,
                    "provenance_json": _safe_json(
                        {
                            "test_id": test_id,
                            "test_run_id": test_run_id,
                            "generated": True,
                        }
                    ),
                },
                "observation_id",
            )

        # --------------------------------------------------------------
        # Hypotheses
        # --------------------------------------------------------------

        hypothesis_values = (
            test.get("hypotheses")
            or test.get("hypothesis")
            or test.get("hypothesis_record")
        )

        if not hypothesis_values and test.get("hypothesis_id"):
            hypothesis_values = [{
                "hypothesis_id": test.get("hypothesis_id"),
                "title": test.get("title") or test.get("name") or "",
                "statement": test.get("statement") or test.get("hypothesis") or "",
                "rationale": test.get("rationale") or test.get("reason") or "",
            }]

        hypothesis_ids: list[str] = []

        for hindex, hypothesis in enumerate(_as_list(hypothesis_values)):
            if isinstance(hypothesis, dict):
                hypothesis_id = str(
                    hypothesis.get("hypothesis_id")
                    or stable_id(
                        "hypothesis",
                        f"{scan_id}:{test_id}:{hindex}",
                    )
                )
                category = str(
                    hypothesis.get("category")
                    or test.get("type")
                    or ""
                )
                title = str(
                    hypothesis.get("title")
                    or test.get("title")
                    or test.get("name")
                    or "Security hypothesis"
                )
                statement = str(
                    hypothesis.get("statement")
                    or hypothesis.get("hypothesis")
                    or ""
                )
                rationale = str(
                    hypothesis.get("rationale")
                    or hypothesis.get("reason")
                    or ""
                )
                security_property = str(
                    hypothesis.get("security_property")
                    or test.get("security_property")
                    or ""
                )
                expected_boundary = str(
                    hypothesis.get("expected_boundary")
                    or test.get("expected_boundary")
                    or ""
                )
                status = str(
                    hypothesis.get("status")
                    or test.get("status")
                    or "OPEN"
                )
                priority = str(
                    hypothesis.get("priority")
                    or test.get("priority")
                    or "NORMAL"
                )
                confidence = hypothesis.get("confidence")
                resource_id = hypothesis.get("resource_id") or test.get("resource_id")
            else:
                hypothesis_id = stable_id(
                    "hypothesis",
                    f"{scan_id}:{test_id}:{hindex}:{hypothesis}",
                )
                category = str(test.get("type") or "")
                title = "Security hypothesis"
                statement = str(hypothesis)
                rationale = str(test.get("reason") or "")
                security_property = str(test.get("security_property") or "")
                expected_boundary = str(test.get("expected_boundary") or "")
                status = str(test.get("status") or "OPEN")
                priority = str(test.get("priority") or "NORMAL")
                confidence = None
                resource_id = test.get("resource_id")

            hypothesis_ids.append(hypothesis_id)

            _upsert(
                "research_hypotheses",
                {
                    "hypothesis_id": hypothesis_id,
                    "scan_id": scan_id,
                    "observation_id": (
                        observation_ids[0] if observation_ids else None
                    ),
                    "endpoint_id": test.get("endpoint_id"),
                    "actor_id": test.get("actor_id"),
                    "resource_id": resource_id,
                    "category": category,
                    "title": title,
                    "statement": statement,
                    "rationale": rationale,
                    "security_property": security_property,
                    "expected_boundary": expected_boundary,
                    "status": status,
                    "priority": priority,
                    "confidence": confidence,
                    "created_at": now,
                    "updated_at": now,
                    "provenance_json": _safe_json(
                        {
                            "test_id": test_id,
                            "test_run_id": test_run_id,
                        }
                    ),
                },
                "hypothesis_id",
            )

        primary_hypothesis_id = (
            hypothesis_ids[0]
            if hypothesis_ids
            else test.get("hypothesis_id")
        )

        # --------------------------------------------------------------
        # Research test plan
        # --------------------------------------------------------------

        test_plan_id = stable_id(
            "testplan",
            f"{scan_id}:{test_id}",
        )

        _upsert(
            "research_test_plans",
            {
                "test_plan_id": test_plan_id,
                "scan_id": scan_id,
                "hypothesis_id": primary_hypothesis_id,
                "endpoint_id": test.get("endpoint_id"),
                "actor_id": test.get("actor_id"),
                "authentication_context_id": auth_context_id,
                "name": str(
                    test.get("name")
                    or test.get("title")
                    or f"Test {test_id}"
                ),
                "category": str(
                    test.get("category")
                    or test.get("type")
                    or ""
                ),
                "method": method,
                "parameter": parameter,
                "strategy_json": _safe_json(
                    test.get("strategy")
                    or test.get("test_strategy")
                    or {}
                ),
                "prerequisites_json": _safe_json(
                    test.get("prerequisites")
                    or {}
                ),
                "authorization_required": int(
                    bool(test.get("authorization_required", True))
                ),
                "destructive": int(bool(test.get("destructive", False))),
                "estimated_requests": int(
                    test.get("estimated_requests") or 0
                ),
                "risk": str(test.get("risk") or "LOW"),
                "status": str(test.get("status") or "PLANNED"),
                "created_at": now,
                "updated_at": now,
                "provenance_json": _safe_json(
                    {
                        "test_id": test_id,
                        "test_run_id": test_run_id,
                    }
                ),
            },
            "test_plan_id",
        )

        # --------------------------------------------------------------
        # Research test steps
        # --------------------------------------------------------------

        explicit_steps = (
            test.get("steps")
            or test.get("test_steps")
            or []
        )

        steps: list[Any] = (
            explicit_steps
            if isinstance(explicit_steps, list)
            else [explicit_steps]
        )

        # If the verifier did not supply explicit steps, derive bounded
        # research steps from the evidence that actually exists.
        if not steps:
            derived_steps: list[dict[str, Any]] = []

            if request_ids.get("baseline_exchange_id"):
                derived_steps.append({
                    "stage": "BASELINE",
                    "action": "baseline",
                    "status": "COMPLETE",
                    "request_id": request_ids.get("baseline_exchange_id"),
                    "response_id": response_ids.get("baseline_exchange_id"),
                })

            if payload_ids:
                derived_steps.append({
                    "stage": "MUTATION",
                    "action": "mutation",
                    "status": "COMPLETE",
                    "payload_id": payload_ids[0],
                    "request_id": (
                        request_ids.get("test_exchange_id")
                        or request_ids.get("cross_account_exchange_id")
                    ),
                    "response_id": (
                        response_ids.get("test_exchange_id")
                        or response_ids.get("cross_account_exchange_id")
                    ),
                })

            if request_ids.get("control_exchange_id"):
                derived_steps.append({
                    "stage": "CONTROL",
                    "action": "control",
                    "status": "COMPLETE",
                    "request_id": request_ids.get("control_exchange_id"),
                    "response_id": response_ids.get("control_exchange_id"),
                })

            if diff is not None:
                derived_steps.append({
                    "stage": "DIFFERENTIAL TEST",
                    "action": "differential",
                    "status": "COMPLETE",
                    "diff_id": diff_id,
                })

            if test.get("reproduction_status") or test.get("reproduction"):
                derived_steps.append({
                    "stage": "REPRODUCTION",
                    "action": "reproduction",
                    "status": str(
                        test.get("reproduction_status")
                        or "COMPLETE"
                    ),
                })

            steps = derived_steps

        for sindex, step in enumerate(steps):
            if isinstance(step, dict):
                stage = str(
                    step.get("stage")
                    or step.get("pipeline_stage")
                    or "OBSERVATION"
                )
                action = str(
                    step.get("action")
                    or step.get("name")
                    or stage.lower()
                )
                step_status = str(
                    step.get("status")
                    or "PLANNED"
                )

                step_request_id = (
                    step.get("request_id")
                    or (
                        _lookup_exchange(step.get("exchange_id"))[0]
                        if step.get("exchange_id")
                        else None
                    )
                )
                step_response_id = (
                    step.get("response_id")
                    or (
                        _lookup_exchange(step.get("exchange_id"))[1]
                        if step.get("exchange_id")
                        else None
                    )
                )
                step_payload_id = step.get("payload_id")
                step_control_id = step.get("control_id")
                step_diff_id = step.get("diff_id")

                assertion = step.get("assertion") or {}
                result = step.get("result") or step
            else:
                stage = "OBSERVATION"
                action = str(step)
                step_status = "OBSERVED"
                step_request_id = None
                step_response_id = None
                step_payload_id = None
                step_control_id = None
                step_diff_id = None
                assertion = {}
                result = {"value": step}

            step_id = stable_id(
                "teststep",
                f"{scan_id}:{test_plan_id}:{sindex}",
            )

            _upsert(
                "research_test_steps",
                {
                    "step_id": step_id,
                    "test_plan_id": test_plan_id,
                    "scan_id": scan_id,
                    "sequence_no": sindex + 1,
                    "stage": stage,
                    "action": action,
                    "status": step_status,
                    "request_id": step_request_id,
                    "response_id": step_response_id,
                    "payload_id": step_payload_id,
                    "control_id": step_control_id,
                    "diff_id": step_diff_id,
                    "assertion_json": _safe_json(assertion),
                    "result_json": _safe_json(result),
                    "started_at": step.get("started_at") if isinstance(step, dict) else None,
                    "finished_at": step.get("finished_at") if isinstance(step, dict) else None,
                },
                "step_id",
            )

        # --------------------------------------------------------------
        # Mutations
        # --------------------------------------------------------------

        mutations = (
            test.get("mutations")
            or test.get("mutation")
            or []
        )

        for mindex, mutation in enumerate(_as_list(mutations)):
            if isinstance(mutation, dict):
                original = mutation.get("original_value")
                mutated = mutation.get("mutated_value")
                location = str(mutation.get("location") or parameter)
                mutation_type = str(
                    mutation.get("mutation_type")
                    or mutation.get("type")
                    or "value"
                )
                rationale = str(mutation.get("rationale") or "")
                mutation_status = str(
                    mutation.get("status") or "EXECUTED"
                )
                mutation_payload_id = (
                    mutation.get("payload_id")
                    or (payload_ids[mindex] if mindex < len(payload_ids) else None)
                )
                mutation_request_id = mutation.get("request_id")
            else:
                original = None
                mutated = mutation
                location = parameter
                mutation_type = "value"
                rationale = ""
                mutation_status = "EXECUTED"
                mutation_payload_id = (
                    payload_ids[mindex]
                    if mindex < len(payload_ids)
                    else None
                )
                mutation_request_id = None

            mutation_id = stable_id(
                "mutation",
                f"{scan_id}:{test_id}:{mindex}",
            )

            _upsert(
                "research_mutations",
                {
                    "mutation_id": mutation_id,
                    "scan_id": scan_id,
                    "test_plan_id": test_plan_id,
                    "test_run_id": test_run_id,
                    "parameter": parameter,
                    "location": location,
                    "original_value": _extract_text(original),
                    "mutated_value": _extract_text(mutated),
                    "mutation_type": mutation_type,
                    "rationale": rationale,
                    "payload_id": mutation_payload_id,
                    "request_id": (
                        mutation_request_id
                        or request_ids.get("test_exchange_id")
                        or request_ids.get("cross_account_exchange_id")
                    ),
                    "status": mutation_status,
                    "created_at": now,
                    "provenance_json": _safe_json(
                        {"test_id": test_id}
                    ),
                },
                "mutation_id",
            )

        # --------------------------------------------------------------
        # Baseline
        # --------------------------------------------------------------

        baseline_exchange = named_exchange_ids.get(
            "baseline_exchange_id"
        )

        if baseline_exchange or response_ids.get("baseline_exchange_id"):
            baseline_id = stable_id(
                "baseline",
                f"{scan_id}:{test_id}",
            )

            baseline_data = test.get("baseline")
            if not isinstance(baseline_data, dict):
                baseline_data = {}

            _upsert(
                "research_baselines",
                {
                    "baseline_id": baseline_id,
                    "scan_id": scan_id,
                    "test_run_id": test_run_id,
                    "request_id": request_ids.get("baseline_exchange_id"),
                    "response_id": response_ids.get("baseline_exchange_id"),
                    "endpoint_id": test.get("endpoint_id"),
                    "actor_id": test.get("actor_id"),
                    "fingerprint": str(
                        baseline_data.get("fingerprint")
                        or test.get("baseline_fingerprint")
                        or ""
                    ),
                    "status_code": baseline_data.get("status_code"),
                    "body_hash": str(
                        baseline_data.get("body_hash") or ""
                    ),
                    "semantic_json": _safe_json(
                        baseline_data.get("semantic")
                        or baseline_data.get("semantic_diff")
                        or {}
                    ),
                    "headers_json": _safe_json(
                        baseline_data.get("headers")
                        or {}
                    ),
                    "timing_json": _safe_json(
                        baseline_data.get("timing")
                        or {}
                    ),
                    "validity": str(
                        baseline_data.get("validity")
                        or baseline_data.get("status")
                        or test.get("baseline_status")
                        or "VALID"
                    ),
                    "established_at": now,
                    "invalid_reason": str(
                        baseline_data.get("invalid_reason")
                        or baseline_data.get("validity_reason")
                        or ""
                    ),
                },
                "baseline_id",
            )

        # --------------------------------------------------------------
        # Research controls
        # --------------------------------------------------------------

        research_controls = (
            test.get("controls")
            or test.get("control")
            or []
        )

        for cindex, control in enumerate(_as_list(research_controls)):
            if isinstance(control, dict):
                control_type = str(
                    control.get("type")
                    or control.get("kind")
                    or "control"
                )
                purpose = str(
                    control.get("purpose")
                    or control.get("description")
                    or ""
                )
                expected = control.get("expected") or {}
                observed = control.get("observed") or {}
                passed = control.get("passed")
                control_status = str(
                    control.get("status") or "OBSERVED"
                )
                control_request_id = control.get("request_id")
                control_response_id = control.get("response_id")
            else:
                control_type = "control"
                purpose = str(control)
                expected = {}
                observed = {}
                passed = None
                control_status = "OBSERVED"
                control_request_id = request_ids.get("control_exchange_id")
                control_response_id = response_ids.get("control_exchange_id")

            research_control_id = stable_id(
                "research-control",
                f"{scan_id}:{test_id}:{cindex}:{control_type}",
            )

            _upsert(
                "research_controls",
                {
                    "research_control_id": research_control_id,
                    "scan_id": scan_id,
                    "test_run_id": test_run_id,
                    "type": control_type,
                    "purpose": purpose,
                    "request_id": (
                        control_request_id
                        or request_ids.get("control_exchange_id")
                    ),
                    "response_id": (
                        control_response_id
                        or response_ids.get("control_exchange_id")
                    ),
                    "expected_json": _safe_json(expected),
                    "observed_json": _safe_json(observed),
                    "passed": passed,
                    "status": control_status,
                    "rationale": str(
                        control.get("rationale") or ""
                        if isinstance(control, dict)
                        else ""
                    ),
                    "created_at": now,
                },
                "research_control_id",
            )

        # Preserve a named control even when it was only supplied through
        # the legacy exchange fields.
        if (
            not research_controls
            and request_ids.get("control_exchange_id")
        ):
            research_control_id = stable_id(
                "research-control",
                f"{scan_id}:{test_id}:exchange",
            )

            _upsert(
                "research_controls",
                {
                    "research_control_id": research_control_id,
                    "scan_id": scan_id,
                    "test_run_id": test_run_id,
                    "type": "exchange_control",
                    "purpose": "Control exchange linked to test",
                    "request_id": request_ids.get("control_exchange_id"),
                    "response_id": response_ids.get("control_exchange_id"),
                    "expected_json": _safe_json({}),
                    "observed_json": _safe_json({}),
                    "status": "OBSERVED",
                    "created_at": now,
                },
                "research_control_id",
            )

        # --------------------------------------------------------------
        # Differential
        # --------------------------------------------------------------

        if diff is not None:
            differential_id = stable_id(
                "differential",
                f"{scan_id}:{test_id}",
            )

            if isinstance(diff, dict):
                status_difference = diff.get("status")
                header_difference = (
                    diff.get("headers")
                    or diff.get("header_difference")
                    or {}
                )
                body_difference = (
                    diff.get("body")
                    or diff.get("body_difference")
                    or {}
                )
                semantic_difference = (
                    diff.get("semantic")
                    or diff.get("semantic_difference")
                    or {}
                )
                auth_boundary_change = (
                    diff.get("authorization")
                    or diff.get("auth_boundary")
                    or {}
                )
                meaningful = diff.get("meaningful")
            else:
                status_difference = None
                header_difference = {}
                body_difference = diff
                semantic_difference = {}
                auth_boundary_change = {}
                meaningful = None

            _upsert(
                "research_differentials",
                {
                    "differential_id": differential_id,
                    "scan_id": scan_id,
                    "test_run_id": test_run_id,
                    "baseline_response_id": response_ids.get(
                        "baseline_exchange_id"
                    ),
                    "control_response_id": response_ids.get(
                        "control_exchange_id"
                    ),
                    "mutated_response_id": (
                        response_ids.get("test_exchange_id")
                        or response_ids.get("cross_account_exchange_id")
                    ),
                    "comparison_type": str(
                        test.get("comparison_type")
                        or "baseline_control_mutation"
                    ),
                    "status": "ANALYZED",
                    "status_code_changed": int(
                        bool(status_difference)
                    ),
                    "headers_changed": int(
                        bool(header_difference)
                    ),
                    "body_changed": int(
                        bool(body_difference)
                    ),
                    "semantic_changed": int(
                        bool(semantic_difference)
                    ),
                    "authorization_boundary_changed": int(
                        bool(auth_boundary_change)
                    ),
                    "meaningful": (
                        int(bool(meaningful))
                        if meaningful is not None
                        else 0
                    ),
                    "summary": str(
                        diff.get("summary")
                        if isinstance(diff, dict)
                        else ""
                    ),
                    "diff_json": _safe_json({
                        "legacy_status_difference": status_difference,
                        "legacy_header_difference": header_difference,
                        "legacy_body_difference": body_difference,
                        "legacy_semantic_difference": semantic_difference,
                        "legacy_authorization_boundary": (
                            auth_boundary_change
                        ),
                        "meaningful": meaningful,
                        "original": diff,
                    }),
                    "created_at": now,
                },
                "differential_id",
            )
        else:
            differential_id = None

        # --------------------------------------------------------------
        # Reproduction
        # --------------------------------------------------------------

        reproduction_values = (
            test.get("reproductions")
            or test.get("reproduction")
        )

        if reproduction_values:
            for rindex, reproduction in enumerate(
                _as_list(reproduction_values)
            ):
                if isinstance(reproduction, dict):
                    attempt_no = int(
                        reproduction.get("attempt_no")
                        or rindex + 1
                    )
                    reproduction_request_id = reproduction.get(
                        "request_id"
                    )
                    reproduction_response_id = reproduction.get(
                        "response_id"
                    )
                    expected = reproduction.get("expected") or {}
                    observed = reproduction.get("observed") or {}
                    matched = reproduction.get("matched")
                    stability_score = reproduction.get(
                        "stability_score"
                    )
                    reproduction_status = str(
                        reproduction.get("status")
                        or ("MATCHED" if matched else "OBSERVED")
                    )
                else:
                    attempt_no = rindex + 1
                    reproduction_request_id = None
                    reproduction_response_id = None
                    expected = {}
                    observed = reproduction
                    matched = None
                    stability_score = None
                    reproduction_status = "OBSERVED"

                reproduction_id = stable_id(
                    "reproduction",
                    f"{scan_id}:{test_id}:{attempt_no}",
                )

                _upsert(
                    "reproductions",
                    {
                        "reproduction_id": reproduction_id,
                        "scan_id": scan_id,
                        "test_run_id": test_run_id,
                        "attempt_no": attempt_no,
                        "request_id": (
                            reproduction_request_id
                            or request_ids.get("repeat_exchange_id")
                        ),
                        "response_id": (
                            reproduction_response_id
                            or response_ids.get("repeat_exchange_id")
                        ),
                        "expected_json": _safe_json(expected),
                        "observed_json": _safe_json(observed),
                        "matched": matched,
                        "stability_score": stability_score,
                        "status": reproduction_status,
                        "created_at": now,
                    },
                    "reproduction_id",
                )

        # --------------------------------------------------------------
        # Impact validation
        # --------------------------------------------------------------

        impact_values = (
            test.get("impact_validations")
            or test.get("impact_validation")
            or test.get("impact")
        )

        if impact_values:
            for iindex, impact in enumerate(_as_list(impact_values)):
                if isinstance(impact, dict):
                    contract_type = str(
                        impact.get("contract_type")
                        or impact.get("type")
                        or "security_boundary"
                    )
                    security_boundary = str(
                        impact.get("security_boundary")
                        or ""
                    )
                    protected_resource = str(
                        impact.get("protected_resource")
                        or ""
                    )
                    affected_actor = str(
                        impact.get("affected_actor")
                        or ""
                    )
                    impact_class = str(
                        impact.get("impact_class")
                        or impact.get("class")
                        or ""
                    )
                    evidence = impact.get("evidence") or {}
                    proven = impact.get("proven")
                    impact_status = str(
                        impact.get("status") or "OBSERVED"
                    )
                    rationale = str(
                        impact.get("rationale") or ""
                    )
                else:
                    contract_type = "security_boundary"
                    security_boundary = ""
                    protected_resource = ""
                    affected_actor = ""
                    impact_class = ""
                    evidence = impact
                    proven = None
                    impact_status = "OBSERVED"
                    rationale = ""

                impact_id = stable_id(
                    "impact",
                    f"{scan_id}:{test_id}:{iindex}",
                )

                _upsert(
                    "impact_validations",
                    {
                        "impact_id": impact_id,
                        "scan_id": scan_id,
                        "test_run_id": test_run_id,
                        "contract_type": contract_type,
                        "security_boundary": security_boundary,
                        "protected_resource": protected_resource,
                        "affected_actor": affected_actor,
                        "impact_class": impact_class,
                        "evidence_json": _safe_json(evidence),
                        "proven": proven,
                        "status": impact_status,
                        "rationale": rationale,
                        "created_at": now,
                    },
                    "impact_id",
                )

        # --------------------------------------------------------------
        # Derived research evidence
        #
        # Converts verifier-produced evidence into structured research
        # records. This section NEVER creates or promotes findings.
        # --------------------------------------------------------------

        test_type = str(
            test.get("type")
            or test.get("category")
            or ""
        ).strip().lower()

        def _as_bool(value):
            if isinstance(value, bool):
                return value
            if value is None:
                return None
            return str(value).strip().lower() in {
                "1", "true", "yes", "verified", "passed", "match"
            }

        def _trace(
            object_type,
            object_id,
            *,
            relation="supports",
            request_id=None,
            response_id=None,
            exchange_id=None,
            evidence_id=None,
            finding_id=None,
        ):
            if not object_id:
                return

            trace_id = stable_id(
                "research-trace",
                f"{scan_id}:{test_id}:{object_type}:{object_id}:{relation}",
            )

            _upsert(
                "research_trace_links",
                {
                    "trace_id": trace_id,
                    "scan_id": scan_id,
                    "object_type": object_type,
                    "object_id": str(object_id),
                    "request_id": request_id,
                    "response_id": response_id,
                    "exchange_id": exchange_id,
                    "test_id": test_id,
                    "hypothesis_id": primary_hypothesis_id,
                    "evidence_id": evidence_id,
                    "finding_id": finding_id,
                    "relation": relation,
                    "created_at": now,
                },
                "trace_id",
            )

        def _evidence_node(node_type, object_id, label, metadata=None):
            if not object_id:
                return None

            node_id = stable_id(
                "evidence-node",
                f"{scan_id}:{node_type}:{object_id}",
            )

            _upsert(
                "evidence_graph",
                {
                    "evidence_node_id": node_id,
                    "scan_id": scan_id,
                    "node_type": node_type,
                    "object_id": str(object_id),
                    "label": label,
                    "metadata_json": _safe_json(metadata or {}),
                    "created_at": now,
                },
                "evidence_node_id",
            )

            return node_id

        def _evidence_edge(source_id, target_id, relation, rationale=""):
            if not source_id or not target_id:
                return

            edge_id = stable_id(
                "evidence-edge",
                f"{scan_id}:{source_id}:{target_id}:{relation}",
            )

            _upsert(
                "evidence_edges",
                {
                    "edge_id": edge_id,
                    "scan_id": scan_id,
                    "source_node_id": source_id,
                    "target_node_id": target_id,
                    "relation": relation,
                    "rationale": rationale,
                    "created_at": now,
                },
                "edge_id",
            )

        is_bola = (
            "cross-account-object-authorization" in test_type
            or "bola" in test_type
            or "object-level authorization" in str(
                test.get("security_boundary") or ""
            ).lower()
        )

        if is_bola:
            baseline_exchange_id = named_exchange_ids.get(
                "baseline_exchange_id"
            )
            cross_exchange_id = named_exchange_ids.get(
                "cross_account_exchange_id"
            )
            repeat_exchange_id = named_exchange_ids.get(
                "repeat_exchange_id"
            )

            baseline_request_id = request_ids.get(
                "baseline_exchange_id"
            )
            baseline_response_id = response_ids.get(
                "baseline_exchange_id"
            )

            cross_request_id = request_ids.get(
                "cross_account_exchange_id"
            )
            cross_response_id = response_ids.get(
                "cross_account_exchange_id"
            )

            repeat_request_id = request_ids.get(
                "repeat_exchange_id"
            )
            repeat_response_id = response_ids.get(
                "repeat_exchange_id"
            )

            owner_verified = _as_bool(
                test.get("owner_identity_verified")
            )
            other_verified = _as_bool(
                test.get("other_identity_verified")
            )

            baseline_owner_matches = _as_bool(
                test.get("baseline_owner_matches")
            )
            cross_owner_matches = _as_bool(
                test.get("cross_owner_matches")
            )

            repeat_stable = _as_bool(
                test.get("repeat_response_stable")
            )

            sensitive_fields = test.get(
                "sensitive_fields"
            ) or []

            # ----------------------------------------------------------
            # Authorization mutation
            # ----------------------------------------------------------

            if cross_exchange_id:
                mutation_id = stable_id(
                    "mutation",
                    f"{scan_id}:{test_id}:authorization-context",
                )

                _upsert(
                    "research_mutations",
                    {
                        "mutation_id": mutation_id,
                        "scan_id": scan_id,
                        "test_plan_id": test_plan_id,
                        "test_run_id": test_run_id,
                        "parameter": str(
                            test.get(
                                "identity_assertion_header"
                            )
                            or parameter
                            or "identity"
                        ),
                        "location": "authorization context",
                        "original_value": str(
                            test.get("owner_identity_label")
                            or "owner"
                        ),
                        "mutated_value": str(
                            test.get("other_identity_label")
                            or "other actor"
                        ),
                        "mutation_type": "authorization-context",
                        "rationale": (
                            "Compare the protected resource under "
                            "different authorized identities."
                        ),
                        "payload_id": None,
                        "request_id": cross_request_id,
                        "status": "EXECUTED",
                        "created_at": now,
                        "provenance_json": _safe_json({
                            "derived_from_verifier": True,
                            "exchange_id": cross_exchange_id,
                        }),
                    },
                    "mutation_id",
                )

                _trace(
                    "mutation",
                    mutation_id,
                    relation="executes",
                    request_id=cross_request_id,
                    response_id=cross_response_id,
                    exchange_id=cross_exchange_id,
                )

            # ----------------------------------------------------------
            # Identity control
            # ----------------------------------------------------------

            if (
                owner_verified is not None
                or other_verified is not None
                or baseline_owner_matches is not None
                or cross_owner_matches is not None
            ):
                control_id = stable_id(
                    "research-control",
                    f"{scan_id}:{test_id}:identity-boundary",
                )

                control_passed = (
                    owner_verified is True
                    and other_verified is True
                    and baseline_owner_matches is True
                )

                _upsert(
                    "research_controls",
                    {
                        "research_control_id": control_id,
                        "scan_id": scan_id,
                        "test_run_id": test_run_id,
                        "type": "identity_boundary",
                        "purpose": (
                            "Verify that the owner and other actor "
                            "identities are distinct and attributable."
                        ),
                        "request_id": baseline_request_id,
                        "response_id": baseline_response_id,
                        "expected_json": _safe_json({
                            "owner_identity_verified": True,
                            "other_identity_verified": True,
                            "baseline_owner_matches": True,
                        }),
                        "observed_json": _safe_json({
                            "owner_identity_verified": owner_verified,
                            "other_identity_verified": other_verified,
                            "baseline_owner_matches": baseline_owner_matches,
                            "cross_owner_matches": cross_owner_matches,
                        }),
                        "passed": control_passed,
                        "status": (
                            "PASSED"
                            if control_passed
                            else "OBSERVED"
                        ),
                        "rationale": (
                            "Derived exclusively from verifier-supplied "
                            "identity assertions."
                        ),
                        "created_at": now,
                    },
                    "research_control_id",
                )

                _trace(
                    "control",
                    control_id,
                    relation="validates",
                    request_id=baseline_request_id,
                    response_id=baseline_response_id,
                    exchange_id=baseline_exchange_id,
                )

            # ----------------------------------------------------------
            # Authorization differential
            # ----------------------------------------------------------

            differential_id = None

            if baseline_response_id and cross_response_id:
                differential_id = stable_id(
                    "differential",
                    f"{scan_id}:{test_id}:authorization-boundary",
                )

                _upsert(
                    "research_differentials",
                    {
                        "differential_id": differential_id,
                        "scan_id": scan_id,
                        "test_run_id": test_run_id,
                        "baseline_response_id": baseline_response_id,
                        "control_response_id": response_ids.get(
                            "control_exchange_id"
                        ),
                        "mutated_response_id": cross_response_id,
                        "comparison_type": "authorization-boundary",
                        "status": "ANALYZED",
                        "status_code_changed": int(
                            test.get("baseline_status")
                            != test.get("cross_account_status")
                        ),
                        "headers_changed": 0,
                        "body_changed": int(
                            bool(
                                test.get("baseline_response_sha256")
                                and test.get(
                                    "cross_account_response_sha256"
                                )
                                and (
                                    test.get(
                                        "baseline_response_sha256"
                                    )
                                    != test.get(
                                        "cross_account_response_sha256"
                                    )
                                )
                            )
                        ),
                        "semantic_changed": int(
                            (
                                baseline_owner_matches is not None
                                and cross_owner_matches is not None
                                and baseline_owner_matches
                                != cross_owner_matches
                            )
                            or (
                                _as_bool(
                                    test.get(
                                        "baseline_sensitive_fields_present"
                                    )
                                )
                                != _as_bool(
                                    test.get(
                                        "cross_sensitive_fields_present"
                                    )
                                )
                            )
                        ),
                        "authorization_boundary_changed": int(
                            cross_owner_matches is True
                        ),
                        "meaningful": 1,
                        "summary": (
                            "Compared the owner baseline with the "
                            "cross-account authorization response using "
                            "verifier-supplied identity and response evidence."
                        ),
                        "diff_json": _safe_json({
                            "baseline_exchange_id": baseline_exchange_id,
                            "cross_account_exchange_id": cross_exchange_id,
                            "baseline_status": test.get(
                                "baseline_status"
                            ),
                            "cross_account_status": test.get(
                                "cross_account_status"
                            ),
                            "baseline_response_sha256": test.get(
                                "baseline_response_sha256"
                            ),
                            "cross_account_response_sha256": test.get(
                                "cross_account_response_sha256"
                            ),
                            "baseline_owner_matches": (
                                baseline_owner_matches
                            ),
                            "cross_owner_matches": (
                                cross_owner_matches
                            ),
                            "baseline_sensitive_fields_present": (
                                _as_bool(
                                    test.get(
                                        "baseline_sensitive_fields_present"
                                    )
                                )
                            ),
                            "cross_sensitive_fields_present": (
                                _as_bool(
                                    test.get(
                                        "cross_sensitive_fields_present"
                                    )
                                )
                            ),
                            "sensitive_fields": sensitive_fields,
                            "identity_assertion_header": test.get(
                                "identity_assertion_header"
                            ),
                            "owner_identity_label": test.get(
                                "owner_identity_label"
                            ),
                            "other_identity_label": test.get(
                                "other_identity_label"
                            ),
                        }),
                        "created_at": now,
                    },
                    "differential_id",
                )

                _trace(
                    "differential",
                    differential_id,
                    relation="compares",
                    request_id=cross_request_id,
                    response_id=cross_response_id,
                    exchange_id=cross_exchange_id,
                )

            # ----------------------------------------------------------
            # Reproduction
            # ----------------------------------------------------------

            if repeat_exchange_id:
                reproduction_id = stable_id(
                    "reproduction",
                    f"{scan_id}:{test_id}:repeat",
                )

                matched = (
                    repeat_stable
                    if repeat_stable is not None
                    else str(
                        test.get("reproduction_status") or ""
                    ).upper() in {
                        "VERIFIED",
                        "MATCHED",
                        "REPRODUCED",
                    }
                )

                _upsert(
                    "reproductions",
                    {
                        "reproduction_id": reproduction_id,
                        "scan_id": scan_id,
                        "test_run_id": test_run_id,
                        "attempt_no": 1,
                        "request_id": repeat_request_id,
                        "response_id": repeat_response_id,
                        "expected_json": _safe_json({
                            "stable_cross_account_behavior": True,
                        }),
                        "observed_json": _safe_json({
                            "repeat_response_stable": repeat_stable,
                            "repeat_owner_matches": _as_bool(
                                test.get("repeat_owner_matches")
                            ),
                            "repeat_sensitive_fields_present": (
                                _as_bool(
                                    test.get(
                                        "repeat_sensitive_fields_present"
                                    )
                                )
                            ),
                            "reproduction_status": test.get(
                                "reproduction_status"
                            ),
                        }),
                        "matched": matched,
                        "stability_score": (
                            1.0 if matched is True else None
                        ),
                        "status": str(
                            test.get("reproduction_status")
                            or "OBSERVED"
                        ),
                        "created_at": now,
                    },
                    "reproduction_id",
                )

                _trace(
                    "reproduction",
                    reproduction_id,
                    relation="reproduces",
                    request_id=repeat_request_id,
                    response_id=repeat_response_id,
                    exchange_id=repeat_exchange_id,
                )

            # ----------------------------------------------------------
            # Impact validation
            # ----------------------------------------------------------

            if (
                test.get("impact_proven") is not None
                or test.get("security_boundary")
                or sensitive_fields
            ):
                impact_id = stable_id(
                    "impact",
                    f"{scan_id}:{test_id}:authorization-boundary",
                )

                impact_proven = _as_bool(
                    test.get("impact_proven")
                )

                _upsert(
                    "impact_validations",
                    {
                        "impact_id": impact_id,
                        "scan_id": scan_id,
                        "test_run_id": test_run_id,
                        "contract_type": "authorization_boundary",
                        "security_boundary": str(
                            test.get("security_boundary")
                            or "object-level authorization"
                        ),
                        "protected_resource": str(
                            test.get("endpoint") or endpoint
                        ),
                        "affected_actor": str(
                            test.get("other_identity_label")
                            or "other actor"
                        ),
                        "impact_class": (
                            "cross-account-data-access"
                            if sensitive_fields
                            else "authorization-boundary"
                        ),
                        "evidence_json": _safe_json({
                            "sensitive_fields": sensitive_fields,
                            "cross_account_exchange_id": (
                                cross_exchange_id
                            ),
                            "repeat_exchange_id": repeat_exchange_id,
                            "cross_account_status": test.get(
                                "cross_account_status"
                            ),
                            "cross_owner_matches": cross_owner_matches,
                        }),
                        "proven": impact_proven,
                        "status": (
                            "PROVEN"
                            if impact_proven is True
                            else "OBSERVED"
                        ),
                        "rationale": (
                            "Impact state is copied from verifier "
                            "evidence. The research mapper does not "
                            "independently promote impact."
                        ),
                        "created_at": now,
                    },
                    "impact_id",
                )

                _trace(
                    "impact",
                    impact_id,
                    relation="validates-impact",
                    request_id=cross_request_id,
                    response_id=cross_response_id,
                    exchange_id=cross_exchange_id,
                    finding_id=test.get("finding_id"),
                )

            # ----------------------------------------------------------
            # Evidence graph
            # ----------------------------------------------------------

            test_node = _evidence_node(
                "test",
                test_id,
                f"Test {test_id}",
                {
                    "type": test_type,
                    "status": str(test.get("status") or ""),
                },
            )

            plan_node = _evidence_node(
                "test_plan",
                test_plan_id,
                "Research test plan",
                {
                    "category": test_type,
                    "endpoint": endpoint,
                    "method": method,
                },
            )

            hypothesis_node = None

            if primary_hypothesis_id:
                hypothesis_node = _evidence_node(
                    "hypothesis",
                    primary_hypothesis_id,
                    "Security hypothesis",
                    {"category": test_type},
                )

            if plan_node and test_node:
                _evidence_edge(
                    plan_node,
                    test_node,
                    "executes",
                    "Research test plan produced this test run.",
                )

            if hypothesis_node and plan_node:
                _evidence_edge(
                    hypothesis_node,
                    plan_node,
                    "drives",
                    "Hypothesis drives the test plan.",
                )

            for role, exchange_id in (
                ("baseline", baseline_exchange_id),
                ("mutation", cross_exchange_id),
                ("reproduction", repeat_exchange_id),
            ):
                if not exchange_id:
                    continue

                node = _evidence_node(
                    "exchange",
                    exchange_id,
                    f"{role.title()} exchange",
                    {"role": role},
                )

                if test_node and node:
                    _evidence_edge(
                        test_node,
                        node,
                        f"uses-{role}",
                    )

            if differential_id:
                node = _evidence_node(
                    "differential",
                    differential_id,
                    "Authorization differential",
                )
                if test_node and node:
                    _evidence_edge(
                        test_node,
                        node,
                        "produces-differential",
                    )

            finding_id = test.get("finding_id")

            if finding_id:
                finding_node = _evidence_node(
                    "finding",
                    finding_id,
                    f"Finding {finding_id}",
                    {"status": str(test.get("status") or "")},
                )

                if test_node and finding_node:
                    _evidence_edge(
                        test_node,
                        finding_node,
                        "supports",
                        "Existing verification pipeline supplied "
                        "the finding linkage.",
                    )
        # --------------------------------------------------------------
        # Research decision
        # --------------------------------------------------------------

        decision_value = (
            test.get("decision")
            or test.get("finding_decision")
            or test.get("verification_decision")
        )

        if decision_value is not None:
            if isinstance(decision_value, dict):
                decision = str(
                    decision_value.get("decision")
                    or decision_value.get("status")
                    or ""
                )
                decision_reason = str(
                    decision_value.get("reason")
                    or decision_value.get("rationale")
                    or ""
                )
                decision_status = str(
                    decision_value.get("status")
                    or decision
                    or "RECORDED"
                )
            else:
                decision = str(decision_value)
                decision_reason = str(
                    test.get("confidence_rationale")
                    or test.get("reason")
                    or ""
                )
                decision_status = decision
        else:
            decision = ""
            decision_reason = ""
            decision_status = ""

        if decision or str(test.get("status") or "").upper() in {
            "VERIFIED",
            "CONFIRMED",
            "KILLED",
            "FALSE_POSITIVE",
            "CANDIDATE",
            "UNTESTABLE",
            "BLOCKED",
        }:
            research_decision_id = stable_id(
                "decision",
                f"{scan_id}:{test_id}",
            )

            _upsert(
                "research_decisions",
                {
                    "decision_id": research_decision_id,
                    "scan_id": scan_id,
                    "test_run_id": test_run_id,
                    "hypothesis_id": primary_hypothesis_id,
                    "decision": decision
                    or str(test.get("status") or "CANDIDATE"),
                    "status": decision_status
                    or str(test.get("status") or "RECORDED"),
                    "reason": decision_reason,
                    "confidence": test.get("confidence"),
                    "confidence_rationale": str(
                        test.get("confidence_rationale")
                        or test.get("reason")
                        or ""
                    ),
                    "created_at": now,
                },
                "decision_id",
            )

        # --------------------------------------------------------------
        # Research tool observation
        # --------------------------------------------------------------

        tool_observation = (
            test.get("tool_observation")
            or test.get("scanner_observation")
        )

        if tool_observation is not None:
            tool_observation_id = stable_id(
                "tool-observation",
                f"{scan_id}:{test_id}",
            )

            _upsert(
                "research_tool_observations",
                {
                    "tool_observation_id": tool_observation_id,
                    "scan_id": scan_id,
                    "test_run_id": test_run_id,
                    "tool": str(
                        test.get("tool")
                        or test.get("module")
                        or "external-tool"
                    ),
                    "observation_json": _safe_json(
                        tool_observation
                    ),
                    "created_at": now,
                },
                "tool_observation_id",
            )

        # --------------------------------------------------------------
        # Provenance
        # --------------------------------------------------------------

        provenance_id = stable_id(
            "provenance",
            f"{scan_id}:{test_id}",
        )

        _upsert(
            "research_provenance",
            {
                "provenance_id": provenance_id,
                "scan_id": scan_id,
                "test_run_id": test_run_id,
                "source_type": "test",
                "source_id": test_id,
                "source_module": str(
                    test.get("module")
                    or test.get("source")
                    or ""
                ),
                "metadata_json": _safe_json(
                    {
                        "test_id": test_id,
                        "test_run_id": test_run_id,
                        "pipeline_stage": current_stage(test),
                        "scope_decision": scope_decision,
                    }
                ),
                "created_at": now,
            },
            "provenance_id",
        )

        # --------------------------------------------------------------
        # Unified canonical trace links
        #
        # research_trace_links is the canonical request/response/evidence
        # trace model. Do not write the obsolete trace_link_id/source_type/
        # target_type schema here.
        # --------------------------------------------------------------

        # Test-run provenance.
        _trace(
            "test_run",
            test_run_id,
            relation="supports",
        )

        # Test-plan provenance.
        _trace(
            "test_plan",
            test_plan_id,
            relation="drives",
        )

        # Observations.
        for observation_id in observation_ids:
            _trace(
                "observation",
                observation_id,
                relation="supports",
            )

        # Hypotheses.
        for hypothesis_id in hypothesis_ids:
            _trace(
                "hypothesis",
                hypothesis_id,
                relation="drives",
            )

        # Legacy differential, when present.
        if diff_id:
            _trace(
                "legacy_diff",
                diff_id,
                relation="supports",
            )

        # Payload provenance.
        for payload_id in payload_ids:
            _trace(
                "payload",
                payload_id,
                relation="uses",
            )

        # Exchange provenance. Resolve the corresponding request/response
        # identifiers so the dashboard can walk:
        #
        # exchange -> request -> response -> test/evidence/finding
        #
        # Preserve the semantic role instead of treating every exchange
        # as an undifferentiated "supports" edge.
        exchange_roles = (
            ("baseline_exchange_id", "uses-baseline"),
            ("test_exchange_id", "uses-test"),
            ("cross_account_exchange_id", "uses-cross-account"),
            ("control_exchange_id", "uses-control"),
            ("negative_control_exchange_id", "uses-negative-control"),
            ("repeat_exchange_id", "uses-reproduction"),
        )

        for exchange_key, relation in exchange_roles:
            exchange_id = named_exchange_ids.get(exchange_key)

            if not exchange_id:
                continue

            request_id = request_ids.get(exchange_key)
            response_id = response_ids.get(exchange_key)

            _trace(
                "exchange",
                str(exchange_id),
                relation=relation,
                request_id=request_id,
                response_id=response_id,
                exchange_id=str(exchange_id),
                finding_id=test.get("finding_id"),
            )

        # If a nested verifier payload exposed an exchange that was not
        # one of the named canonical exchanges, retain it as observed
        # traffic without inventing a vulnerability relationship.
        named_exchange_set = {
            str(exchange_id)
            for exchange_id in named_exchange_ids.values()
            if exchange_id
        }

        for exchange_id in dict.fromkeys(nested_exchange_ids):
            exchange_id = str(exchange_id)

            if exchange_id in named_exchange_set:
                continue

            request_id, response_id = _lookup_exchange(exchange_id)

            _trace(
                "exchange",
                exchange_id,
                relation="observed",
                request_id=request_id,
                response_id=response_id,
                exchange_id=exchange_id,
            )

def record_audit_event(con: sqlite3.Connection, *, action: str, object_type: str = "", object_id: str = "", scan_id: str = "", actor: str = "local-user", result: str = "recorded", metadata: Any = None) -> int:
    cur = con.execute("INSERT INTO audit_events(scan_id,timestamp,actor,action,object_type,object_id,result,metadata_json) VALUES (?,?,?,?,?,?,?,?)", (scan_id or None, time.time(), actor, action, object_type or None, object_id or None, result, _json(metadata or {})))
    return int(cur.lastrowid)
