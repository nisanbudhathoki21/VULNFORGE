"""
VulnForge — persistence layer (SQLite now, PostgreSQL later; spec §54).

SQLite persistence for scans, endpoint inventory, tests, exchanges, and evidence.
The schema is initialized idempotently; HTTP exchange secrets are redacted by
default, with explicit local-only plaintext history supported for the dashboard.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional

from .redaction import REDACTED, redact_any, redact_url_query_values
from .relational import (
    ensure_relational_schema,
    link_test_records,
    materialize_exchange,
    migration_status,
    record_audit_event,
    record_migration,
    stable_id,
)


def _redact_sensitive_urls(value, field=""):
    if isinstance(value,dict):
        output={}
        for key,item in value.items():
            name=str(key).lower()
            if isinstance(item,str) and (name in {"url","target","location","referer","endpoint"} or name.endswith("_url")):
                output[key]=redact_url_query_values(item)
            else:
                output[key]=_redact_sensitive_urls(item,name)
        return output
    if isinstance(value,list): return [_redact_sensitive_urls(item,field) for item in value]
    if isinstance(value,tuple): return [_redact_sensitive_urls(item,field) for item in value]
    if isinstance(value,str) and field in {"url","target","location","referer","endpoint"}:
        return redact_url_query_values(value)
    return value


def _redact_header_items(items, sensitive_names):
    output=[]
    for item in items if isinstance(items,list) else []:
        if not isinstance(item,(list,tuple)) or len(item)<2: continue
        name,value=str(item[0]),item[1]
        output.append([name,REDACTED if name.lower() in sensitive_names else redact_any(value)])
    return output

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    profile TEXT NOT NULL,
    started_at REAL,
    finished_at REAL,
    status TEXT,
    stats_json TEXT,
    scope_json TEXT,
    audit_json TEXT
);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT, method TEXT, url TEXT, normalized TEXT, path TEXT,
    status INTEGER, source TEXT, state_changing INTEGER, auth_hint TEXT,
    content_type TEXT, data_json TEXT
);
CREATE TABLE IF NOT EXISTS parameters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT, endpoint TEXT, method TEXT, name TEXT, location TEXT,
    type_hint TEXT, classifications TEXT, source TEXT, example TEXT
);
CREATE TABLE IF NOT EXISTS technologies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT, name TEXT, category TEXT, confidence TEXT, signals TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT, finding_id TEXT, title TEXT, category TEXT, severity TEXT,
    confidence REAL, status TEXT, endpoint TEXT, parameter TEXT,
    source_plugin TEXT, data_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
CREATE TABLE IF NOT EXISTS scan_documents (scan_id TEXT PRIMARY KEY, report_json TEXT NOT NULL,
  FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS hypotheses (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, data_json TEXT NOT NULL,
  FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS exchanges (id INTEGER PRIMARY KEY AUTOINCREMENT, exchange_id TEXT, scan_id TEXT NOT NULL, method TEXT, url TEXT,
  status INTEGER, module TEXT, redirect_json TEXT, data_json TEXT,
  FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS dns_observations (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, hostname TEXT, record_type TEXT, value TEXT, source TEXT,
  FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS tests (test_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, hypothesis_id TEXT, status TEXT, data_json TEXT,
  FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS evidence (evidence_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, finding_id TEXT, test_id TEXT, data_json TEXT,
  FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS phases (scan_id TEXT NOT NULL, phase_id TEXT NOT NULL, status TEXT NOT NULL, data_json TEXT NOT NULL,
  PRIMARY KEY(scan_id,phase_id), FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS asset_nodes (scan_id TEXT NOT NULL, asset_id TEXT NOT NULL, asset_type TEXT, value TEXT, data_json TEXT NOT NULL,
  PRIMARY KEY(scan_id,asset_id), FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS asset_edges (scan_id TEXT NOT NULL, edge_id TEXT NOT NULL, source_id TEXT, target_id TEXT, relation TEXT, data_json TEXT NOT NULL,
  PRIMARY KEY(scan_id,edge_id), FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS actors (scan_id TEXT NOT NULL, actor_id TEXT NOT NULL, data_json TEXT NOT NULL,
  PRIMARY KEY(scan_id,actor_id), FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS resources (scan_id TEXT NOT NULL, resource_id TEXT NOT NULL, data_json TEXT NOT NULL,
  PRIMARY KEY(scan_id,resource_id), FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS security_properties (scan_id TEXT NOT NULL, property_id TEXT NOT NULL, data_json TEXT NOT NULL,
  PRIMARY KEY(scan_id,property_id), FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS test_plans (scan_id TEXT NOT NULL, test_id TEXT NOT NULL, hypothesis_id TEXT, status TEXT, data_json TEXT NOT NULL,
  PRIMARY KEY(scan_id,test_id), FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS application_models (scan_id TEXT PRIMARY KEY, application_id TEXT NOT NULL, data_json TEXT NOT NULL,
  FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS scan_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
  kind TEXT NOT NULL, message TEXT NOT NULL, data_json TEXT NOT NULL,
  timestamp REAL NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scan_events_scan_cursor ON scan_events(scan_id,event_id);
"""


SCHEMA_VERSION = 3


def _validate_scans_parent_key(con: sqlite3.Connection, path: str) -> None:
    """Reject legacy/incompatible scans tables before adding dependent tables.

    New structured tables reference scans(scan_id) with foreign keys. Older
    dashboard databases may already own a different ``scans`` table (for
    example, with ``id`` as its primary key). SQLite accepts CREATE TABLE for
    those child tables but later fails on writes with ``foreign key mismatch``.
    Leave the old database untouched and direct the user to a fresh structured
    database rather than attempting an implicit migration.
    """
    exists = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scans'"
    ).fetchone()
    if not exists:
        return

    columns = con.execute("PRAGMA table_info(scans)").fetchall()
    scan_id = next((row for row in columns if row["name"] == "scan_id"), None)
    has_unique_scan_id = bool(scan_id and scan_id["pk"])
    if scan_id and not has_unique_scan_id:
        for index in con.execute("PRAGMA index_list(scans)").fetchall():
            # index_list columns: seq, name, unique, origin, partial
            if not index["unique"] or (len(index) > 4 and index[4]):
                continue
            quoted = str(index["name"]).replace('"', '""')
            indexed_columns = [row["name"] for row in con.execute(
                f'PRAGMA index_info("{quoted}")'
            ).fetchall()]
            if indexed_columns == ["scan_id"]:
                has_unique_scan_id = True
                break
    if not has_unique_scan_id:
        raise ValueError(
            "The selected database has an incompatible legacy 'scans' table: "
            "it does not define a unique scans.scan_id key required by the "
            "structured engine. No migration or deletion was performed. "
            "Keep this database for its existing data. Set "
            "VULNFORGE_SCAN_DB_PATH to a new structured database, or pass "
            "`--db <new-file>` to this command."
        )


class Store:
    def __init__(self, path: str = "vulnforge.db"):
        self.path = path
        self._init()

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.execute("PRAGMA foreign_keys=ON")
        con.row_factory = sqlite3.Row
        return con

    def _init(self) -> None:
        with self._conn() as con:
            version=int(con.execute("PRAGMA user_version").fetchone()[0])
            if version>SCHEMA_VERSION:
                raise RuntimeError(f"Database schema {version} is newer than this VulnForge build supports ({SCHEMA_VERSION}).")
            _validate_scans_parent_key(con, self.path)
            # All schema changes are additive CREATE TABLE/INDEX operations; historical rows are untouched.
            # Existing scan rows and historical report documents are not rewritten.
            con.executescript(_SCHEMA)
            # Keep the legacy pragma at version 3 for compatibility with the
            # original store while recording the named additive migration in a
            # durable ledger.  This gives `vulnforge db migrate` a real,
            # idempotent migration surface without rewriting old databases.
            ensure_relational_schema(con)
            record_migration(con)
            if version<SCHEMA_VERSION:
                con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    # ------------------------------------------------------------------
    def start_scan_record(self, scan_id: str, target: str, profile: str, started_at: float) -> None:
        """Create a durable RUNNING row and its project/target relationship."""
        from urllib.parse import urlsplit
        clean_target = redact_any(target)
        parsed = urlsplit(str(target))
        project_id = "project-default"
        target_id = stable_id("target", str(target).lower().rstrip("/"))
        scope_id = stable_id("scope", scan_id)
        with self._conn() as con:
            con.execute("INSERT OR REPLACE INTO scans(scan_id,target,profile,started_at,finished_at,status,stats_json,scope_json,audit_json) VALUES (?,?,?,?,?,?,?,?,?)",
                (scan_id,clean_target,profile,started_at,None,"running","{}","{}","{}"))
            con.execute("INSERT INTO projects(project_id,name,description,created_at,updated_at) VALUES (?,?,?,?,?) ON CONFLICT(project_id) DO UPDATE SET updated_at=excluded.updated_at",
                        (project_id,"Default project","Canonical VulnForge workspace",started_at,started_at))
            con.execute("INSERT INTO targets(target_id,project_id,canonical_url,scheme,host,port,created_at,last_seen) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET last_seen=excluded.last_seen",
                        (target_id,project_id,clean_target,parsed.scheme or "",parsed.hostname or "",parsed.port or (443 if parsed.scheme == "https" else 80),started_at,started_at))
            con.execute("INSERT OR REPLACE INTO scopes(scope_id,target_id,confirmed,policy_json,created_at) VALUES (?,?,?,?,?)",
                        (scope_id,target_id,0,"{}",started_at))
            con.execute("INSERT OR REPLACE INTO scan_targets(scan_id,target_id,scope_id) VALUES (?,?,?)", (scan_id,target_id,scope_id))
            con.execute("INSERT OR REPLACE INTO scan_runs(scan_id,project_id,target_id,profile,status,started_at,finished_at,statistics_json) VALUES (?,?,?,?,?,?,?,?)", (scan_id,project_id,target_id,profile,"running",started_at,None,"{}"))
            record_audit_event(con, action="scan_started", object_type="scan", object_id=scan_id, scan_id=scan_id,
                               metadata={"target_id": target_id, "profile": profile})

    def record_exchange(self, scan_id: str, exchange: Dict[str, Any], sensitive_headers=None,
                        redact: bool = True) -> None:
        """Persist one exchange; secret values are redacted unless explicitly opted in."""
        from .redaction import SENSITIVE_HEADERS
        source=exchange if isinstance(exchange,dict) else {}
        module_name=str(source.get("module",""))
        browser_workflow=module_name=="browser-workflow"
        force_sensitive_redaction=module_name in {"browser-workflow","sql-injection-validation"}
        redact=bool(redact or force_sensitive_redaction)
        safe_source=dict(source)
        if force_sensitive_redaction:
            # Browser session material and SQL parser diagnostics remain ephemeral.
            safe_source["request_body"]=""
            safe_source["response_body"]=""
            if browser_workflow: safe_source["browser_bodies_stored"]=False
            else: safe_source["sql_probe_bodies_stored"]=False
        doc=redact_any(safe_source) if redact else safe_source
        header_names=set(SENSITIVE_HEADERS)
        header_names.update(str(name).lower() for name in (sensitive_headers or []))
        if force_sensitive_redaction:
            for field_name in ("request_headers","response_headers"):
                mapping=source.get(field_name,{})
                if isinstance(mapping,dict):
                    header_names.update(str(name).lower() for name in mapping
                        if re.search(r"(?:auth|token|secret|api.?key|cookie|session|credential|csrf|password)",str(name),re.I))
            for field_name in ("request_header_items","response_header_items"):
                for pair in source.get(field_name,[]) if isinstance(source.get(field_name,[]),list) else []:
                    if isinstance(pair,(list,tuple)) and pair and re.search(r"(?:auth|token|secret|api.?key|cookie|session|credential|csrf|password)",str(pair[0]),re.I):
                        header_names.add(str(pair[0]).lower())
        if redact:
            for field_name in ("request_headers","response_headers"):
                headers=doc.get(field_name,{})
                if isinstance(headers,dict):
                    doc[field_name]={key:(REDACTED if str(key).lower() in header_names else redact_any(value))
                                     for key,value in headers.items()}
            for field_name in ("request_header_items","response_header_items"):
                if field_name in doc:
                    doc[field_name]=_redact_header_items(doc[field_name],header_names)
        if force_sensitive_redaction:
            doc=_redact_sensitive_urls(doc)
        doc["sensitive_values_stored"]=not redact
        exchange_id=str(doc.get("exchange_id") or "")
        if not exchange_id:
            return
        doc.setdefault("request_id",f"{exchange_id}:request")
        doc.setdefault("response_id",f"{exchange_id}:response")
        doc.setdefault("scan_id",scan_id)
        stored_url=redact_any(doc.get("url","")) if redact else doc.get("url","")
        redirect_data=redact_any(doc.get("redirect_chain",[])) if redact else doc.get("redirect_chain",[])
        with self._conn() as con:
            con.execute("INSERT OR REPLACE INTO exchanges(exchange_id,scan_id,method,url,status,module,redirect_json,data_json) VALUES (?,?,?,?,?,?,?,?)",
                (exchange_id,scan_id,doc.get("method","GET"),stored_url,doc.get("status",0),
                 doc.get("module",""),json.dumps(redirect_data),json.dumps(doc)))
            # The JSON exchange remains the compatibility projection; the
            # normalized request/response rows are the workbench source for
            # filtering, joins, and CLI detail views.
            materialize_exchange(con, scan_id, doc)
            record_audit_event(con, action="request_sent", object_type="exchange", object_id=exchange_id,
                               scan_id=scan_id, metadata={"request_id": doc.get("request_id"), "response_id": doc.get("response_id"), "module": doc.get("module", "")})

    def record_event(self, scan_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Persist one real engine event for resumable live/history views.

        Event payloads are redacted before storage and oversized arbitrary data is
        replaced with a bounded truncation marker. The monotonic database event_id
        is the SSE cursor; wall-clock timestamps are retained as observations.
        """
        source=event if isinstance(event,dict) else {}
        kind=str(source.get("kind") or "unknown")[:80]
        message=str(source.get("message") or kind)[:2000]
        data=source.get("data") if isinstance(source.get("data"),dict) else {}
        clean_data=redact_any(_redact_sensitive_urls(data))
        serialized=json.dumps(clean_data,ensure_ascii=False,default=str,separators=(",",":"))
        raw_size=len(serialized.encode("utf-8","replace"))
        if raw_size>256*1024:
            clean_data={"truncated":True,"original_bytes":raw_size}
            serialized=json.dumps(clean_data,separators=(",",":"))
        # A message may contain a URL outside the structured data object.
        clean_message=redact_any(message)
        stamp=source.get("timestamp",time.time())
        try: stamp=float(stamp)
        except (TypeError,ValueError): stamp=time.time()
        with self._conn() as con:
            cursor=con.execute("INSERT INTO scan_events(scan_id,kind,message,data_json,timestamp) VALUES (?,?,?,?,?)",
                (scan_id,kind,str(clean_message),serialized,stamp))
            event_id=int(cursor.lastrowid)
        return {"event_id":event_id,"scan_id":scan_id,"kind":kind,
                "message":str(clean_message),"data":clean_data,"timestamp":stamp}

    def list_scan_events(self, scan_id: str, after_event_id: int = 0,
                         limit: int = 250) -> List[Dict[str, Any]]:
        limit=max(1,min(int(limit),10000)); after_event_id=max(0,int(after_event_id))
        with self._conn() as con:
            rows=con.execute("SELECT event_id,scan_id,kind,message,data_json,timestamp FROM scan_events "
                "WHERE scan_id=? AND event_id>? ORDER BY event_id ASC LIMIT ?",
                (scan_id,after_event_id,limit)).fetchall()
        out=[]
        for row in rows:
            try: data=json.loads(row["data_json"] or "{}")
            except (ValueError,TypeError): data={"corrupt_event_data":True}
            out.append({"event_id":int(row["event_id"]),"scan_id":row["scan_id"],
                "kind":row["kind"],"message":row["message"],"data":data,
                "timestamp":row["timestamp"]})
        return out

    def finish_scan_record(self, scan_id: str, status: str, finished_at: float) -> None:
        with self._conn() as con:
            con.execute("UPDATE scans SET status=?,finished_at=? WHERE scan_id=?",
                        (status,finished_at,scan_id))
            con.execute("UPDATE scan_runs SET status=?,finished_at=? WHERE scan_id=?", (status,finished_at,scan_id))
            record_audit_event(con, action="scan_finished", object_type="scan", object_id=scan_id, scan_id=scan_id, metadata={"status": status})

    # ------------------------------------------------------------------
    def save_scan(self, scan) -> None:
        """scan is engine.orchestrator.ScanResult (kept duck-typed)."""
        ctx = scan.context
        from ..report.json_report import build_report_dict
        report_doc = build_report_dict(scan)
        with self._conn() as con:
            # Remove only this scan's replaceable projections. Audit events are
            # intentionally retained as the durable activity trail.
            for table in ("controls", "diffs", "test_runs"):
                con.execute(f"DELETE FROM {table} WHERE scan_id=?", (ctx.scan_id,))
            con.execute("DELETE FROM payloads WHERE test_id IN (SELECT test_id FROM tests WHERE scan_id=?)", (ctx.scan_id,))
            con.execute("DELETE FROM responses WHERE scan_id=?", (ctx.scan_id,))
            con.execute("DELETE FROM requests WHERE scan_id=?", (ctx.scan_id,))
            for table in ("endpoints", "parameters", "technologies", "findings", "hypotheses", "exchanges", "dns_observations", "tests", "evidence", "phases", "asset_nodes", "asset_edges", "actors", "resources", "security_properties", "test_plans", "application_models"):
                con.execute(f"DELETE FROM {table} WHERE scan_id=?", (ctx.scan_id,))
            con.execute("DELETE FROM scan_documents WHERE scan_id=?", (ctx.scan_id,))
            con.execute(
                "INSERT INTO scans(scan_id,target,profile,started_at,finished_at,status,stats_json,scope_json,audit_json) "
                "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(scan_id) DO UPDATE SET "
                "target=excluded.target,profile=excluded.profile,started_at=excluded.started_at,"
                "finished_at=excluded.finished_at,status=excluded.status,stats_json=excluded.stats_json,"
                "scope_json=excluded.scope_json,audit_json=excluded.audit_json",
                (ctx.scan_id, redact_any(ctx.config.target), ctx.config.profile_name,
                 ctx.stats.started_at, ctx.stats.finished_at,
                 "aborted" if scan.aborted else ("partial" if ctx.stop_reason else "completed"),
                 json.dumps(ctx.stats.to_dict()),
                 json.dumps(redact_any(ctx.authorization.describe())),
                 json.dumps(redact_any(ctx.authorization.audit_dump()))))
            target_id = stable_id("target", str(ctx.config.target).lower().rstrip("/"))
            parsed_target = __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(str(ctx.config.target))
            now = time.time()
            con.execute("INSERT INTO projects(project_id,name,description,created_at,updated_at) VALUES (?,?,?,?,?) ON CONFLICT(project_id) DO UPDATE SET updated_at=excluded.updated_at", ("project-default", "Default project", "Canonical VulnForge workspace", now, now))
            con.execute("INSERT INTO targets(target_id,project_id,canonical_url,scheme,host,port,created_at,last_seen) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET last_seen=excluded.last_seen", (target_id, "project-default", redact_any(ctx.config.target), parsed_target.scheme or "", parsed_target.hostname or "", parsed_target.port or (443 if parsed_target.scheme == "https" else 80), now, now))
            scope_id = stable_id("scope", ctx.scan_id)
            con.execute("INSERT OR REPLACE INTO scopes(scope_id,target_id,confirmed,policy_json,created_at) VALUES (?,?,?,?,?)", (scope_id, target_id, 1 if getattr(ctx.authorization, "confirmed", False) else 0, json.dumps(redact_any(ctx.authorization.describe())), now))
            con.execute("INSERT OR REPLACE INTO scan_targets(scan_id,target_id,scope_id) VALUES (?,?,?)", (ctx.scan_id, target_id, scope_id))
            hostname = parsed_target.hostname or ""
            if hostname:
                host_id = stable_id("host", f"{ctx.scan_id}:{hostname}")
                con.execute("INSERT OR REPLACE INTO hosts(host_id,target_id,scan_id,hostname,ip_address,source,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)", (host_id, target_id, ctx.scan_id, hostname, None, "target", now, now))
                con.execute("INSERT OR REPLACE INTO ports(port_id,host_id,port,scheme,service,source) VALUES (?,?,?,?,?,?)", (stable_id("port", f"{host_id}:{parsed_target.port or (443 if parsed_target.scheme == 'https' else 80)}"), host_id, parsed_target.port or (443 if parsed_target.scheme == "https" else 80), parsed_target.scheme, "https" if parsed_target.scheme == "https" else "http", "target"))
            final_status = "aborted" if scan.aborted else ("partial" if ctx.stop_reason else "completed")
            con.execute("INSERT OR REPLACE INTO scan_runs(scan_id,project_id,target_id,profile,status,started_at,finished_at,statistics_json) VALUES (?,?,?,?,?,?,?,?)", (ctx.scan_id, "project-default", target_id, ctx.config.profile_name, final_status, ctx.stats.started_at, ctx.stats.finished_at, json.dumps(ctx.stats.to_dict())))
            endpoint_ids = {}
            for ep in ctx.endpoints.values():
                endpoint_id = stable_id("endpoint", f"{ctx.scan_id}:{ep.method}:{ep.normalized}")
                endpoint_ids[ep.key()] = endpoint_id
                ep_doc = redact_any(ep.to_dict())
                ep_doc["endpoint_id"] = endpoint_id
                con.execute(
                    "INSERT INTO endpoints (scan_id,endpoint_id,target_id,method,url,normalized,path,status,source,state_changing,auth_hint,content_type,first_seen,last_seen,data_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ctx.scan_id, endpoint_id, target_id, ep.method, redact_any(ep.url), redact_any(ep.normalized), redact_any(ep.path), ep.status,
                     ep.source, int(ep.state_changing), ep.auth_hint, ep.content_type, ep.discovered_at or now, now,
                     json.dumps(ep_doc)))
            for p in ctx.parameters.values():
                endpoint_id = endpoint_ids.get(f"{p.method}:{p.endpoint_url}")
                parameter_id = stable_id("parameter", f"{ctx.scan_id}:{p.key()}")
                values = [p.example] if p.example else []
                con.execute(
                    "INSERT INTO parameters (scan_id,parameter_id,endpoint_id,endpoint,method,name,location,type_hint,classifications,source,example,observed_values,first_seen,last_seen,test_count,finding_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ctx.scan_id, parameter_id, endpoint_id, redact_any(p.endpoint_url), p.method, p.name, p.location,
                     p.type_hint, json.dumps(redact_any(p.classifications)), p.source, redact_any(p.example), json.dumps(redact_any(values)), now, now, 0, 0))
            for t in ctx.technologies.values():
                con.execute(
                    "INSERT INTO technologies (scan_id,name,category,confidence,signals) VALUES (?,?,?,?,?)",
                    (ctx.scan_id, t.name, t.category, t.confidence, json.dumps(redact_any({
                        "items":t.signals,"observations_count":t.observations_count}),ensure_ascii=False)))
            for f in ctx.findings:
                con.execute(
                    "INSERT INTO findings (scan_id,finding_id,title,category,severity,confidence,status,endpoint,parameter,source_plugin,data_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (ctx.scan_id, f.id, f.title, f.category, f.severity, f.confidence,
                     f.status, redact_any(f.endpoint), redact_any(f.parameter), f.source_plugin,
                     json.dumps(redact_any(f.to_dict()))))
            for h in getattr(ctx, "hypotheses", []):
                hdoc=h.to_dict() if hasattr(h,"to_dict") else h
                con.execute("INSERT INTO hypotheses(scan_id,data_json) VALUES (?,?)",
                            (ctx.scan_id, json.dumps(redact_any(hdoc))))
            for phase in getattr(ctx,"phases",[]):
                doc=phase.to_dict() if hasattr(phase,"to_dict") else phase
                con.execute("INSERT INTO phases(scan_id,phase_id,status,data_json) VALUES (?,?,?,?)",
                    (ctx.scan_id,doc["phase_id"],doc["status"],json.dumps(redact_any(doc))))
            for node in getattr(ctx,"asset_nodes",[]):
                doc=node.to_dict() if hasattr(node,"to_dict") else node
                con.execute("INSERT INTO asset_nodes(scan_id,asset_id,asset_type,value,data_json) VALUES (?,?,?,?,?)",
                    (ctx.scan_id,doc["asset_id"],doc.get("asset_type"),redact_any(doc.get("value","")),json.dumps(redact_any(doc))))
            for i,edge in enumerate(getattr(ctx,"asset_edges",[])):
                doc=edge.to_dict() if hasattr(edge,"to_dict") else edge
                con.execute("INSERT INTO asset_edges(scan_id,edge_id,source_id,target_id,relation,data_json) VALUES (?,?,?,?,?,?)",
                    (ctx.scan_id,f"edge-{i+1}",doc["source_id"],doc["target_id"],doc["relation"],json.dumps(redact_any(doc))))
            for entity,table,key in ((ctx.actors,"actors","actor_id"),(ctx.resources,"resources","resource_id"),(ctx.security_properties,"security_properties","property_id")):
                for item in entity:
                    doc=item.to_dict() if hasattr(item,"to_dict") else item
                    con.execute(f"INSERT INTO {table}(scan_id,{key},data_json) VALUES (?,?,?)",
                        (ctx.scan_id,doc[key],json.dumps(redact_any(doc))))
            for item in getattr(ctx,"test_plan",[]):
                doc=item.to_dict() if hasattr(item,"to_dict") else item
                con.execute("INSERT INTO test_plans(scan_id,test_id,hypothesis_id,status,data_json) VALUES (?,?,?,?,?)",
                    (ctx.scan_id,doc["test_id"],doc.get("hypothesis_id"),doc.get("status"),json.dumps(redact_any(doc))))
            app_model=getattr(ctx,"application_model",None)
            if app_model:
                doc=app_model.to_dict() if hasattr(app_model,"to_dict") else app_model
                con.execute("INSERT INTO application_models(scan_id,application_id,data_json) VALUES (?,?,?)",
                    (ctx.scan_id,doc["application_id"],json.dumps(redact_any(doc))))
            for test in getattr(ctx, "tests", []):
                con.execute("INSERT INTO tests(test_id,scan_id,hypothesis_id,status,data_json) VALUES (?,?,?,?,?)",
                            (test["test_id"], ctx.scan_id, test.get("hypothesis_id"), test.get("status"), json.dumps(redact_any(test))))
            for f in ctx.findings:
                for index, item in enumerate(f.evidence):
                    detail = item.to_dict()
                    test_id = detail.get("detail", {}).get("test_id")
                    evidence_id = f"evidence-{f.id}-{index+1}"
                    con.execute("INSERT INTO evidence(evidence_id,scan_id,finding_id,test_id,data_json) VALUES (?,?,?,?,?)",
                                (evidence_id, ctx.scan_id, f.id, test_id, json.dumps(redact_any(detail))))
            from .redaction import SENSITIVE_HEADERS
            configured_sensitive_headers={str(k).lower() for k in SENSITIVE_HEADERS}
            configured_sensitive_headers.update(str(k).lower() for k in getattr(ctx.config,"extra_headers",{}))
            for identity in getattr(ctx.config,"auth_data",{}).get("identities",{}).values():
                configured_sensitive_headers.update(str(k).lower() for k in identity.get("headers",{}))
            redact_exchanges=not bool(getattr(ctx.config,"store_sensitive_http",False))
            for ex in getattr(ctx.requester, "exchanges", []):
                module_name=str(getattr(ex,"module",""))
                force_sensitive_redaction=module_name in {"browser-workflow","sql-injection-validation"}
                browser_workflow=module_name=="browser-workflow"
                should_redact=redact_exchanges or force_sensitive_redaction
                exchange_doc=ex.to_dict()
                if force_sensitive_redaction:
                    exchange_doc["request_body"]=""
                    exchange_doc["response_body"]=""
                    if browser_workflow: exchange_doc["browser_bodies_stored"]=False
                    else: exchange_doc["sql_probe_bodies_stored"]=False
                    for field_name in ("request_headers","response_headers"):
                        mapping=exchange_doc.get(field_name,{})
                        if isinstance(mapping,dict):
                            configured_sensitive_headers.update(str(name).lower() for name in mapping
                                if re.search(r"(?:auth|token|secret|api.?key|cookie|session|credential|csrf|password)",str(name),re.I))
                    for field_name in ("request_header_items","response_header_items"):
                        for pair in exchange_doc.get(field_name,[]) if isinstance(exchange_doc.get(field_name,[]),list) else []:
                            if isinstance(pair,(list,tuple)) and pair and re.search(r"(?:auth|token|secret|api.?key|cookie|session|credential|csrf|password)",str(pair[0]),re.I):
                                configured_sensitive_headers.add(str(pair[0]).lower())
                exchange_doc.setdefault("request_id",f"{ex.exchange_id}:request")
                exchange_doc.setdefault("response_id",f"{ex.exchange_id}:response")
                exchange_doc.setdefault("scan_id",ctx.scan_id)
                if should_redact:
                    for header_field in ("request_headers","response_headers"):
                        headers=exchange_doc.get(header_field,{})
                        if isinstance(headers,dict):
                            exchange_doc[header_field]={key:(REDACTED if str(key).lower() in configured_sensitive_headers else redact_any(value))
                                for key,value in headers.items()}
                    exchange_doc["request_header_items"]=_redact_header_items(exchange_doc.get("request_header_items",[]),configured_sensitive_headers)
                    exchange_doc["response_header_items"]=_redact_header_items(exchange_doc.get("response_header_items",[]),configured_sensitive_headers)
                    exchange_doc=redact_any(exchange_doc)
                    if force_sensitive_redaction:
                        exchange_doc=_redact_sensitive_urls(exchange_doc)
                exchange_doc["sensitive_values_stored"]=not should_redact
                stored_url=(redact_url_query_values(ex.url) if force_sensitive_redaction else redact_any(ex.url)) if should_redact else ex.url
                redirects=(_redact_sensitive_urls(ex.redirect_chain) if force_sensitive_redaction else redact_any(ex.redirect_chain)) if should_redact else ex.redirect_chain
                con.execute("INSERT OR REPLACE INTO exchanges(exchange_id,scan_id,method,url,status,module,redirect_json,data_json) VALUES (?,?,?,?,?,?,?,?)",
                    (ex.exchange_id, ctx.scan_id, ex.method, stored_url, ex.status, ex.module,
                     json.dumps(redirects), json.dumps(exchange_doc)))
                materialize_exchange(con, ctx.scan_id, exchange_doc, target_id=target_id)
            # Link test, payload, control, and differential records to the
            # normalized request/response IDs after every exchange is present.
            link_test_records(con, ctx.scan_id, getattr(ctx, "tests", []))
            # Evidence rows keep direct traversal columns in addition to their
            # redacted JSON description: finding -> evidence -> test run ->
            # exact request/response/diff.
            evidence_rows = con.execute("SELECT evidence_id,test_id,data_json FROM evidence WHERE scan_id=?", (ctx.scan_id,)).fetchall()
            for evidence_row in evidence_rows:
                test_run = con.execute("SELECT baseline_request_id,baseline_response_id,test_request_id,test_response_id FROM test_runs WHERE test_id=? AND scan_id=?", (evidence_row["test_id"], ctx.scan_id)).fetchone() if evidence_row["test_id"] else None
                if test_run:
                    diff_row = con.execute("SELECT diff_id FROM diffs WHERE test_run_id=? LIMIT 1", (stable_id("testrun", f"{ctx.scan_id}:{evidence_row['test_id']}"),)).fetchone()
                    con.execute("UPDATE evidence SET request_id=?,response_id=?,diff_id=? WHERE evidence_id=?", (test_run["test_request_id"] or test_run["baseline_request_id"], test_run["test_response_id"] or test_run["baseline_response_id"], diff_row[0] if diff_row else None, evidence_row["evidence_id"]))
            intel = getattr(ctx, "intelligence", {})
            dns = intel.get("dns", {})
            observed_hostname = dns.get("hostname") or parsed_target.hostname or ""
            for typ in ("A", "AAAA"):
                for val in dns.get(typ, []):
                    con.execute("INSERT INTO dns_observations(scan_id,hostname,record_type,value,source) VALUES (?,?,?,?,?)",
                                (ctx.scan_id, observed_hostname, typ, val, "system resolver"))
                    host_id = stable_id("host", f"{ctx.scan_id}:{observed_hostname}:{val}")
                    con.execute("INSERT OR REPLACE INTO hosts(host_id,target_id,scan_id,hostname,ip_address,source,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)", (host_id, target_id, ctx.scan_id, observed_hostname, val, "dns", now, now))
            con.execute("INSERT INTO scan_documents(scan_id,report_json) VALUES (?,?)",
                        (ctx.scan_id, json.dumps(redact_any(report_doc))))
            for fmt, report_path in (getattr(scan, "report_paths", {}) or {}).items():
                report_id = stable_id("report", f"{ctx.scan_id}:{fmt}")
                con.execute("INSERT OR REPLACE INTO reports(report_id,scan_id,format,path,generated_at,redacted,metadata_json) VALUES (?,?,?,?,?,?,?)",
                            (report_id, ctx.scan_id, fmt, str(report_path), time.time(), 1, "{}"))
            record_audit_event(con, action="scan_persisted", object_type="scan", object_id=ctx.scan_id,
                               scan_id=ctx.scan_id, metadata={"endpoints": len(ctx.endpoints), "requests": getattr(ctx.stats, "requests_sent", 0), "findings": len(ctx.findings)})

    # ------------------------------------------------------------------
    def relational_metrics(self) -> Dict[str, int]:
        """Return actual row counts from the normalized workspace tables."""
        tables = ("projects", "targets", "scopes", "scan_runs", "hosts", "ports", "endpoints", "parameters", "requests", "responses", "tests", "test_runs", "payloads", "controls", "diffs", "evidence", "findings", "tool_observations", "browser_events", "audit_events")
        with self._conn() as con:
            return {table: int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in tables}

    def database_status(self) -> Dict[str, Any]:
        with self._conn() as con:
            version = int(con.execute("PRAGMA user_version").fetchone()[0])
            migration = migration_status(con)
            journal = con.execute("PRAGMA journal_mode").fetchone()[0]
        return {"engine": "SQLite", "path": self.path, "schema_version": version,
                "journal_mode": journal, "migration": migration, "counts": self.relational_metrics()}

    def migrate(self) -> Dict[str, Any]:
        """Re-run the additive migration safely and return its status."""
        with self._conn() as con:
            ensure_relational_schema(con)
            record_migration(con)
            record_audit_event(con, action="database_migrated", object_type="database", object_id=self.path)
            return migration_status(con)

    def backup(self, destination: str) -> str:
        """Create a consistent SQLite backup, including WAL state, safely."""
        import pathlib
        destination_path = pathlib.Path(destination).expanduser()
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        # sqlite backup() works while the database is open and is safer than a
        # byte-for-byte copy when WAL journaling is active.
        source = self._conn()
        try:
            target = sqlite3.connect(str(destination_path))
            try:
                source.backup(target)
            finally:
                target.close()
        finally:
            source.close()
        return str(destination_path)

    def resolve_exchange(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Resolve an exchange ID, request/response ID, numeric DB row, or 1-based display index."""
        value = str(identifier or "").strip()
        if not value:
            return None
        exact = self.get_exchange(value)
        if exact:
            return exact
        with self._conn() as con:
            if value.isdigit():
                row = con.execute("SELECT data_json FROM exchanges WHERE id=?", (int(value),)).fetchone()
                if row:
                    try: return json.loads(row["data_json"] or "{}")
                    except (ValueError, TypeError): return None
                rows = con.execute("SELECT data_json FROM exchanges ORDER BY id DESC LIMIT 1 OFFSET ?", (max(0, int(value) - 1),)).fetchall()
                if rows:
                    try: return json.loads(rows[0]["data_json"] or "{}")
                    except (ValueError, TypeError): return None
            row = con.execute("SELECT data_json FROM exchanges WHERE json_extract(data_json,'$.request_id')=? OR json_extract(data_json,'$.response_id')=? ORDER BY id DESC LIMIT 1", (value, value)).fetchone()
            if row:
                try: return json.loads(row["data_json"] or "{}")
                except (ValueError, TypeError): return None
        return None

    def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as con:
            row = con.execute("SELECT * FROM requests WHERE request_id=? OR exchange_id=? LIMIT 1", (str(request_id), str(request_id))).fetchone()
            if not row: return None
            item = dict(row)
            headers = con.execute("SELECT name,value FROM request_headers WHERE request_id=? ORDER BY position", (row["request_id"],)).fetchall()
            params = con.execute("SELECT name,location,value,redacted FROM request_parameters WHERE request_id=? ORDER BY id", (row["request_id"],)).fetchall()
        item["headers"] = [dict(x) for x in headers]
        item["parameters"] = [dict(x) for x in params]
        return item

    def get_response(self, response_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as con:
            row = con.execute("SELECT * FROM responses WHERE response_id=? OR request_id=? LIMIT 1", (str(response_id), str(response_id))).fetchone()
            if not row: return None
            item = dict(row)
            headers = con.execute("SELECT name,value FROM response_headers WHERE response_id=? ORDER BY position", (row["response_id"],)).fetchall()
            cookies = con.execute("SELECT cookie_name,cookie_value,attributes_json FROM response_cookies WHERE response_id=? ORDER BY id", (row["response_id"],)).fetchall()
        item["headers"] = [dict(x) for x in headers]
        item["cookies"] = [dict(x) for x in cookies]
        return item

    def get_endpoint_detail(self, identifier: str) -> Optional[Dict[str, Any]]:
        value = str(identifier or "").strip()
        with self._conn() as con:
            row = None
            if value.isdigit():
                row = con.execute("SELECT * FROM endpoints WHERE id=?", (int(value),)).fetchone()
            if row is None:
                row = con.execute("SELECT * FROM endpoints WHERE endpoint_id=?", (value,)).fetchone()
            if row is None and value:
                row = con.execute("SELECT * FROM endpoints WHERE url LIKE ? OR path LIKE ? ORDER BY id DESC LIMIT 1", (f"%{value}%", f"%{value}%")).fetchone()
            if row is None: return None
            item = dict(row)
            endpoint_id = item.get("endpoint_id")
            requests = con.execute("SELECT request_id,exchange_id,method,host,path,query,source,timestamp FROM requests WHERE endpoint_id=? ORDER BY timestamp DESC", (endpoint_id,)).fetchall() if endpoint_id else []
            tests = con.execute("SELECT test_run_id,test_id,status FROM test_runs WHERE scan_id=? AND (result_json LIKE ? OR result_json LIKE ?) ORDER BY rowid DESC", (item.get("scan_id"), f"%{item.get('path','')}%", f"%{item.get('url','')}%" )).fetchall()
            findings = con.execute("SELECT finding_id,title,status,severity FROM findings WHERE scan_id=? AND endpoint LIKE ?", (item.get("scan_id"), f"%{item.get('path','')}%" )).fetchall()
            parameter_count = con.execute("SELECT COUNT(*) FROM parameters WHERE scan_id=? AND endpoint_id=?", (item.get("scan_id"), endpoint_id)).fetchone()[0] if endpoint_id else 0
        from urllib.parse import urlsplit
        item["host"] = urlsplit(str(item.get("url") or "")).hostname or "Not recorded"
        item["requests"] = [dict(x) for x in requests]
        item["tests"] = [dict(x) for x in tests]
        item["findings"] = [dict(x) for x in findings]
        item["parameter_count"] = int(parameter_count)
        item["request_count"] = len(item["requests"])
        item["test_count"] = len(item["tests"])
        item["finding_count"] = len(item["findings"])
        return item

    def global_search(self, query: str, limit: int = 50) -> Dict[str, List[Dict[str, Any]]]:
        """Search normalized and compatibility records without exposing secrets."""
        q = f"%{str(query or '').strip().lower()}%"
        limit = max(1, min(int(limit), 200))
        out: Dict[str, List[Dict[str, Any]]] = {"endpoints": [], "requests": [], "responses": [], "parameters": [], "payloads": [], "findings": [], "evidence": [], "hosts": []}
        with self._conn() as con:
            out["endpoints"] = [dict(r) for r in con.execute("SELECT endpoint_id,scan_id,method,url,path,status FROM endpoints WHERE lower(url) LIKE ? OR lower(path) LIKE ? LIMIT ?", (q, q, limit))]
            out["requests"] = [dict(r) for r in con.execute("SELECT request_id,exchange_id,scan_id,method,host,path,source,timestamp FROM requests WHERE lower(path) LIKE ? OR lower(host) LIKE ? OR lower(body) LIKE ? LIMIT ?", (q, q, q, limit))]
            out["responses"] = [dict(r) for r in con.execute("SELECT response_id,request_id,scan_id,status_code,content_type,body_hash FROM responses WHERE lower(body) LIKE ? OR lower(content_type) LIKE ? LIMIT ?", (q, q, limit))]
            out["parameters"] = [dict(r) for r in con.execute("SELECT parameter_id,scan_id,name,location,endpoint FROM parameters WHERE lower(name) LIKE ? OR lower(endpoint) LIKE ? LIMIT ?", (q, q, limit))]
            out["payloads"] = [dict(r) for r in con.execute("SELECT payload_id,test_id,payload_type,payload FROM payloads WHERE lower(payload) LIKE ? OR lower(payload_type) LIKE ? LIMIT ?", (q, q, limit))]
            out["findings"] = [dict(r) for r in con.execute("SELECT finding_id,scan_id,title,severity,status,endpoint FROM findings WHERE lower(title) LIKE ? OR lower(endpoint) LIKE ? OR lower(category) LIKE ? LIMIT ?", (q, q, q, limit))]
            out["evidence"] = [dict(r) for r in con.execute("SELECT evidence_id,scan_id,finding_id,test_id,request_id,response_id FROM evidence WHERE lower(data_json) LIKE ? LIMIT ?", (q, limit))]
            out["hosts"] = [dict(r) for r in con.execute("SELECT host_id,scan_id,hostname,ip_address,source FROM hosts WHERE lower(hostname) LIKE ? OR lower(ip_address) LIKE ? LIMIT ?", (q, q, limit))]
        return out

    def record_audit(self, action: str, object_type: str = "", object_id: str = "", scan_id: str = "", result: str = "recorded", metadata: Any = None) -> int:
        with self._conn() as con:
            return record_audit_event(con, action=action, object_type=object_type, object_id=object_id, scan_id=scan_id, result=result, metadata=metadata)

    # ------------------------------------------------------------------
    def list_scans(self) -> List[Dict[str, Any]]:
        with self._conn() as con:
            rows=con.execute("SELECT scan_id,target,profile,started_at,finished_at,status,stats_json FROM scans ORDER BY started_at DESC").fetchall()
            endpoints={r["scan_id"]:r["n"] for r in con.execute("SELECT scan_id,COUNT(*) n FROM endpoints GROUP BY scan_id")}
            exchanges={r["scan_id"]:r["n"] for r in con.execute("SELECT scan_id,COUNT(*) n FROM exchanges GROUP BY scan_id")}
            findings={r["scan_id"]:r["n"] for r in con.execute("SELECT scan_id,COUNT(*) n FROM findings GROUP BY scan_id")}
            verified={r["scan_id"]:r["n"] for r in con.execute("SELECT scan_id,COUNT(*) n FROM findings WHERE upper(status)='VERIFIED' GROUP BY scan_id")}
            candidates={r["scan_id"]:r["n"] for r in con.execute("SELECT scan_id,COUNT(*) n FROM findings WHERE upper(status) IN ('CANDIDATE','CONFIRMED') GROUP BY scan_id")}
        out=[]
        for row in rows:
            item=dict(row)
            try: stats=json.loads(item.pop("stats_json") or "{}")
            except (ValueError,TypeError): stats={}
            item["requests_count"]=int(stats["requests_sent"] if "requests_sent" in stats else exchanges.get(item["scan_id"],0))
            item["endpoints_count"]=int(stats["endpoints_discovered"] if "endpoints_discovered" in stats else endpoints.get(item["scan_id"],0))
            item["findings_count"]=findings.get(item["scan_id"],0)
            item["verified_count"]=verified.get(item["scan_id"],0)
            item["candidates_count"]=candidates.get(item["scan_id"],0)
            out.append(item)
        return out

    def list_endpoints(self, scan_id: str = "", search: str = "", limit: int = 500, offset: int = 0) -> List[Dict[str, Any]]:
        clauses=[]; values=[]
        if scan_id: clauses.append("e.scan_id=?"); values.append(scan_id)
        if search: clauses.append("lower(e.url) LIKE ?"); values.append("%"+search.lower()+"%")
        where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
        with self._conn() as con:
            rows=con.execute("SELECT e.id,e.endpoint_id,e.scan_id,s.target,e.method,e.url,e.path,e.status,e.source,e.state_changing,e.auth_hint,e.content_type FROM endpoints e JOIN scans s ON s.scan_id=e.scan_id"+where+" ORDER BY e.id DESC LIMIT ? OFFSET ?",values+[max(1,min(int(limit),1000)),max(0,int(offset))]).fetchall()
        return [dict(row) for row in rows]

    def list_technologies(self, scan_id: str = "", search: str = "", limit: int = 500, offset: int = 0) -> List[Dict[str, Any]]:
        clauses=[]; values=[]
        if scan_id: clauses.append("t.scan_id=?"); values.append(scan_id)
        if search: clauses.append("lower(t.name) LIKE ?"); values.append("%"+search.lower()+"%")
        where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
        with self._conn() as con:
            rows=con.execute("SELECT t.scan_id,s.target,t.name,t.category,t.confidence,t.signals FROM technologies t JOIN scans s ON s.scan_id=t.scan_id"+where+" ORDER BY t.id DESC LIMIT ? OFFSET ?",values+[max(1,min(int(limit),1000)),max(0,int(offset))]).fetchall()
        out=[]
        for row in rows:
            item=dict(row)
            try: decoded=json.loads(item["signals"] or "[]")
            except (ValueError,TypeError): decoded=[]
            if isinstance(decoded,dict):
                all_samples=decoded.get("items",[]) if isinstance(decoded.get("items"),list) else []
                item["observations_count"]=decoded.get("observations_count",len(all_samples))
            elif isinstance(decoded,list):
                all_samples=decoded
                item["observations_count"]=len(decoded)
            else:
                all_samples=[];item["observations_count"]=0
            item["signals"]=all_samples[:8]
            item["evidence_samples_omitted"]=max(0,len(all_samples)-len(item["signals"]))
            out.append(item)
        return out

    def list_all_findings(self, scan_id: str = "", status: str = "", severity: str = "", search: str = "", limit: int = 500, offset: int = 0) -> List[Dict[str, Any]]:
        clauses=[]; values=[]
        if scan_id: clauses.append("f.scan_id=?"); values.append(scan_id)
        if status: clauses.append("upper(f.status)=?"); values.append(status.upper())
        if severity: clauses.append("upper(f.severity)=?"); values.append(severity.upper())
        if search: clauses.append("(lower(f.title) LIKE ? OR lower(f.endpoint) LIKE ? OR lower(f.category) LIKE ?)"); values.extend(["%"+search.lower()+"%"]*3)
        where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
        with self._conn() as con:
            rows=con.execute("SELECT f.scan_id,s.target,f.finding_id,f.title,f.category,f.severity,f.confidence,f.status,f.endpoint,f.parameter,f.source_plugin,f.data_json FROM findings f JOIN scans s ON s.scan_id=f.scan_id"+where+" ORDER BY f.id DESC LIMIT ? OFFSET ?",values+[max(1,min(int(limit),1000)),max(0,int(offset))]).fetchall()
        out=[]
        for row in rows:
            item=dict(row)
            try: detail=json.loads(item.pop("data_json") or "{}")
            except (ValueError,TypeError): detail={}
            normalized=self._normalize_finding_status(detail)
            indexed={k:row[k] for k in ("scan_id","target","finding_id","title","category","severity","confidence","status","endpoint","parameter","source_plugin")}
            item={**normalized,**indexed}
            item["stored_status"]=indexed["status"]
            item["status"]=normalized.get("status") or indexed["status"]
            if normalized.get("state"): item["state"]=normalized["state"]
            if normalized.get("legacy_status"): item["legacy_status"]=normalized["legacy_status"]
            out.append(item)
        return out

    def finding_state_counts(self) -> Dict[str, int]:
        with self._conn() as con:
            rows=con.execute("SELECT status,data_json FROM findings").fetchall()
        counts={}
        for row in rows:
            try: detail=json.loads(row["data_json"] or "{}")
            except (ValueError,TypeError): detail={}
            detail.setdefault("status",row["status"])
            normalized=self._normalize_finding_status(detail)
            state=str(normalized.get("state") or normalized.get("status") or row["status"] or "UNKNOWN").upper()
            counts[state]=counts.get(state,0)+1
        return counts

    def list_evidence(self, scan_id: str = "", finding_id: str = "", limit: int = 500, offset: int = 0) -> List[Dict[str, Any]]:
        clauses=[]; values=[]
        if scan_id: clauses.append("e.scan_id=?"); values.append(scan_id)
        if finding_id: clauses.append("e.finding_id=?"); values.append(finding_id)
        where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
        with self._conn() as con:
            rows=con.execute("SELECT e.evidence_id,e.scan_id,s.target,e.finding_id,e.test_id,e.data_json FROM evidence e JOIN scans s ON s.scan_id=e.scan_id"+where+" ORDER BY e.rowid DESC LIMIT ? OFFSET ?",values+[max(1,min(int(limit),1000)),max(0,int(offset))]).fetchall()
        out=[]
        for row in rows:
            item=dict(row)
            try: item["evidence"]=json.loads(item.pop("data_json") or "{}")
            except (ValueError,TypeError): item["evidence"]={}
            out.append(item)
        return out

    @staticmethod
    def _normalize_finding_status(doc):
        status=str(doc.get("status",""))
        if status.lower()=="confirmed":
            doc["legacy_status"]=status
            doc["status"]="CANDIDATE"
            doc["state"]="CANDIDATE"
        elif status.lower()=="candidate":
            doc["status"]="CANDIDATE"; doc.setdefault("state","CANDIDATE")
        elif status.upper()=="VERIFIED":
            doc["status"]="VERIFIED"; doc["state"]="VERIFIED"
        return doc

    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        with self._conn() as con:
            rows = con.execute(
                "SELECT data_json FROM findings WHERE scan_id=? ORDER BY confidence DESC",
                (scan_id,)).fetchall()
        return [self._normalize_finding_status(json.loads(r["data_json"])) for r in rows]

    def get_report(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as con:
            row = con.execute("SELECT report_json FROM scan_documents WHERE scan_id=?", (scan_id,)).fetchone()
        return json.loads(row["report_json"]) if row else None

    def get_scan_bundle(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Load stored, scan-ID-scoped data without exposing a database path."""
        scan=self.get_scan(scan_id)
        if scan is None:
            return None
        report=self.get_report(scan_id) or {}
        history=self.list_exchanges(scan_id=scan_id,limit=1000,offset=0)
        exchanges=[]
        for item in history:
            full=self.get_exchange(item.get("exchange_id",""))
            if full is not None:
                exchanges.append(full)
        return {
            "scan": scan,
            "report": report,
            "http_history": history,
            "exchanges": exchanges,
            "evidence_records": self.list_evidence(scan_id=scan_id,limit=1000,offset=0),
            "events": self.list_scan_events(scan_id,limit=10000),
        }

    def append_browser_capture(self, scan_id: str, capture: Dict[str, Any],
                               workflow_validation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Persist pre-redacted HAR observations into an existing completed scan."""
        scan=self.get_scan(scan_id)
        if not scan:
            raise ValueError("Browser capture import requires an existing scan with a stored report.")
        if str(scan.get("status","")).lower()=="running":
            raise ValueError("Browser capture cannot be attached while the scan is running.")
        report=self.get_report(scan_id)
        if report is None:
            raise ValueError("Browser capture import requires an existing scan with a stored report.")
        capture_id=str(capture.get("capture_id") or "")
        if not capture_id:
            raise ValueError("Capture ID is required.")
        imports=report.setdefault("browser_capture_imports",[])
        if any(item.get("capture_id")==capture_id for item in imports if isinstance(item,dict)):
            raise ValueError("This browser capture has already been imported into the scan.")
        exchanges=capture.get("exchanges",[])
        if not isinstance(exchanges,list): raise ValueError("Capture exchanges must be a list.")
        for exchange in exchanges:
            if not isinstance(exchange,dict) or exchange.get("module")!="browser-capture":
                raise ValueError("Only normalized browser-capture exchange records can be imported.")
            exchange["scan_id"]=scan_id
            self.record_exchange(scan_id,exchange,redact=True)
        from ..engine.browser_capture import correlate_capture_workflow
        workflow=correlate_capture_workflow(report.get("workflow_model",{}),exchanges)
        item={"capture_id":capture_id,"source_format":capture.get("source_format","HAR 1.2"),
              "imported_at":time.time(),"summary":capture.get("summary",{}),
              "body_policy":"OMITTED","exchange_ids":[str(x.get("exchange_id","")) for x in exchanges]}
        imports.append(item)
        report.setdefault("workflow_capture_observations",[]).append({"capture_id":capture_id,**workflow})
        if workflow_validation is not None:
            report.setdefault("configured_workflow_capture_validations",[]).append({"capture_id":capture_id,**workflow_validation})
        summary=report.setdefault("capture_summary",{})
        summary["imports_total"]=len(imports)
        summary["exchanges_imported"]=sum(int(x.get("summary",{}).get("imported",0)) for x in imports if isinstance(x,dict))
        with self._conn() as con:
            con.execute("UPDATE scan_documents SET report_json=? WHERE scan_id=?",
                        (json.dumps(redact_any(report),ensure_ascii=False),scan_id))
        return {"capture_import":item,"workflow_observations":workflow}

    def get_evidence_chain(self, finding_id: str) -> List[Dict[str, Any]]:
        resolved = str(finding_id or "")
        with self._conn() as con:
            rows = con.execute("SELECT evidence_id,test_id,data_json FROM evidence WHERE finding_id=?", (resolved,)).fetchall()
            if not rows and resolved.isdigit():
                match = con.execute("SELECT finding_id FROM findings WHERE id=?", (int(resolved),)).fetchone()
                if match:
                    resolved = str(match[0])
                    rows = con.execute("SELECT evidence_id,test_id,data_json FROM evidence WHERE finding_id=?", (resolved,)).fetchall()
        out=[]
        for row in rows:
            item={"evidence_id":row["evidence_id"],"test_id":row["test_id"],"evidence":json.loads(row["data_json"])}
            if row["test_id"]:
                with self._conn() as con:
                    test=con.execute("SELECT data_json FROM tests WHERE test_id=?",(row["test_id"],)).fetchone()
                item["test"]=json.loads(test["data_json"]) if test else None
                if test:
                    td=item["test"]
                    exchange_ids=[]
                    def collect_exchange_ids(value):
                        if isinstance(value, dict):
                            for key, child in value.items():
                                if str(key).endswith("exchange_id") and child:
                                    exchange_ids.append(str(child))
                                elif str(key) == "exchange_ids" and isinstance(child, list):
                                    exchange_ids.extend(str(x) for x in child if x)
                                elif isinstance(child, (dict, list)):
                                    collect_exchange_ids(child)
                        elif isinstance(value, list):
                            for child in value: collect_exchange_ids(child)
                    collect_exchange_ids(td)
                    item["exchanges"]=[]
                    for exchange_id in dict.fromkeys(exchange_ids):
                        with self._conn() as con:
                            ex=con.execute("SELECT data_json FROM exchanges WHERE exchange_id=?",(exchange_id,)).fetchone()
                        if ex: item["exchanges"].append(json.loads(ex["data_json"]))
            out.append(item)
        return out

    def list_exchanges(self, scan_id: str = "", method: str = "", host: str = "", endpoint: str = "",
                       status: Optional[int] = None, limit: int = 100, offset: int = 0,
                       module: str = "", has_error: Optional[bool] = None,
                       parent_exchange_id: str = "") -> List[Dict[str, Any]]:
        clauses=[]; values=[]
        if scan_id: clauses.append("scan_id=?"); values.append(scan_id)
        if method: clauses.append("upper(method)=?"); values.append(method.upper())
        if host: clauses.append("lower(url) LIKE ?"); values.append("%://"+host.lower()+"%")
        if endpoint: clauses.append("lower(url) LIKE ?"); values.append("%"+endpoint.lower()+"%")
        if status is not None: clauses.append("status=?"); values.append(int(status))
        if module: clauses.append("lower(module)=?"); values.append(module.strip().lower())
        if parent_exchange_id: clauses.append("json_extract(data_json,'$.parent_exchange_id')=?"); values.append(parent_exchange_id)
        if has_error is True: clauses.append("coalesce(json_extract(data_json,'$.error'),'')!=''")
        elif has_error is False: clauses.append("coalesce(json_extract(data_json,'$.error'),'')=''")
        where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
        limit=max(1,min(int(limit),1000)); offset=max(0,int(offset))
        query=("SELECT exchange_id,scan_id,method,url,status,module,data_json FROM exchanges"+where+
               " ORDER BY id DESC LIMIT ? OFFSET ?")
        values.extend([limit,offset])
        with self._conn() as con:
            rows=con.execute(query,values).fetchall()
        out=[]
        for row in rows:
            try: detail=json.loads(row["data_json"] or "{}")
            except (ValueError,TypeError): detail={}
            exchange_id=row["exchange_id"] or ""
            out.append({"exchange_id":exchange_id,"scan_id":row["scan_id"],
                "request_id":detail.get("request_id",f"{exchange_id}:request"),
                "response_id":detail.get("response_id",f"{exchange_id}:response"),
                "parent_exchange_id":detail.get("parent_exchange_id",""),
                "method":row["method"],"url":row["url"],"status":row["status"],
                "module":row["module"],"error":detail.get("error"),
                "duration_ms":detail.get("duration_ms",0),
                "request_bytes":len(detail.get("request_body","") or ""),
                "response_bytes":len(detail.get("response_body","") or "")})
        return out

    def get_exchange(self, exchange_id: str) -> Optional[Dict[str, Any]]:
        value = str(exchange_id or "").strip()
        with self._conn() as con:
            row=con.execute("SELECT scan_id,data_json FROM exchanges WHERE exchange_id=? ORDER BY id DESC LIMIT 1",(value,)).fetchone()
            if row is None and value.isdigit():
                row=con.execute("SELECT scan_id,data_json FROM exchanges WHERE id=?",(int(value),)).fetchone()
                if row is None:
                    row=con.execute("SELECT scan_id,data_json FROM exchanges ORDER BY id DESC LIMIT 1 OFFSET ?",(max(0,int(value)-1),)).fetchone()
            if row is None:
                row=con.execute("SELECT scan_id,data_json FROM exchanges WHERE json_extract(data_json,'$.request_id')=? OR json_extract(data_json,'$.response_id')=? ORDER BY id DESC LIMIT 1",(value,value)).fetchone()
        if not row: return None
        try:
            data=json.loads(row["data_json"] or "{}")
            data.setdefault("scan_id",row["scan_id"])
            data.setdefault("request_id",f"{exchange_id}:request")
            data.setdefault("response_id",f"{exchange_id}:response")
            return data
        except (ValueError,TypeError): return None

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        value = str(finding_id or "").strip()
        with self._conn() as con:
            row = con.execute("SELECT finding_id,data_json FROM findings WHERE finding_id=?", (value,)).fetchone()
            if row is None and value.isdigit():
                row = con.execute("SELECT finding_id,data_json FROM findings WHERE id=?", (int(value),)).fetchone()
        if not row: return None
        doc = self._normalize_finding_status(json.loads(row["data_json"]))
        doc.setdefault("finding_id", row["finding_id"])
        return doc

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as con:
            row = con.execute("SELECT scan_id,target,profile,started_at,finished_at,status,scope_json FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        if not row: return None
        item=dict(row)
        try: item["scope_policy"]=json.loads(item.pop("scope_json") or "{}")
        except (ValueError,TypeError): item["scope_policy"]={}
        return item

    def get_endpoints(self, scan_id: str) -> List[Dict[str, Any]]:
        with self._conn() as con:
            rows = con.execute(
                "SELECT method,url,path,status,source,state_changing FROM endpoints WHERE scan_id=?",
                (scan_id,)).fetchall()
        return [dict(r) for r in rows]
