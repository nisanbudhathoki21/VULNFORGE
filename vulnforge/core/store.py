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
            if version<SCHEMA_VERSION:
                con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    # ------------------------------------------------------------------
    def start_scan_record(self, scan_id: str, target: str, profile: str, started_at: float) -> None:
        """Create a durable RUNNING row so HTTP exchanges can be browsed live."""
        with self._conn() as con:
            con.execute("INSERT OR REPLACE INTO scans(scan_id,target,profile,started_at,finished_at,status,stats_json,scope_json,audit_json) VALUES (?,?,?,?,?,?,?,?,?)",
                (scan_id,redact_any(target),profile,started_at,None,"running","{}","{}","{}"))

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
            con.execute("INSERT INTO exchanges(exchange_id,scan_id,method,url,status,module,redirect_json,data_json) VALUES (?,?,?,?,?,?,?,?)",
                (exchange_id,scan_id,doc.get("method","GET"),stored_url,doc.get("status",0),
                 doc.get("module",""),json.dumps(redirect_data),json.dumps(doc)))

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

    # ------------------------------------------------------------------
    def save_scan(self, scan) -> None:
        """scan is engine.orchestrator.ScanResult (kept duck-typed)."""
        ctx = scan.context
        from ..report.json_report import build_report_dict
        report_doc = build_report_dict(scan)
        with self._conn() as con:
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
            for ep in ctx.endpoints.values():
                con.execute(
                    "INSERT INTO endpoints (scan_id,method,url,normalized,path,status,source,state_changing,auth_hint,content_type,data_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (ctx.scan_id, ep.method, redact_any(ep.url), redact_any(ep.normalized), redact_any(ep.path), ep.status,
                     ep.source, int(ep.state_changing), ep.auth_hint, ep.content_type,
                     json.dumps(redact_any(ep.to_dict()))))
            for p in ctx.parameters.values():
                con.execute(
                    "INSERT INTO parameters (scan_id,endpoint,method,name,location,type_hint,classifications,source,example) VALUES (?,?,?,?,?,?,?,?,?)",
                    (ctx.scan_id, redact_any(p.endpoint_url), p.method, p.name, p.location,
                     p.type_hint, json.dumps(redact_any(p.classifications)), p.source, redact_any(p.example)))
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
                con.execute("INSERT INTO exchanges(exchange_id,scan_id,method,url,status,module,redirect_json,data_json) VALUES (?,?,?,?,?,?,?,?)",
                    (ex.exchange_id, ctx.scan_id, ex.method, stored_url, ex.status, ex.module,
                     json.dumps(redirects), json.dumps(exchange_doc)))
            intel = getattr(ctx, "intelligence", {})
            dns = intel.get("dns", {})
            for typ in ("A", "AAAA"):
                for val in dns.get(typ, []):
                    con.execute("INSERT INTO dns_observations(scan_id,hostname,record_type,value,source) VALUES (?,?,?,?,?)",
                                (ctx.scan_id, dns.get("hostname", ""), typ, val, "system resolver"))
            con.execute("INSERT INTO scan_documents(scan_id,report_json) VALUES (?,?)",
                        (ctx.scan_id, json.dumps(redact_any(report_doc))))

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
            rows=con.execute("SELECT e.scan_id,s.target,e.method,e.url,e.path,e.status,e.source,e.state_changing,e.auth_hint,e.content_type FROM endpoints e JOIN scans s ON s.scan_id=e.scan_id"+where+" ORDER BY e.id DESC LIMIT ? OFFSET ?",values+[max(1,min(int(limit),1000)),max(0,int(offset))]).fetchall()
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
        with self._conn() as con:
            rows = con.execute("SELECT evidence_id,test_id,data_json FROM evidence WHERE finding_id=?", (finding_id,)).fetchall()
        out=[]
        for row in rows:
            item={"evidence_id":row["evidence_id"],"test_id":row["test_id"],"evidence":json.loads(row["data_json"])}
            if row["test_id"]:
                with self._conn() as con:
                    test=con.execute("SELECT data_json FROM tests WHERE test_id=?",(row["test_id"],)).fetchone()
                item["test"]=json.loads(test["data_json"]) if test else None
                if test:
                    td=item["test"]
                    exchange_ids=[td.get("baseline_exchange_id"),td.get("cross_account_exchange_id"),td.get("repeat_exchange_id")]
                    item["exchanges"]=[]
                    for exchange_id in filter(None,exchange_ids):
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
        with self._conn() as con:
            row=con.execute("SELECT scan_id,data_json FROM exchanges WHERE exchange_id=? ORDER BY id DESC LIMIT 1",(exchange_id,)).fetchone()
        if not row: return None
        try:
            data=json.loads(row["data_json"] or "{}")
            data.setdefault("scan_id",row["scan_id"])
            data.setdefault("request_id",f"{exchange_id}:request")
            data.setdefault("response_id",f"{exchange_id}:response")
            return data
        except (ValueError,TypeError): return None

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as con:
            row = con.execute("SELECT data_json FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        return self._normalize_finding_status(json.loads(row["data_json"])) if row else None

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
