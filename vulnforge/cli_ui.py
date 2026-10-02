"""Terminal-only presentation adapters; the scan engine emits data, not UI text."""
from __future__ import annotations

import shutil
import sys
import time
import textwrap
from collections import deque
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

BANNER_ART = r"""██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚══════╝"""
SUBTITLE = "RED TEAM SECURITY ENGINE"


def banner_lines(width: int = 100) -> List[str]:
    """Return the full wordmark when it fits, otherwise a clean narrow fallback."""
    art = BANNER_ART.splitlines()
    if width < max(map(len, art)) + 2:
        return ["VULNFORGE", SUBTITLE]
    return [*art, "", SUBTITLE.center(max(map(len, art)))]


def print_banner(stream=None, *, color: bool = False, width: Optional[int] = None) -> None:
    import os
    color = bool(color) and "NO_COLOR" not in os.environ
    stream = stream or sys.stdout
    width = width or shutil.get_terminal_size((80, 24)).columns
    lines = banner_lines(width)
    for index, line in enumerate(lines):
        if color:
            code = "\033[1;36m" if index == len(lines) - 1 else "\033[1;34m"
            stream.write(f"{code}{line}\033[0m\n")
        else:
            stream.write(line + "\n")


def _timestamp() -> str:
    return datetime.now().astimezone().strftime("%H:%M:%S")


def _terminal_safe(value: Any) -> str:
    """Make untrusted scan/response text safe to write into a terminal."""
    text = str(value)
    return "".join(ch if ord(ch) >= 32 and ord(ch) != 127 else (" " if ord(ch) in (9, 10, 13) else "�") for ch in text)


def _display_url(url: str) -> str:
    from .core.redaction import redact_url_query_values
    return redact_url_query_values(str(url))


def _display_text(value: Any) -> str:
    import re
    from .core.redaction import redact_text
    text = redact_text(str(value))
    return re.sub(r"https?://\S+", lambda match: _display_url(match.group(0)), text, flags=re.I)


def _safe_path(url: str) -> str:
    try:
        parsed = urlsplit(str(url))
        path = parsed.path or "/"
        # Do not put query values (which may contain tokens) in the live display.
        return path[:88] + ("…" if len(path) > 88 else "")
    except Exception:
        return "/"


class LiveScanDashboard:
    """Small live view driven only by real events emitted by the engine."""
    def __init__(self, target: str, *, stream=None, tty: Optional[bool] = None,
                 color: Optional[bool] = None, clock=time.monotonic):
        self.target = _display_url(target)
        self.stream = stream or sys.stdout
        self.tty = self.stream.isatty() if tty is None else bool(tty)
        import os
        self.color = self.tty and "NO_COLOR" not in os.environ and (True if color is None else bool(color))
        self.clock = clock
        self.started = clock()
        self.status = "SCANNING"
        self.activity = "Starting authorized assessment"
        self.requests = 0
        self.responses = 0
        self.recent_http = deque(maxlen=5)
        self.activity_log = deque(maxlen=7)
        self.endpoints = None
        self.hosts = None
        self.parameters = None
        self.forms = None
        self.api_endpoints = None
        self.js_routes = None
        self.hypotheses = None
        self.tests = None
        self.controls = None
        self.differentials = None
        self.observations = None
        self.confirmed = None
        self.unconfirmed = None
        self.killed = None
        self.untestable = None
        self.latest_http = "No HTTP exchange recorded yet"
        self._started_display = False
        self.finished = False

    def __call__(self, kind: str, message: str, data: Dict[str, Any]) -> None:
        data = data if isinstance(data, dict) else {}
        if kind == "http-exchange":
            self.requests += 1
            if data.get("status") not in (None, "", 0):
                self.responses += 1
            self.recent_http.append({
                "time": _timestamp(), "method": str(data.get("method") or "HTTP"),
                "path": _safe_path(data.get("url", "")),
                "status": data.get("status") or "—",
                "size": data.get("response_chars"),
                "duration_ms": data.get("duration_ms"),
            })
            self.activity = "HTTP exchange recorded"
            self.latest_http = (f"{data.get('method','HTTP')} {_safe_path(data.get('url',''))[:28]} "
                                f"{data.get('status') or 'no response'} · "
                                f"{data.get('duration_ms','?')} ms · {data.get('response_chars','?')} ch")
            self._add_activity("HTTP", f"{data.get('method','HTTP')} {_safe_path(data.get('url',''))} → {data.get('status') or 'no response'}")
        elif kind == "stage-start":
            safe_message = _terminal_safe(_display_text(message))
            self.activity = safe_message
            self._add_activity("ACTIVE", safe_message)
        elif kind == "stage-done":
            safe_message = _terminal_safe(_display_text(message))
            self.activity = f"Completed: {safe_message}"
            self._add_activity("DONE", f"{safe_message} · {data.get('seconds','?')}s")
        elif kind in {"error", "crawl-error"}:
            safe_message = _terminal_safe(_display_text(message))
            self.activity = safe_message
            self._add_activity("ATTENTION", safe_message)
        elif kind == "stage":
            safe_message = _terminal_safe(_display_text(message))
            self.activity = safe_message
            self._add_activity("INFO", safe_message)
        elif kind == "crawl-progress":
            self.activity = "Crawling observed pages"
        if self.tty:
            self.draw()

    def _add_activity(self, tag: str, message: str) -> None:
        self.activity_log.append((_timestamp(), tag, message))

    def finish(self, context) -> None:
        from collections import Counter
        self.status = "STOPPED" if getattr(context, "stop_reason", "") else "COMPLETE"
        stats = getattr(context, "stats", None)
        self.requests = int(getattr(stats, "requests_sent", self.requests))
        self.responses = sum(1 for exchange in getattr(getattr(context, "requester", None), "exchanges", []) if getattr(exchange, "status", 0)) or min(self.requests, self.responses)
        asset_nodes = list(getattr(context, "asset_nodes", []))
        self.hosts = len({getattr(node, "value", "") for node in asset_nodes if getattr(node, "asset_type", "") in {"host", "hostname", "domain", "ip", "ip-address"} and getattr(node, "value", "")}) or 1
        self.endpoints = len(getattr(context, "endpoints", {}))
        self.parameters = len(getattr(context, "parameters", {}))
        endpoints = list(getattr(context, "endpoints", {}).values())
        self.forms = sum(1 for endpoint in endpoints if getattr(endpoint, "source", "") == "form")
        self.api_endpoints = sum(1 for endpoint in endpoints if getattr(endpoint, "source", "") in {"api", "api-schema", "openapi"} or "/api/" in getattr(endpoint, "path", ""))
        self.js_routes = sum(1 for endpoint in endpoints if "javascript" in getattr(endpoint, "source", "").lower() or "js" in getattr(endpoint, "source", "").lower())
        self.hypotheses = len(getattr(context, "hypotheses", []))
        self.tests = len(getattr(context, "tests", []))
        test_docs = getattr(context, "tests", [])
        self.controls = sum(1 for test in test_docs if isinstance(test, dict) and any("control" in str(key).lower() for key in test))
        self.differentials = sum(1 for test in test_docs if isinstance(test, dict) and any("diff" in str(key).lower() for key in test))
        findings = list(getattr(context, "findings", []))
        self.observations = sum(1 for finding in findings if getattr(finding, "status", "") not in {"VERIFIED", "REPRODUCED"})
        self.confirmed = sum(1 for finding in findings if getattr(finding, "status", "") == "VERIFIED")
        self.unconfirmed = sum(1 for finding in findings if getattr(finding, "status", "") in {"CANDIDATE", "OBSERVED", "SIGNAL", "REPRODUCED"})
        self.killed = sum(1 for finding in findings if getattr(finding, "status", "") == "KILLED")
        self.untestable = sum(1 for test in test_docs if isinstance(test, dict) and str(test.get("status", "")).upper() in {"BLOCKED", "UNTESTABLE", "SKIPPED"})
        self.activity = "Scan finished; records saved"
        self.finished = True
        if self.tty:
            self.draw()

    def _paint(self, text: str, color: str = "") -> str:
        if not self.color or not color:
            return text
        codes = {"blue": "1;34", "cyan": "1;36", "green": "1;32", "yellow": "1;33", "red": "1;31", "muted": "2;37"}
        return f"\033[{codes.get(color,'0')}m{text}\033[0m"

    def lines(self, width: Optional[int] = None) -> List[str]:
        width = width or shutil.get_terminal_size((80, 24)).columns
        inner = max(10, min(width, 110))
        out = []
        if inner >= max(map(len, BANNER_ART.splitlines())) + 2:
            out.extend(banner_lines(inner))
        else:
            out.append("VULNFORGE  /  RED TEAM SECURITY ENGINE")
        elapsed = max(0, int(self.clock() - self.started))
        out.append(f"TARGET  {self.target}")
        out.append(f"STATUS  {self.status}   ELAPSED  {elapsed // 60:02d}:{elapsed % 60:02d}   HTTP EXCHANGES  {self.requests}")
        if self.endpoints is not None:
            out.extend([
                "DISCOVERY",
                f"  Hosts       {self.hosts}   Endpoints {self.endpoints}   Parameters {self.parameters}   Forms {self.forms}",
                f"  API routes  {self.api_endpoints}   JavaScript routes {self.js_routes}",
                "HTTP TRAFFIC",
                f"  Requests sent {self.requests}   Responses received {self.responses}",
                "TESTING",
                f"  Observations {self.observations}   Hypotheses {self.hypotheses}   Tests {self.tests}   Controls {self.controls}   Differentials {self.differentials}",
                "VALIDATION",
                f"  Confirmed {self.confirmed}   Unconfirmed {self.unconfirmed}   Killed {self.killed}   Untestable {self.untestable}",
            ])
        out.append("")
        out.append("CURRENT ACTIVITY")
        out.append("  " + self.activity)
        out.append("")
        out.append("RECENT HTTP TRAFFIC  (query values hidden)")
        if not self.recent_http:
            out.append("  No HTTP exchange has been recorded yet.")
        else:
            out.append("  TIME      METHOD  PATH".ljust(min(inner, 78)) + " STATUS   CHARS   TIME")
            for item in self.recent_http:
                size = f"{item['size']} ch" if isinstance(item["size"], int) else "—"
                duration = f"{item['duration_ms']:.0f} ms" if isinstance(item["duration_ms"], (int, float)) else "—"
                line = f"  {item['time']}  {item['method']:<6}  {item['path']:<34} {item['status']!s:<7} {size:<8} {duration}"
                out.append(line[:inner])
        out.append("")
        out.append("LIVE ACTIVITY")
        for stamp, tag, text in list(self.activity_log)[-5:]:
            out.append(f"  {stamp}  {tag:<8} {text}"[:inner])
        out.append("")
        out.append("Detailed execution: --verbose   |   Interactive results: --interactive")
        return [line if len(line) <= inner else line[:max(0, inner - 1)] + "…" for line in out]

    def draw(self) -> None:
        """Draw one header, then update only one carriage-return status line."""
        if not self.tty:
            return
        width=max(40,shutil.get_terminal_size((80,24)).columns)
        if not self._started_display:
            print_banner(self.stream,color=self.color,width=width)
            self.stream.write(f"TARGET  {_terminal_safe(self.target)}\n")
            self.stream.write("LIVE SCAN · status updates in place; organized results follow\n")
            self._started_display=True
        elapsed=max(0,int(self.clock()-self.started))
        line=(f"{self.status} · {elapsed}s · {self.requests} HTTP · last: {self.latest_http} · {self.activity}")
        line=_terminal_safe(line)[:max(1,width-1)]
        self.stream.write("\r"+line.ljust(max(1,width-1)))
        if self.finished: self.stream.write("\n")
        self.stream.flush()


def _finding_state(finding) -> str:
    from .core.outcomes import finding_result_status
    data = finding.to_dict() if hasattr(finding, "to_dict") else finding
    return finding_result_status(data if isinstance(data, dict) else {})


def _path_only(url: str) -> str:
    return _safe_path(url)


def build_workbench_pages(result, store, report_paths: Dict[str, str]) -> Dict[str, List[str]]:
    """Build truthful, scrollable views from completed scan/store data."""
    ctx = result.context
    intel = getattr(ctx, "intelligence", {}) or {}
    stats = getattr(ctx, "stats", None)
    target = intel.get("target", {})
    technologies = list(getattr(ctx, "technologies", {}).values())
    exchanges = store.list_exchanges(scan_id=ctx.scan_id, limit=500, offset=0)
    findings = list(getattr(ctx, "findings", []))
    verified = sum(1 for f in findings if getattr(f, "status", "") == "VERIFIED")
    classes = list(getattr(ctx, "vulnerability_matrix", []))
    supported = sum(1 for row in classes if row.get("supported"))
    unsupported = sum(1 for row in classes if not row.get("supported"))
    started = getattr(stats, "started_at", 0) if stats else 0
    duration = max(0, (getattr(stats, "finished_at", time.time()) or time.time()) - started) if started else 0
    pages: Dict[str, List[str]] = {
        "Overview": [
            f"Target: {_display_url(target.get('final_url') or ctx.config.target)}",
            f"Status: {'STOPPED' if getattr(ctx,'stop_reason','') else 'COMPLETE'}",
            f"Duration: {duration:.1f}s  ·  Requests: {getattr(stats,'requests_sent',0)}",
            f"Endpoints: {len(ctx.endpoints)}  ·  Parameters: {len(ctx.parameters)}  ·  Hypotheses: {len(ctx.hypotheses)}",
            f"Tests: {len(ctx.tests)}  ·  Confirmed: {verified}  ·  Candidates/observations: {sum(1 for f in findings if f.status!='VERIFIED')}",
            f"Registered classes supported: {supported}  ·  unsupported: {unsupported}",
            f"Reports: {', '.join(report_paths.values()) if report_paths else 'Not generated'}",
            "Only persisted scan data is shown; no progress percentage or asset value is invented.",
        ],
        "Recon": [], "Traffic": [], "Endpoints": [], "Technologies": [],
        "APIs & Auth": [], "Hypotheses": [], "Tests": [], "Findings": [], "Evidence": [], "Reports": [],
    }
    dns = intel.get("dns", {})
    pages["Recon"].append(f"Observed DNS addresses: {', '.join(dns.get('observed_addresses', [])) or 'Unknown / not observed'}")
    for service in intel.get("services", []):
        pages["Recon"].append(f"Service: {_display_url(service.get('url',''))} · status {service.get('status','Unknown')} · source {service.get('source','observed')}")
    if not intel.get("services"):
        pages["Recon"].append("No HTTP service result was recorded.")
    for name, data in intel.items():
        if any(tag in name.lower() for tag in ("waf", "cdn", "tls", "server", "infrastructure")) and isinstance(data, dict):
            pages["Recon"].append(f"{name}: {data.get('status') or data.get('vendor') or 'Unknown'}")
    for tech in technologies:
        pages["Technologies"].append(f"{tech.name} · {tech.category} · {tech.confidence} confidence · {', '.join(tech.signals[:4])}")
    if not technologies:
        pages["Technologies"].append("No technology fingerprint was supported by collected evidence.")
    for api in getattr(ctx, "api_inventory", []):
        pages["APIs & Auth"].append(f"API: {_display_url(api.get('url') or api.get('endpoint',''))} · {api.get('status','observed')}")
    auth = intel.get("authentication", {})
    pages["APIs & Auth"].append(f"Authentication signals: {auth.get('status','Unknown')} · MFA: {intel.get('mfa',{}).get('status','Unknown')}")
    for row in exchanges:
        pages["Traffic"].append(f"{row.get('exchange_id','')} · {row.get('method','')} · {_path_only(row.get('url',''))} · {row.get('status') or 'NO RESPONSE'} · {row.get('response_bytes',0)} B · {row.get('duration_ms',0)} ms · {row.get('module','')}")
    if not exchanges:
        pages["Traffic"].append("No stored HTTP exchanges for this scan.")
    for endpoint in getattr(ctx, "endpoints", {}).values():
        pages["Endpoints"].append(f"{endpoint.method} {endpoint.path} · HTTP {endpoint.status or 'not recorded'} · {endpoint.source} · {endpoint.scope_status}")
    if not pages["Endpoints"]:
        pages["Endpoints"].append("No endpoints were recorded.")
    for hypothesis in ctx.hypotheses:
        pages["Hypotheses"].append(f"{hypothesis.status} · {hypothesis.category} · {_path_only(hypothesis.endpoint)}? · {hypothesis.reason}")
    if not pages["Hypotheses"]:
        pages["Hypotheses"].append("No hypotheses were generated.")
    for test in ctx.tests:
        from .core.outcomes import test_result_status
        pages["Tests"].append(f"{test_result_status(test)} · {test.get('type','test')} · {_path_only(test.get('endpoint',''))} · {test.get('reason','')}")
    for plan in ctx.test_plan:
        pages["Tests"].append(f"PLAN {plan.status} · {plan.test_type} · {_path_only(plan.endpoint)} · up to {plan.request_cost} requests")
    if not pages["Tests"]:
        pages["Tests"].append("No controlled test ran; consult coverage for unsupported classes.")
    for finding in findings:
        pages["Findings"].append(f"{_finding_state(finding)} · {finding.severity.upper()} · {finding.confidence:.0%} · {finding.title} · {_path_only(finding.endpoint)}")
    if not findings:
        pages["Findings"].append("No finding or observation records were stored.")
    for finding in findings:
        for evidence in finding.evidence:
            summary = getattr(evidence, "description", "") or getattr(evidence, "response_summary", "Evidence")
            pages["Evidence"].append(f"{finding.id} · {finding.title} · {summary}")
    if not pages["Evidence"]:
        pages["Evidence"].append("No finding evidence records were stored.")
    for kind, path in report_paths.items():
        pages["Reports"].append(f"{kind.upper()}: {path}")
    return pages


def _exchange_view(store, exchange_id: str, side: str) -> List[str]:
    exchange = store.get_exchange(exchange_id)
    if not exchange:
        return ["Exchange is no longer available in the selected scan database."]
    if side == "request":
        request_url=_display_url(exchange.get('url',''))
        parsed=urlsplit(request_url)
        request_target=parsed.path or "/"
        if parsed.query: request_target+="?"+parsed.query
        start = f"{exchange.get('method','GET')} {request_target} {exchange.get('request_version','HTTP/1.1')}"
        header_items = exchange.get("request_header_items") or list((exchange.get("request_headers") or {}).items())
        body=exchange.get("request_body") or "[No request body stored]"
        lines = [start, *[_display_text(f"{k}: {v}") for k, v in header_items], "", _display_text(body)]
    else:
        status = exchange.get("status") or "No response"
        lines = [f"{exchange.get('response_version','HTTP/1.1')} {status} {exchange.get('reason_phrase','')}"]
        header_items = exchange.get("response_header_items") or list((exchange.get("response_headers") or {}).items())
        lines.extend(_display_text(f"{k}: {v}") for k, v in header_items)
        body=exchange.get("response_body") or "[No response body stored]"
        lines.extend(["", _display_text(body),
                      f"Duration: {exchange.get('duration_ms',0)} ms · exchange {exchange_id}"])
    return [str(line) for line in lines]


def run_results_workbench(result, store, report_paths: Dict[str, str]) -> bool:
    """Post-scan, keyboard-navigable result workbench; returns False on fallback."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Interactive workbench requires a TTY; showing the compact scan summary instead.")
        return False
    try:
        import curses
    except ImportError:
        print("Interactive workbench unavailable in this Python build; use the compact summary or web dashboard.")
        return False
    try:
        pages = build_workbench_pages(result, store, report_paths)
        traffic_rows = store.list_exchanges(scan_id=result.context.scan_id, limit=500, offset=0)
        page_names = list(pages)
        state = {"page": 0, "offset": 0, "query": "", "traffic_index": 0, "inspector": "request"}

        def draw(screen):
            screen.erase()
            height, width = screen.getmaxyx()
            width = max(20, width)
            title = f"VULNFORGE  /  {_display_url(result.context.config.target)}  /  {page_names[state['page']].upper()}"
            _safe_add(screen, 0, 0, title, width - 1, curses.A_BOLD)
            _safe_add(screen, 1, 0, "←/→ or Tab: view   ↑/↓: move   /: search   Enter: request/response   q: exit", width - 1)
            name = page_names[state["page"]]
            lines = list(pages[name])
            if name == "Traffic" and traffic_rows:
                index = max(0, min(state["traffic_index"], len(traffic_rows) - 1))
                selected = traffic_rows[index]
                lines = [f"{i+1:03d}  {row.get('method')}  {_path_only(row.get('url',''))}  {row.get('status') or 'NO RESPONSE'}  {row.get('duration_ms',0)} ms" for i,row in enumerate(traffic_rows)]
                lines.insert(0, f"Stored exchanges: {len(traffic_rows)} (latest page) · selected {index+1}/{len(traffic_rows)}")
                lines += ["", f"Selected exchange: {selected.get('exchange_id')} · press Enter to toggle request/response detail", ""]
                lines.extend(_exchange_view(store, selected.get("exchange_id", ""), state["inspector"]))
            if state["query"]:
                lines = [line for line in lines if state["query"].lower() in line.lower()]
            visible = max(0, height - 4)
            start = max(0, min(state["offset"], max(0, len(lines) - visible)))
            for row, line in enumerate(lines[start:start + visible], 2):
                _safe_add(screen, row, 0, line, width - 1)
            footer = f"{name} · {len(lines)} line(s)" + (f" · filter: {state['query']}" if state["query"] else "")
            _safe_add(screen, height - 1, 0, footer, width - 1, curses.A_DIM)
            screen.refresh()

        def ui(screen):
            screen.keypad(True)
            screen.timeout(-1)
            if curses.has_colors():
                try:
                    curses.start_color(); curses.use_default_colors()
                    curses.init_pair(1, curses.COLOR_CYAN, -1)
                    curses.init_pair(2, curses.COLOR_BLUE, -1)
                    screen.bkgd(' ', curses.color_pair(2))
                except curses.error:
                    pass
            while True:
                draw(screen)
                key = screen.getch()
                height, _ = screen.getmaxyx()
                if key in (ord('q'), 27): return
                if key in (curses.KEY_RIGHT, 9): state["page"] = (state["page"] + 1) % len(page_names); state["offset"] = 0
                elif key == curses.KEY_LEFT: state["page"] = (state["page"] - 1) % len(page_names); state["offset"] = 0
                elif key in (curses.KEY_DOWN, ord('j')):
                    if page_names[state["page"]] == "Traffic" and traffic_rows:
                        state["traffic_index"] = min(len(traffic_rows)-1, state["traffic_index"]+1)
                    else: state["offset"] += 1
                elif key in (curses.KEY_UP, ord('k')):
                    if page_names[state["page"]] == "Traffic" and traffic_rows:
                        state["traffic_index"] = max(0, state["traffic_index"]-1)
                    else: state["offset"] = max(0, state["offset"] - 1)
                elif key == curses.KEY_NPAGE: state["offset"] += max(1, height - 5)
                elif key == curses.KEY_PPAGE: state["offset"] = max(0, state["offset"] - max(1, height - 5))
                elif key == ord('/'):
                    curses.echo(); screen.timeout(-1)
                    _safe_add(screen, height - 1, 0, "Search: ", max(1, screen.getmaxyx()[1] - 1)); screen.refresh()
                    try: query = screen.getstr(height - 1, 8, 120).decode("utf-8", "replace")
                    except curses.error: query = ""
                    curses.noecho(); state["query"] = query; state["offset"] = 0
                elif key == 12: screen.clear()
                elif key in (curses.KEY_ENTER, 10, 13) and page_names[state["page"]] == "Traffic" and traffic_rows:
                    state["inspector"] = "response" if state["inspector"] == "request" else "request"
        curses.wrapper(ui)
        return True
    except (curses.error, OSError, ImportError):
        print("Interactive workbench unavailable in this terminal; use the stored reports or web dashboard.")
        return False



def _stored_record_text(record: Any) -> str:
    import json
    return _terminal_safe(_display_text(json.dumps(record, ensure_ascii=False, default=str)))


def _stored_rows(records: Any, empty: str) -> List[Dict[str, Any]]:
    return [item for item in records if isinstance(item, dict)] if isinstance(records, list) else []


def build_stored_scan_pages(bundle: Dict[str, Any]):
    """Build dashboard pages exclusively from records loaded for one scan ID."""
    report=bundle.get("report") or {}; scan=bundle.get("scan") or {}
    intel=report.get("intelligence",{}) or {}; dns=intel.get("dns",{}) or {}
    target=intel.get("target",{}) or {}
    nodes=_stored_rows(report.get("asset_nodes",[]),"")
    edges=_stored_rows(report.get("asset_edges",[]),"")
    services=_stored_rows(intel.get("services",[]),"")
    technologies=_stored_rows(report.get("technologies",[]),"")
    endpoints=_stored_rows(report.get("endpoints",[]),"")
    parameters=_stored_rows(report.get("parameters",[]),"")
    hypotheses=_stored_rows(report.get("hypotheses",[]),"")
    tests=_stored_rows(report.get("tests",[]),"")
    findings=_stored_rows(report.get("findings",[]),"")+_stored_rows(report.get("candidates",[]),"")
    exchanges=_stored_rows(bundle.get("exchanges",[]),"")
    evidence=_stored_rows(bundle.get("evidence_records",[]),"")
    events=_stored_rows(bundle.get("events",[]),"")
    observations=_stored_rows(report.get("discovery_signals",[]),"")+_stored_rows(report.get("live_observations",[]),"")
    plans=_stored_rows(report.get("test_plan",[]),"")
    controls=[]; differentials=[]
    def collect(obj,needle,out,owner=""):
        if isinstance(obj,dict):
            for key,value in obj.items():
                label=f"{owner}.{key}" if owner else str(key)
                if needle in str(key).lower(): out.append({"owner":owner,"field":label,"value":value})
                elif isinstance(value,(dict,list)): collect(value,needle,out,label)
        elif isinstance(obj,list):
            for index,value in enumerate(obj): collect(value,needle,out,f"{owner}[{index}]")
    for test in tests:
        owner=str(test.get("test_id") or test.get("type") or "test")
        collect(test,"control",controls,owner)
        collect(test,"differential",differentials,owner)
    for plan in plans:
        method=plan.get("methodology",{})
        if isinstance(method,dict):
            for control in method.get("negative_controls",[]) or []:
                controls.append({"owner":plan.get("test_id",plan.get("test_type","test plan")),
                                 "field":"planned negative control","value":control})
    hosts=[]
    if dns.get("hostname"):
        hosts.append({"hostname":dns.get("hostname"),"observed_addresses":dns.get("observed_addresses",[])})
    for node in nodes:
        if str(node.get("asset_type","")).lower() in {"host","hostname","domain","ip","ip-address"}:
            hosts.append(node)
    scan_doc=report.get("scan",{}) or {}
    stats=report.get("statistics",{}) or {}
    controls_data=report.get("request_controls",{}) or {}
    target_limit=report.get("target_rate_limit_observations",{}) or {}
    technology_groups={}
    for item in technologies:
        technology_groups.setdefault(str(item.get("category","unknown")).lower(),[]).append(item.get("name","Unknown"))
    waf=[str(item.get("name")) for item in technologies if str(item.get("category","")).lower()=="waf"]
    cdn=[str(item.get("name")) for item in technologies if str(item.get("category","")).lower()=="cdn"]
    servers=[str(item.get("name")) for item in technologies if str(item.get("category","")).lower()=="server"]
    front=[str(item.get("name")) for item in technologies if str(item.get("category","")).lower() in {"frontend","js-framework","build-tool"}]
    backend=[str(item.get("name")) for item in technologies if str(item.get("category","")).lower() in {"framework","language","runtime"}]
    auth=intel.get("authentication",{}) or {}; mfa=intel.get("mfa",{}) or {}; tls=intel.get("tls",{}) or {}
    pathmap=(scan_doc.get("report_paths",{}) or {})
    if not pathmap: pathmap=report.get("report_manifest",{}) or {}
    pages={
        "Overview":[
            f"Scan ID: {scan.get('scan_id','unknown')}",
            f"Target: {_display_url(scan_doc.get('target') or scan.get('target','unknown'))}",
            f"Status: {scan.get('status','unknown')} · profile: {scan.get('profile','unknown')}",
            f"Started: {time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(scan.get('started_at') or 0))}",
            f"Requests: {stats.get('requests_sent',0)} · endpoints: {len(endpoints)} · parameters: {len(parameters)}",
            f"Hypotheses: {len(hypotheses)} · tests: {len(tests)} · findings: {len(findings)}",
            "Every view is loaded from this scan ID's stored report and exchange rows.",
        ],
        "Recon":[f"Hostname: {target.get('hostname') or dns.get('hostname') or 'Not observed'}",
                 f"Observed addresses: {', '.join(dns.get('observed_addresses',[]) or []) or 'Not observed'}",
                 f"Redirect observations: {len(intel.get('redirects',[]) or [])}",
                 f"Authentication signals: {auth.get('status','NOT DETERMINED')} · MFA: {mfa.get('status','NOT DETERMINED')}",
                 f"API types observed: {', '.join((intel.get('api',{}) or {}).get('types_observed',[]) or []) or 'Not observed'}"],
        "Infrastructure":[f"CDN/edge fingerprints: {', '.join(cdn) if cdn else 'No matching passive signature observed'}",
                           f"WAF fingerprints: {', '.join(waf) if waf else 'No matching passive signature observed; absence is not established'}",
                           f"Web server fingerprints: {', '.join(servers) if servers else 'Not identified from responses'}",
                           f"TLS: {tls.get('status','NOT DETERMINED')} · {tls.get('reason','')}",
                           f"Scanner rate cap: {controls_data.get('configured_rate_limit_per_second') or 'not recorded'} req/s · request budget {controls_data.get('request_budget') or 'not recorded'}",
                           f"Target throttling signals: {target_limit.get('http_429_responses',0)} HTTP 429 · Retry-After on {target_limit.get('retry_after_responses',0)} response(s)"],
        "Hosts":[],"Services":[],"Technologies":[],"Endpoints":[],"Parameters":[],
        "HTTP History":[],"Requests":[],"Responses":[],"Observations":[],"Hypotheses":[],
        "Tests":[],"Controls":[],"Differentials":[],"Evidence":[],"Findings":[],"Events":[],"Reports":[],
    }
    selectable={"HTTP History":exchanges,"Requests":exchanges,"Responses":exchanges,
                "Hypotheses":hypotheses,"Tests":tests,"Controls":controls,
                "Differentials":differentials,"Evidence":evidence,"Findings":findings,"Events":events}
    if not hosts: pages["Hosts"].append("No host/address records were stored for this scan.")
    for item in hosts: pages["Hosts"].append(_stored_record_text(item))
    for item in services: pages["Services"].append(_stored_record_text(item))
    if not services: pages["Services"].append("No HTTP service records were stored.")
    if technologies:
        for item in technologies: pages["Technologies"].append(_stored_record_text(item))
    else:
        pages["Technologies"].append("No technology fingerprints matched collected evidence.")
    for item in endpoints: pages["Endpoints"].append(_stored_record_text(item))
    if not endpoints: pages["Endpoints"].append("No endpoints were stored.")
    for item in parameters: pages["Parameters"].append(_stored_record_text(item))
    if not parameters: pages["Parameters"].append("No parameters were stored.")
    for item in exchanges:
        method=item.get("method","HTTP"); url=_display_url(item.get("url",""))
        path=urlsplit(url).path or "/"
        row=f"{item.get('exchange_id','')} · {method} {path} · {item.get('status') or 'NO RESPONSE'} · {item.get('duration_ms',0)} ms · {item.get('module','')}"
        pages["HTTP History"].append(row)
        pages["Requests"].append(f"{item.get('request_id','')} · {method} {path} · {item.get('module','')}")
        pages["Responses"].append(f"{item.get('response_id','')} · {item.get('status') or 'NO RESPONSE'} · {item.get('duration_ms',0)} ms")
    for item in observations: pages["Observations"].append(_stored_record_text(item))
    if not observations: pages["Observations"].append("No discovery/live observation records were stored.")
    for item in hypotheses: pages["Hypotheses"].append(f"{item.get('hypothesis_id','')} · {item.get('status','UNKNOWN')} · {item.get('category','')} · {_display_url(item.get('endpoint',''))} · {item.get('reason','')}")
    if not hypotheses: pages["Hypotheses"].append("No hypotheses were stored.")
    for item in tests: pages["Tests"].append(f"{item.get('test_id','')} · {item.get('status','UNKNOWN')} · {item.get('type','test')} · hypothesis {item.get('hypothesis_id','none')} · {_display_url(item.get('endpoint',''))}")
    if not tests: pages["Tests"].append("No test records were stored.")
    for item in controls: pages["Controls"].append(_stored_record_text(item))
    if not controls: pages["Controls"].append("No distinct control records/fields were persisted for this scan.")
    for item in differentials: pages["Differentials"].append(_stored_record_text(item))
    if not differentials: pages["Differentials"].append("No differential records were persisted for this scan.")
    if not evidence: pages["Evidence"].append("No separate evidence rows were stored.")
    for item in findings: pages["Findings"].append(f"{item.get('id',item.get('finding_id',''))} · {item.get('status',item.get('state','UNKNOWN'))} · {str(item.get('severity','info')).upper()} · {item.get('title','Finding')}")
    if not findings: pages["Findings"].append("No finding or candidate records were stored.")
    for item in events:
        pages["Events"].append(f"{item.get('event_id','')} · {item.get('kind','unknown')} · {item.get('message','')}")
    if not events: pages["Events"].append("No persisted engine events are available for this scan.")
    if pathmap:
        for kind,path in pathmap.items(): pages["Reports"].append(f"{str(kind).upper()}: {path}")
    else:
        pages["Reports"].append("Report paths were not stored; export with --report.")
    if not pages["HTTP History"]: pages["HTTP History"].append("No HTTP exchanges were stored.")
    if not pages["Requests"]: pages["Requests"].append("No request records were stored.")
    if not pages["Responses"]: pages["Responses"].append("No response records were stored.")
    return pages,selectable,{"bundle":bundle,"report":report,"exchanges":exchanges,
        "hypotheses":hypotheses,"tests":tests,"findings":findings,"evidence":evidence}


def run_stored_scan_dashboard(scan_id: str, store) -> bool:
    """Open a navigable dashboard using only the saved records for scan_id."""
    bundle=store.get_scan_bundle(scan_id)
    if bundle is None:
        print(f"Error: scan ID not found: {scan_id}. Run `vulnforge results`.",file=sys.stderr)
        return False
    if not bundle.get("report"):
        print(f"Error: scan {scan_id} has no stored structured report.",file=sys.stderr)
        return False
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Interactive dashboard needs a TTY. Use `vulnforge <SCAN-ID> --database` for a text view.")
        return False
    try:
        import curses
    except ImportError:
        print("Interactive dashboard needs Python curses; use `vulnforge <SCAN-ID> --database` instead.",file=sys.stderr)
        return False
    try:
        import json
        pages,selectable,records=build_stored_scan_pages(bundle)
        names=list(pages); state={"page":0,"offset":0,"selection":0,"query":"","history_side":"request"}
        def current_items(name):
            items=selectable.get(name)
            if items is None: return None
            query=state["query"].lower()
            if query: return [item for item in items if query in _stored_record_text(item).lower()]
            return items
        def detail_lines(name,item):
            if item is None: return []
            if name in {"Requests","Responses","HTTP History"}:
                side=("request" if name=="Requests" else ("response" if name=="Responses" else state["history_side"]))
                return _exchange_view(store,str(item.get("exchange_id","")),side)
            if name=="Hypotheses":
                hypothesis_id=item.get("hypothesis_id","")
                related=[test for test in records["tests"] if test.get("hypothesis_id")==hypothesis_id]
                lines=["SELECTED HYPOTHESIS",*_pretty_json_lines(item),"",f"ASSOCIATED TESTS · {len(related)}"]
                for test in related: lines.extend(_pretty_json_lines(test))
                if not related: lines.append("No tests are linked to this hypothesis.")
                return lines
            if name=="Findings":
                finding_id=item.get("id",item.get("finding_id",""))
                related=[e for e in records["evidence"] if e.get("finding_id")==finding_id]
                lines=["SELECTED FINDING",*_pretty_json_lines(item),"",f"EVIDENCE CHAIN · {len(related)} stored evidence row(s)"]
                for evidence_item in related: lines.extend(_pretty_json_lines(evidence_item))
                if not related:
                    embedded=item.get("evidence",[]) or []
                    if embedded:
                        for evidence_item in embedded: lines.extend(_pretty_json_lines(evidence_item))
                    else: lines.append("No evidence rows were linked to this finding.")
                return lines
            return _pretty_json_lines(item)
        def draw(screen):
            screen.erase(); height,width=screen.getmaxyx(); width=max(20,width)
            page=names[state["page"]]
            _safe_add(screen,0,0,f"VULNFORGE · {scan_id} · {page.upper()}",width-1,curses.A_BOLD)
            _safe_add(screen,1,0,"←/→ or Tab: section · ↑/↓: select/scroll · Enter: inspect · /: search · q: exit",width-1)
            base=list(pages[page]); items=current_items(page)
            if items is not None:
                base=[]
                for i,item in enumerate(items): base.append(_selectable_label(page,item,i))
                if not items: base=["No records match this view/filter."]
            selection=state["selection"]
            item=(items[selection] if items and 0<=selection<len(items) else None) if items is not None else None
            if item is not None:
                base.extend(["","─ SELECTED RECORD · Enter details below ─"])
                base.extend(detail_lines(page,item))
            query=state["query"]
            if items is None and query: base=[line for line in base if query in line.lower()]
            visible=max(0,height-4); start=max(0,min(state["offset"],max(0,len(base)-visible)))
            for row,line in enumerate(base[start:start+visible],2):
                attr=curses.A_REVERSE if items is not None and row-2+start==selection else curses.A_NORMAL
                _safe_add(screen,row,0,line,width-1,attr)
            footer=f"{page} · {len(items) if items is not None else len(base)} record/line(s)"
            if query: footer+=f" · filter: {query}"
            _safe_add(screen,height-1,0,footer,width-1,curses.A_DIM); screen.refresh()
        def ui(screen):
            screen.keypad(True); screen.timeout(-1)
            while True:
                draw(screen); key=screen.getch(); height,_=screen.getmaxyx()
                if key in (ord('q'),27): return
                if key in (curses.KEY_RIGHT,9): state["page"]=(state["page"]+1)%len(names); state["offset"]=0; state["selection"]=0
                elif key==curses.KEY_LEFT: state["page"]=(state["page"]-1)%len(names); state["offset"]=0; state["selection"]=0
                elif key in (curses.KEY_DOWN,ord('j')):
                    items=current_items(names[state["page"]])
                    if items is not None: state["selection"]=min(max(0,len(items)-1),state["selection"]+1)
                    else: state["offset"]+=1
                elif key in (curses.KEY_UP,ord('k')):
                    items=current_items(names[state["page"]])
                    if items is not None: state["selection"]=max(0,state["selection"]-1)
                    else: state["offset"]=max(0,state["offset"]-1)
                elif key in (curses.KEY_NPAGE,curses.KEY_PPAGE):
                    delta=max(1,height-5)*(1 if key==curses.KEY_NPAGE else -1)
                    state["offset"]=max(0,state["offset"]+delta)
                elif key==ord('/'):
                    curses.echo(); _safe_add(screen,height-1,0,"Search: ",max(1,screen.getmaxyx()[1]-1)); screen.refresh()
                    try: query=screen.getstr(height-1,8,100).decode("utf-8","replace")
                    except curses.error: query=""
                    curses.noecho(); state["query"]=query.lower(); state["selection"]=0; state["offset"]=0
                elif key in (curses.KEY_ENTER,10,13):
                    page=names[state["page"]]
                    if page=="HTTP History": state["history_side"]="response" if state["history_side"]=="request" else "request"
                elif key==curses.KEY_RESIZE: screen.erase()
        curses.wrapper(ui)
        return True
    except (OSError,ImportError,curses.error) as exc:
        print(f"Interactive dashboard unavailable in this terminal: {exc}",file=sys.stderr)
        return False


def _selectable_label(page: str,item: Dict[str,Any],index: int) -> str:
    if page in {"HTTP History","Requests","Responses"}:
        return f"{index+1:04d} · {item.get('method','HTTP')} {_safe_path(item.get('url',''))} · {item.get('status') or 'NO RESPONSE'} · {item.get('exchange_id','')}"
    if page=="Hypotheses": return f"{index+1:04d} · {item.get('status','UNKNOWN')} · {item.get('category','')} · {item.get('hypothesis_id','')} · {item.get('reason','')}"
    if page=="Tests": return f"{index+1:04d} · {item.get('status','UNKNOWN')} · {item.get('type','test')} · {item.get('test_id','')}"
    if page=="Findings": return f"{index+1:04d} · {item.get('status',item.get('state','UNKNOWN'))} · {str(item.get('severity','info')).upper()} · {item.get('title','')}"
    return f"{index+1:04d} · {_stored_record_text(item)}"


def _pretty_json_lines(value: Any) -> List[str]:
    import json
    text=_display_text(json.dumps(_redact_json_urls(value),indent=2,ensure_ascii=False,default=str))
    return text.splitlines()


def _redact_json_urls(value: Any,key: str="") -> Any:
    if isinstance(value,dict): return {k:_redact_json_urls(v,str(k).lower()) for k,v in value.items()}
    if isinstance(value,list): return [_redact_json_urls(v,key) for v in value]
    if isinstance(value,str) and (key in {"url","target","endpoint","location","referer"} or key.endswith("_url")):
        return _display_url(value)
    return value

def _safe_add(screen, row: int, col: int, text: str, max_width: int, attr: int = 0) -> None:
    import curses
    if max_width <= 0:
        return
    try:
        screen.addnstr(max(0, row), max(0, col), _terminal_safe(text), max_width, attr)
    except curses.error:
        pass
