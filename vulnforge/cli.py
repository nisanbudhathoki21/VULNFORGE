"""VulnForge evidence-led assessment CLI."""
from __future__ import annotations
import argparse, ipaddress, json, math, os, shutil, signal, sys, time, uuid
import urllib.parse
from pathlib import Path
from urllib.parse import urlsplit
from .core.authorization import AuthorizationContext
from .core.profiles import PROFILES, get_profile
from .core.store import Store
from .engine.normalize import canonicalize
from .engine.orchestrator import ScanConfig, run_scan
from .report.json_report import write_json_report
from .report.renderers import write_html_report, write_markdown_report, write_pdf_report

DEFAULT_DB = os.environ.get("VULNFORGE_SCAN_DB_PATH", "vulnforge.db")

def resolve_profiles(profile_arg: str, safety_mode: str = "", severity_flag: str = ""):
    """Resolve priority portfolio separately from safety/resource controls."""
    from .engine.vulnerability_registry import PROFILE_NAMES as VULN_PROFILE_NAMES
    mode_profile={"PASSIVE":"passive","SAFE_ACTIVE":"safe-active",
                  "CONTROLLED_ACTIVE":"controlled-active","LAB":"lab"}
    if severity_flag and profile_arg in VULN_PROFILE_NAMES and profile_arg != severity_flag:
        raise ValueError("Choose only one severity profile")
    test_profile=severity_flag or (profile_arg if profile_arg in VULN_PROFILE_NAMES else
                                  ("passive" if profile_arg=="passive" else "full"))
    from .core.profiles import PROFILES
    resource_profile=profile_arg if profile_arg in PROFILES else "standard"
    return mode_profile.get(safety_mode,resource_profile),test_profile


def normalize_target(raw: str):
    original = raw
    value = raw.strip()
    if not value: raise ValueError("Target is required")
    if "://" not in value:
        hostpart=value.split("/",1)[0].split(":",1)[0].strip("[]")
        local=hostpart.lower() == "localhost"
        try: local = local or ipaddress.ip_address(hostpart).is_loopback
        except ValueError: pass
        value=("http" if local else "https") + "://" + value
    p=urlsplit(value)
    if p.scheme.lower() not in ("http","https") or not p.hostname: raise ValueError("Target must be a valid http(s) URL")
    if p.username or p.password: raise ValueError("Credentials in target URLs are not accepted")
    try: _=p.port
    except ValueError as ex: raise ValueError(f"Invalid target port: {ex}")
    return original, canonicalize(value, drop_tracking=False)


def build_parser():
    p=argparse.ArgumentParser(prog="vulnforge", description="Evidence-led web security assessment engine", epilog="Stored scans: vulnforge <SCAN-ID> --dashboard | --database | --report [--format html|pdf|json|md]")
    sub=p.add_subparsers(dest="command")
    s=sub.add_parser("scan", help="Run a scoped assessment; Full implemented portfolio is the default after authorization confirmation")
    s.add_argument("target", nargs="?", help="Target hostname or HTTP(S) URL; use `url <target>` as a compatibility form")
    s.add_argument("target_extra", nargs="?", help=argparse.SUPPRESS)
    s.add_argument("--url", dest="url", help="Target URL (legacy alias)")
    s.add_argument("--active", action="store_true", help="Compatibility flag; scans request the Full portfolio by default after authorization confirmation")
    s.add_argument("--rate", type=float, default=None, help="Maximum requests per second")
    s.add_argument("--max-requests", type=int, default=None, help="Request budget")
    s.add_argument("--timeout", type=float, default=10.0)
    s.add_argument("--scope", nargs="*", default=[], help="Host rules or one scope file: JSON/YAML policy, or .txt/.ips IP/CIDR allowlist (never a batch scan list)")
    s.add_argument("--auth", help="Optional JSON/YAML auth headers and explicit identity-test configuration")
    s.add_argument("--login", help="Optional JSON/YAML login-flow config: POST credentials once before scanning, reuse the resulting session for every request")
    from .engine.vulnerability_registry import PROFILE_NAMES as VULN_PROFILE_NAMES
    s.add_argument("--profile", default="standard", choices=sorted(set(PROFILES)|set(VULN_PROFILE_NAMES)),
                   help="Vulnerability priority profile (critical/high/medium/low/full) or legacy resource profile")
    severity_group=s.add_mutually_exclusive_group()
    for name in ("critical","high","medium","low","full"):
        severity_group.add_argument(f"--{name}",dest="severity_profile",action="store_const",const=name,
                                    help=f"Select the {name.title()} vulnerability portfolio")
    severity_group.add_argument("--all",dest="severity_profile",action="store_const",const="full",
                                help="Prioritize all implemented, applicable checks (alias for --full)")
    s.add_argument("--lab",action="store_true",help="Use loopback-only LAB safety mode")
    s.add_argument("--mode", choices=["PASSIVE","SAFE_ACTIVE","CONTROLLED_ACTIVE","LAB"], default=None,
                   help="Safety mode; active checks still require an implemented, configured test")
    s.add_argument("--allow-private", action="store_true", help=argparse.SUPPRESS)
    s.add_argument("--insecure", action="store_true", help="Disable TLS verification (not recommended)")
    s.add_argument("--yes", "-y", action="store_true", help="Confirm authorized testing in non-interactive mode")
    s.add_argument("--db", default=DEFAULT_DB)
    s.add_argument("--out", default="", help="Output directory (default: reports/<scan-id>)")
    output_group=s.add_mutually_exclusive_group()
    output_group.add_argument("--verbose", action="store_true", help="Show detailed execution stages and diagnostic messages")
    output_group.add_argument("--quiet", action="store_true", help="Show only scan outcome, confirmed findings, and report location")
    s.add_argument("--interactive", action="store_true", help="Open the keyboard-navigable results workbench after the scan")
    s.add_argument("--json", dest="json_output", action="store_true", help="Print the structured redacted report as JSON only")
    s.add_argument("--no-color", action="store_true")
    for name, helptext in [("tools","Show optional tool availability"),("status","Show recent scan status")]:
        q=sub.add_parser(name,help=helptext); q.add_argument("--db",default=DEFAULT_DB)
    q=sub.add_parser("lab",help="Start one synthetic loopback-only training lab")
    from labs.runtime import LEVELS as LAB_LEVELS
    q.add_argument("level",choices=tuple(LAB_LEVELS),help="critical (9001), high (9002), or medium (9003)")
    q.add_argument("--patched",action="store_true",help="run the paired patched/control behavior")
    q=sub.add_parser("dashboard",help="Start the local web dashboard backed by the canonical scan store")
    q.add_argument("--host",default="127.0.0.1",help="Bind host (default: loopback)")
    q.add_argument("--port",type=int,default=8000)
    q=sub.add_parser("scans",help="List scan history"); q.add_argument("--db",default=DEFAULT_DB)
    q=sub.add_parser("results",help="List recent saved scan results"); q.add_argument("--db",default=DEFAULT_DB)
    q=sub.add_parser("report",help="Export a stored scan report by scan ID or target"); q.add_argument("scan_id",metavar="SCAN_ID_OR_TARGET",help="Stored scan ID, hostname, or HTTP(S) URL"); q.add_argument("--db",default=DEFAULT_DB); q.add_argument("--out",default="reports"); q.add_argument("--format",choices=["all","html","pdf","json","md"],default="all")
    q=sub.add_parser("capture",help="Import offline browser-capture evidence")
    capture_sub=q.add_subparsers(dest="capture_command",required=True)
    imp=capture_sub.add_parser("import-har",help="Import a redacted, in-scope HAR into a stored completed scan")
    imp.add_argument("scan_id"); imp.add_argument("har_file")
    imp.add_argument("--confirm-authorized",action="store_true",help="Confirm this capture is authorized for the original scan scope")
    imp.add_argument("--workflow-spec",default="",help="Optional JSON transition assertions to check against this HAR (no replay)")
    imp.add_argument("--db",default=DEFAULT_DB)
    q=sub.add_parser("evidence",help="Inspect finding evidence"); q.add_argument("identifier"); q.add_argument("--db",default=DEFAULT_DB)
    q=sub.add_parser("resume",help="Restart an interrupted scan from its target"); q.add_argument("scan_id",nargs="?"); q.add_argument("--db",default=DEFAULT_DB)
    q=sub.add_parser("findings",help="List findings for a scan (latest scan by default)"); q.add_argument("scan_id",nargs="?"); q.add_argument("--db",default=DEFAULT_DB); q.add_argument("--format",choices=["table","json"],default="table")
    q=sub.add_parser("coverage",help="Show actual vulnerability/test coverage for a stored scan"); q.add_argument("scan_id",nargs="?"); q.add_argument("--db",default=DEFAULT_DB); q.add_argument("--format",choices=["table","json"],default="table")
    q=sub.add_parser("finding",help="Show one finding and its complete evidence chain"); q.add_argument("finding_id"); q.add_argument("--db",default=DEFAULT_DB); q.add_argument("--format",choices=["text","json"],default="text")
    q=sub.add_parser("endpoint",help="Show one endpoint and its requests, tests, and findings"); q.add_argument("endpoint_id"); q.add_argument("--db",default=DEFAULT_DB); q.add_argument("--format",choices=["text","json"],default="text")
    q=sub.add_parser("db",help="Inspect, migrate, back up, or count the canonical SQLite database")
    db_sub=q.add_subparsers(dest="db_action",required=True)
    for action in ("status","migrate","stats"):
        db_sub.add_parser(action,help=f"Database {action}").add_argument("--db",default=DEFAULT_DB)
    backup=db_sub.add_parser("backup",help="Create a consistent SQLite backup")
    backup.add_argument("destination",nargs="?",default="",help="Backup path (default: <db>.backup.sqlite)"); backup.add_argument("--db",default=DEFAULT_DB)
    q=sub.add_parser("search",help="Search endpoints, traffic, parameters, payloads, evidence, and findings"); q.add_argument("query"); q.add_argument("--db",default=DEFAULT_DB); q.add_argument("--limit",type=int,default=50); q.add_argument("--format",choices=["table","json"],default="table")
    q=sub.add_parser("export",help="Export stored HTTP traffic or a finding"); q.add_argument("kind",choices=["traffic","finding"]); q.add_argument("identifier"); q.add_argument("--format",choices=["raw","json","har","md"],default="json"); q.add_argument("--out",default=""); q.add_argument("--db",default=DEFAULT_DB)
    def add_history_parser(command, helptext):
        q=sub.add_parser(command,help=helptext)
        q.add_argument("scan_id_pos",nargs="?",help="Optional scan ID to filter")
        q.add_argument("--scan-id",dest="scan_id_opt",default="",help="Scan ID (legacy option form)")
        q.add_argument("--method",default=""); q.add_argument("--host",default="")
        q.add_argument("--path",default="",help="Filter URL path substring")
        q.add_argument("--endpoint",default="",help="Filter URL endpoint substring (legacy alias)"); q.add_argument("--status",type=int,default=None)
        q.add_argument("--finding",default="",help="Filter by finding state or finding ID")
        q.add_argument("--module",default="",help="Filter request provenance/module")
        q.add_argument("--error",choices=["any","yes","no"],default="any",help="Filter failed/blocked requests")
        q.add_argument("--parent-exchange",default="",help="Filter follow-up exchanges by parent exchange ID")
        q.add_argument("--limit",type=int,default=100); q.add_argument("--offset",type=int,default=0)
        q.add_argument("--format",choices=["table","json"],default="table"); q.add_argument("--db",default=DEFAULT_DB)
        return q
    add_history_parser("history","Inspect redacted stored HTTP exchanges")
    add_history_parser("traffic","Show the HTTP traffic workbench history")
    add_history_parser("requests","List persisted HTTP requests with filters")
    for command,helptext in (("request","Show a stored HTTP request and its response"),("response","Show a stored redacted response")):
        q=sub.add_parser(command,help=helptext)
        # `request 004` is the primary UX; `request show 004` remains accepted
        # by the argv normalizer for compatibility with the original CLI.
        q.add_argument("exchange_id")
        q.add_argument("--db",default=DEFAULT_DB)
    q=sub.add_parser("diff",help="Compare two stored responses; this is not a vulnerability verdict")
    q.add_argument("exchange_a"); q.add_argument("exchange_b"); q.add_argument("--db",default=DEFAULT_DB)
    q.add_argument("--format",choices=["text","json"],default="text")
    q=sub.add_parser("plugins",help="List built-in analysis plugins"); q.add_argument("action",nargs="?",choices=["list"],default="list")
    return p


def _load_mapping(path):
    raw=Path(path).read_text(encoding="utf-8")
    try: return json.loads(raw)
    except json.JSONDecodeError:
        try:
            import yaml
            val=yaml.safe_load(raw)
            return val if isinstance(val,dict) else {}
        except ImportError: raise ValueError("YAML support needs PyYAML; use JSON or install PyYAML")


def _scope_rules(raw, hosts):
    """Build an explicit scope policy from target host, host rules, and one JSON/YAML file.

    A scope file is a policy, not a target list: it never starts extra scans.
    JSON/YAML files can carry the full policy; .txt/.ips files contain only
    explicit IP/CIDR bounds, one entry per line. Unknown keys and multiple
    files are rejected rather than silently ignored.
    """
    fields = {"allowed_hosts", "hosts", "allowed_ips", "allowed_ports", "allowed_prefixes",
              "excluded_hosts", "excluded_paths", "excluded_params", "allowed_methods",
              "not_before", "expires_at"}
    policy = {
        "allowed_hosts": sorted(set(str(h) for h in hosts if h)),
        "allowed_ips": [], "allowed_ports": [], "allowed_prefixes": [],
        "excluded_hosts": [], "excluded_paths": [], "excluded_params": [],
        "allowed_methods": ["GET", "HEAD", "OPTIONS"],
        "not_before": None, "expires_at": None,
    }
    policy_file = None
    extra_hosts = []
    for entry in raw:
        path = Path(entry)
        if path.is_file():
            if policy_file is not None:
                raise ValueError("Provide at most one scope policy file per scan.")
            if path.suffix.lower() in {".txt", ".ips"}:
                ip_entries=[]
                for line_no,line in enumerate(path.read_text(encoding="utf-8").splitlines(),1):
                    value=line.split("#",1)[0].strip()
                    if not value:
                        continue
                    try:
                        ip_entries.append(str(ipaddress.ip_network(value,strict=False)))
                    except ValueError as exc:
                        raise ValueError(f"Invalid IP/CIDR in {path}:{line_no}: {value}") from exc
                    if len(ip_entries)>500:
                        raise ValueError("IP scope file exceeds the 500-entry limit.")
                if not ip_entries:
                    raise ValueError(f"IP scope file is empty: {path}")
                policy_file = (path,ip_entries)
            else:
                policy_file = path
        elif path.suffix.lower() in {".json", ".yaml", ".yml"}:
            raise ValueError(f"Scope policy file does not exist: {entry}")
        else:
            extra_hosts.append(str(entry))
    if policy_file is not None:
        if isinstance(policy_file, tuple):
            _path, ip_entries = policy_file
            policy["allowed_ips"] = ip_entries
        else:
            data = _load_mapping(str(policy_file))
            if not isinstance(data, dict):
                raise ValueError("Scope policy root must be a JSON/YAML object.")
            unknown = set(data) - fields
            if unknown:
                raise ValueError("Unknown scope policy key(s): " + ", ".join(sorted(unknown)))
            host_values=data.get("allowed_hosts",data.get("hosts",[]))
            policy["allowed_hosts"].extend(host_values if isinstance(host_values,list) else [host_values])
            for key in fields - {"allowed_hosts", "hosts"}:
                if key in data:
                    policy[key] = data[key]
    policy["allowed_hosts"] = sorted({str(x).strip() for x in policy["allowed_hosts"] + extra_hosts if x and str(x).strip()})
    for key in ("allowed_ips", "allowed_ports", "allowed_prefixes", "excluded_hosts", "excluded_paths", "excluded_params"):
        value = policy.get(key, [])
        if not isinstance(value, list):
            value = [value]
        if len(value) > 500:
            raise ValueError(f"Scope policy {key} exceeds the 500-entry limit.")
        policy[key] = value
    methods = policy.get("allowed_methods", ["GET", "HEAD", "OPTIONS"])
    if not isinstance(methods, list) or not methods or len(methods) > 16:
        raise ValueError("Scope policy allowed_methods must be a non-empty list of at most 16 methods.")
    policy["allowed_methods"] = methods
    return policy


def _auth_from_file(path):
    if not path: return {}, {}
    d=_load_mapping(path)
    h=d.get("headers",{})
    if not isinstance(h,dict): raise ValueError("auth file must contain a headers mapping")
    return {str(k):str(v) for k,v in h.items()}, d


def _run_login_flow(path, allowed_hosts, insecure, timeout):
    """Run the one-shot login flow synchronously and return session headers.

    `login_url` must resolve to a host already present in the scan's own
    scope policy — a login config can never be used to make the scanner
    talk to a host the person running it didn't already authorize.
    """
    import asyncio
    from urllib.parse import urlsplit
    import httpx
    from .engine.login_flow import LoginFlowConfig, LoginFlowError, perform_login

    d=_load_mapping(path)
    config=LoginFlowConfig.from_mapping(d)
    login_host=urlsplit(config.login_url).hostname or ""
    if not any(login_host==h or (h.startswith("*.") and login_host.endswith(h[1:])) for h in allowed_hosts):
        raise ValueError(f"--login target host {login_host!r} is not in the scan's scope ({allowed_hosts}); add it to --scope first")

    async def _go():
        async with httpx.AsyncClient(verify=not insecure, timeout=httpx.Timeout(timeout, connect=5.0),
                                      follow_redirects=True) as client:
            return await perform_login(client, config)

    try:
        return asyncio.run(_go())
    except LoginFlowError as ex:
        raise ValueError(f"login flow failed: {ex}") from ex


def _emit(verbose=False):
    """Compact live terminal progress; --verbose adds crawl and coverage detail."""
    from .core.phases import PHASE_SPECS
    from .cli_ui import _display_text, _terminal_safe
    safe = lambda value: _terminal_safe(_display_text(value))
    stage_phase={stage:spec for spec in PHASE_SPECS for stage in spec.stages}
    printed=set()
    def fn(kind,message,data):
        if kind=="stage-start":
            stage=data.get("stage","")
            spec=stage_phase.get(stage)
            if spec and spec.phase_id not in printed:
                printed.add(spec.phase_id)
                n=int(spec.phase_id.rsplit("-",1)[1])
                print(f"\n[{n:02d}/{len(PHASE_SPECS):02d}] {spec.name}")
            print(f"  > {safe(message)}")
        elif kind=="stage-done":
            print(f"  OK {safe(message)} ({data.get('seconds','?')}s)")
            spec=stage_phase.get(data.get("stage",""))
            if verbose and spec and data.get("stage")==spec.stages[-1]:
                print(f"     {data.get('phase_status','PARTIAL')}: {spec.note}")
        elif kind=="stage":
            print(f"     {safe(message)}")
        elif kind=="crawl-progress":
            if verbose:
                print(f"     Crawl: pages {data.get('pages',0)}, queued {data.get('queued',0)}, "
                      f"requests {data.get('requests_used',0)}/{data.get('request_budget','?')}, "
                      f"errors {data.get('request_errors',0)}, cancelled {data.get('cancelled',0)}, "
                      f"rate cap {data.get('current_rps',0):.1f}/s")
        elif kind in ("crawl-error","error"):
            if verbose: print(f"  WARNING {safe(message)}")
    return fn


def _set_phase(ctx, phase_id, status, note=None):
    for phase in getattr(ctx,"phases",[]):
        if phase.phase_id==phase_id:
            phase.status=status
            if note is not None: phase.note=note
            import time as _time
            if not phase.started_at: phase.started_at=_time.time()
            if status in ("COMPLETE","PARTIAL","SKIPPED","BLOCKED","FAILED"):
                phase.finished_at=_time.time()
            return


def _severity_explicit(args):
    return bool(args.severity_profile or args.profile in {"critical","high","medium","low","full"})


def _active_requested(args):
    # A plain scan now requests the complete implemented portfolio, but only
    # after the CLI's explicit ownership/authorization confirmation. PASSIVE
    # remains an explicit opt-out; severity selectors prioritize subsets.
    if getattr(args,"mode",None)=="PASSIVE" or getattr(args,"profile",None)=="passive":
        return False
    return True


def _authorized(auth, yes, host, local, *, quiet=False, json_output=False):
    if not quiet and not json_output:
        print("VULNFORGE is for authorized assessments only. Scope and request controls remain enforced.")
    elif json_output:
        print("VULNFORGE: authorized assessments only; confirm scope before proceeding.", file=sys.stderr)
    if yes or local:
        auth.confirmed=True
        return True
    prompt="Confirm you own this system or have explicit permission [y/N]: "
    try:
        if json_output:
            sys.stderr.write(prompt); sys.stderr.flush()
            answer=sys.stdin.readline().strip().lower()
        else:
            answer=input(prompt).strip().lower()
    except (EOFError,KeyboardInterrupt):
        return False
    auth.confirmed=answer in ("y","yes")
    return auth.confirmed


def _summary(result, files, report_path=None, *, detailed=False, quiet=False):
    from .core.redaction import redact_text, redact_url_query_values
    from .cli_ui import _terminal_safe
    safe_text=lambda value: _terminal_safe(redact_text(value))
    c=result.context; intel=getattr(c,"intelligence",{}); target=intel.get("target",{})
    target_display=_terminal_safe(redact_url_query_values(target.get('final_url',c.config.target)))
    dns=intel.get("dns",{}); techs=list(c.technologies.values())
    categories={}
    for tech in techs: categories.setdefault(tech.category,[]).append(tech.name)
    verified=list(getattr(c,"verified_findings",[]))
    if not verified: verified=[f for f in c.findings if f.status=="VERIFIED"]
    candidates=[f for f in c.findings if f.status!="VERIFIED"]
    if quiet:
        state="STOPPED" if result.aborted else ("LIMITED" if c.stop_reason else "COMPLETE")
        print(f"VULNFORGE · SCAN {state}")
        print(f"Target: {target_display}")
        print(f"Confirmed findings: {len(verified)}")
        for finding in verified[:10]:
            print(f"  {finding.severity.upper()} · {safe_text(finding.title)}")
        report_dir=str(Path(next(iter(files.values()))).parent) if files else "Not generated"
        print(f"Reports: {report_dir}")
        print(f"Scan ID: {c.scan_id}")
        return
    if not detailed:
        from collections import Counter
        from .core.outcomes import finding_result_status, test_result_status
        from .core.redaction import redact_url_query_values
        finding_states=Counter(finding_result_status(f.to_dict()) for f in c.findings)
        test_states=Counter(test_result_status(t) for t in c.tests if str(t.get("status","")).upper()!="VERIFIED")
        combined_states=Counter(finding_states)
        for k,v in test_states.items():
            combined_states[k]+=v
        selected=[row for row in getattr(c,"vulnerability_matrix",[]) if row.get("selected")]
        supported=sum(1 for row in selected if row.get("supported"))
        unsupported=sum(1 for row in selected if not row.get("supported"))
        request_budget=getattr(getattr(c.requester,"budget",None),"max_requests",None)
        state="STOPPED" if result.aborted else ("LIMITED" if c.stop_reason else "COMPLETE")
        print(f"\nVULNFORGE · SCAN {state}")
        print(f"Target: {target_display}")
        print(f"HTTP requests: {c.stats.requests_sent}" + (f"/{request_budget}" if request_budget else "") +
              f" · endpoints: {len(c.endpoints)} · parameters: {len(c.parameters)}")
        frontend=[n for k in ("frontend","js-framework","build-tool") for n in categories.get(k,[])]
        backend=[n for k in ("framework","language","runtime") for n in categories.get(k,[])]
        edge=[n for k in ("cdn","waf") for n in categories.get(k,[])]
        server_names=categories.get("server",[])
        print("FINGERPRINTS (observed)")
        print(f"  Host / IPs : {target.get('hostname','Unknown')} · {', '.join(dns.get('observed_addresses',[])) or 'IP not resolved/observed'}")
        print(f"  Edge / WAF : {', '.join(edge) if edge else 'No matching passive signature observed'}")
        print(f"  Frontend   : {', '.join(frontend) if frontend else 'Not identified from observed pages/assets'}")
        print(f"  Backend    : {', '.join(backend) if backend else 'Not identified from observed responses'}")
        print(f"  Web server : {', '.join(server_names) if server_names else 'Not identified from response headers'}")
        configured_rate=getattr(c.config,"request_rate",None)
        configured_budget=getattr(c.config,"request_budget",request_budget)
        observed_exchanges=getattr(getattr(c,"requester",None),"exchanges",[])
        throttled=sum(1 for exchange in observed_exchanges if getattr(exchange,"status",0)==429)
        retry_after=sum(1 for exchange in observed_exchanges if any(str(k).lower()=="retry-after" for k in getattr(exchange,"response_headers",{})))
        rate_text=f"{configured_rate:g} req/s max" if isinstance(configured_rate,(int,float)) else "profile default"
        print(f"  Scan pace  : {rate_text} · budget {configured_budget or 'profile default'} · target 429s {throttled}, Retry-After on {retry_after} response(s)")
        print(f"Testing: {len(c.tests)} executed · {len(c.hypotheses)} hypotheses · {supported} supported class(es) selected · {unsupported} unsupported")
        print("Results: " + " · ".join(f"{name} {combined_states.get(name,0)}" for name in
              ("CONFIRMED","UNCONFIRMED","KILLED","UNTESTABLE","SKIPPED","UNSUPPORTED","INFORMATIONAL")))
        for finding in verified[:10]:
            print(f"  CONFIRMED · {finding.severity.upper()} · {safe_text(finding.title)}")
        if not quiet:
            ordered_tests=sorted(
                [t for t in c.tests if str(t.get("status","")).upper()!="VERIFIED"],
                key=lambda t:(0 if t.get("reproduction_status")=="REPRODUCED" else 1, str(t.get("type","")))
            )
            for item in ordered_tests[:8]:
                t_state=test_result_status(item)
                repro="REPRODUCED · " if item.get("reproduction_status")=="REPRODUCED" else ""
                t_name=str(item.get("type","test")).replace("-"," ").title()
                ep=str(item.get("endpoint",""))
                if ep:
                    safe_ep=redact_url_query_values(ep)
                    parts=urlsplit(safe_ep)
                    ep=(parts.hostname or "")+(parts.path or "/")
                    if parts.query: ep+="?"+parts.query
                ep_text=f" · {ep[:80]}" if ep else ""
                print(f"  {t_state} · {repro}{t_name}{ep_text}")
            ordered_candidates=sorted(
                candidates,
                key=lambda f:(1 if finding_result_status(f.to_dict())=="INFORMATIONAL" else 0, f.title)
            )
            for finding in ordered_candidates[:8]:
                print(f"  {finding_result_status(finding.to_dict())} · {safe_text(finding.title)}")
            print("Reports: " + ", ".join(files.values()))
        else:
            print("Reports: " + files.get("json", "reports not generated"))
        print(f"Scan ID: {c.scan_id}")
        return
    print("\n"+"═"*66)
    print("SCAN STOPPED" if result.aborted else ("SCAN COMPLETE · LIMITED" if c.stop_reason else "SCAN COMPLETE"))
    print("TARGET")
    print(f"  {target_display}")
    print(f"  Host {target.get('hostname','Not identified')} · {target.get('scheme','Not determined').upper()} · port {target.get('port','Not determined')}")
    service_statuses=sorted({str(s.get('status')) for s in intel.get('services',[]) if s.get('status') is not None})
    print(f"  IPs: {', '.join(dns.get('observed_addresses',[])) or 'Not identified'} · redirects: {len(intel.get('redirects',[]))} observed · HTTP status: {', '.join(service_statuses) or 'No response observed'}")
    print("NETWORK & INFRASTRUCTURE")
    print(f"  CDN/WAF : {', '.join(categories.get('cdn',[])+categories.get('waf',[])) or 'Not identified'}")
    print(f"  Server  : {', '.join(categories.get('server',[])) or 'Not identified'}")
    print(f"  TLS     : {intel.get('tls',{}).get('status','NOT DETERMINED')}")
    print("TECHNOLOGY")
    for label,keys in (("Frontend",("frontend","js-framework","build-tool")),("Backend",("framework","language")),("Runtime",("runtime",)),("CMS",("cms",))):
        vals=[name for key in keys for name in categories.get(key,[])]
        print(f"  {label:10}: {', '.join(vals) if vals else 'Not identified'}")
    print("  Database  : Not determined")
    print("SECURITY")
    print(f"  Authentication : {intel.get('authentication',{}).get('status','NOT DETERMINED')} · MFA {intel.get('mfa',{}).get('status','NOT DETERMINED')}")
    print(f"  Cookies        : {len(intel.get('cookies',[]))} names observed")
    headers=intel.get('security_headers',{})
    print(f"  Header controls: {sum(1 for x in headers.values() if x['observed'] and not x['missing'])}/{len(headers)} fully present across observed responses")
    for label,test_type in (("CORS","cors-origin-reflection"),("SQLi","sql-injection-validation")):
        records=[item for item in c.tests if item.get("type")==test_type]
        if records:
            from .core.outcomes import test_result_status
            states=", ".join(f"{state}: {sum(1 for item in records if test_result_status(item)==state)}"
                              for state in ("CONFIRMED","UNCONFIRMED","KILLED","UNTESTABLE","SKIPPED")
                              if any(test_result_status(item)==state for item in records))
            print(f"  {label:14}: {states or 'executed; see report'}")
        else:
            state="not run (passive mode)" if not c.config.active_requested else "no eligible observed surface"
            print(f"  {label:14}: {state}")
    print("APPLICATION")
    print(f"  Endpoints {len(c.endpoints)} · Parameters {len(c.parameters)} · APIs {sum(intel.get('api',{}).get('inventory_counts',{}).values())} · Forms {sum(1 for e in c.endpoints.values() if e.source=='form')} · JS {intel.get('coverage',{}).get('javascript_discovered',0)} discovered/{c.js_analyzed} analyzed")
    print("HYPOTHESES & VERIFICATION")
    print(f"  Hypotheses {len(c.hypotheses)} · Tests {len(c.tests)} · Candidates {len(candidates)} · Confirmed {len(verified)}")
    if c.tests:
        from .core.redaction import redact_url_query_values
        print("TEST RESULTS")
        for item in c.tests:
            test_type=str(item.get("type","test")).replace("-"," ").title()
            endpoint=str(item.get("endpoint", ""))
            if endpoint:
                safe_url=redact_url_query_values(endpoint)
                parts=urlsplit(safe_url)
                endpoint=(parts.hostname or "")+(parts.path or "/")
                if parts.query: endpoint+="?"+parts.query
            detail=(" · "+endpoint[:96]) if endpoint else ""
            if item.get("parameter"): detail+=f" · parameter {item['parameter']}"
            from .core.outcomes import test_result_status
            print(f"  {test_result_status(item):12} {test_type}{detail}")
    for f in verified:
        print(f"  [CONFIRMED] {f.title} · {f.severity.upper()} · evidence {len(f.evidence)} item(s)")
    for f in candidates[:20]:
        from .core.outcomes import finding_result_status
        result_state=finding_result_status(f.to_dict())
        print(f"  [{result_state}] {f.title} · {f.severity.upper()}")
    print("REQUEST CONTROL")
    lim=getattr(c.requester,"limiter",None); budget=getattr(c.requester,"budget",None)
    print(f"  Used {c.stats.requests_sent}/{budget.max_requests if budget else '?'} · rate cap {c.config.request_rate if c.config.request_rate is not None else 'profile default'}/s")
    if c.stop_reason:
        print(f"  Network stop: {c.stop_reason} · offline analysis continued where possible")
    if c.stats.crawl_cancelled or c.stats.crawl_errors:
        print(f"  Crawler: {c.stats.crawl_errors} errors · {c.stats.crawl_cancelled} cancelled · {c.stats.crawl_timeouts} timeouts")
    print("PHASE COVERAGE")
    for phase in getattr(c,"phases",[]):
        print(f"  {phase.phase_id} {phase.status:10} {phase.name}")
    from .core.coverage import build_coverage
    cov=build_coverage(c)
    counts={s:sum(1 for x in cov if x['status']==s) for s in ("TESTED","PARTIAL","NOT_TESTED","UNSUPPORTED","BLOCKED")}
    print("  " + " · ".join(f"{k}: {v}" for k,v in counts.items() if v))
    print("REPORTS")
    for kind,path in files.items(): print(f"  {kind.upper():5} {path}")
    print(f"  Scan ID: {c.scan_id}")
    print("═"*66)

def cmd_scan(args):
    # Fall back to env vars for local credential/scope file paths so a real
    # target's auth file path (and anything in it) never has to be typed on
    # the command line / land in shell history. CLI flags always win.
    if not args.auth and os.environ.get("VULNFORGE_AUTH_FILE"):
        args.auth = os.environ["VULNFORGE_AUTH_FILE"]
    if not args.scope and os.environ.get("VULNFORGE_SCOPE_FILE"):
        args.scope = [os.environ["VULNFORGE_SCOPE_FILE"]]
    if not getattr(args, "login", None) and os.environ.get("VULNFORGE_LOGIN_FILE"):
        args.login = os.environ["VULNFORGE_LOGIN_FILE"]
    if args.json_output and (args.interactive or args.quiet or args.verbose):
        raise ValueError("--json cannot be combined with --interactive, --quiet, or --verbose")
    if args.quiet and args.interactive:
        raise ValueError("Choose either --quiet or --interactive")
    if args.target=="url":
        raw=args.target_extra
        if not raw: raise ValueError("Use `vulnforge scan url <target>`")
    elif args.target_extra:
        raise ValueError("Unexpected extra scan argument; use `vulnforge scan <target>` or `vulnforge scan url <target>`")
    else:
        raw=args.target or args.url
    if not raw: raise ValueError("Provide a target: vulnforge scan <target>")
    original,target=normalize_target(raw)
    p=urlsplit(target); host=p.hostname
    loopback=False
    try: loopback=ipaddress.ip_address(host).is_loopback
    except ValueError: loopback=host.lower()=="localhost"
    scope_policy=_scope_rules(args.scope,[host])
    allowed=scope_policy["allowed_hosts"]
    local=loopback
    if args.lab and args.mode not in (None,"LAB"):
        raise ValueError("--lab cannot be combined with a different --mode")
    safety_mode="LAB" if args.lab else (args.mode or "")
    profile_name,test_profile=resolve_profiles(args.profile,safety_mode,args.severity_profile or "")
    if not _severity_explicit(args) and args.profile!="passive":
        test_profile="full"
    if profile_name=="lab" and not loopback:
        raise ValueError("LAB profile is restricted to loopback targets.")
    profile_explicit=_severity_explicit(args)
    active_requested=_active_requested(args)
    profile=get_profile(profile_name)
    auth=AuthorizationContext(allowed_hosts=allowed, allowed_ips=scope_policy["allowed_ips"],
        allowed_ports=scope_policy["allowed_ports"], allowed_prefixes=scope_policy["allowed_prefixes"],
        excluded_hosts=scope_policy["excluded_hosts"], excluded_paths=scope_policy["excluded_paths"],
        excluded_params=scope_policy["excluded_params"], allowed_methods=scope_policy["allowed_methods"],
        not_before=scope_policy["not_before"], expires_at=scope_policy["expires_at"],
        profile_name=profile_name, allow_private=(args.allow_private or local), confirmed=False)
    if not _authorized(auth,args.yes,host,local,quiet=args.quiet,json_output=args.json_output):
        if not args.json_output: print("Aborted — no requests sent.")
        return 2
    headers,auth_data=_auth_from_file(args.auth)
    if getattr(args,"login",None):
        login_headers=_run_login_flow(args.login, allowed, args.insecure, args.timeout)
        headers={**headers, **login_headers}  # session cookie wins over any static auth header of the same name
    rate=args.rate if args.rate is not None else (2.0 if active_requested or profile_name in ("safe-active","controlled-active") else 5.0)
    budget=args.max_requests if args.max_requests is not None else (1000 if active_requested or profile_name in ("safe-active","controlled-active") else 5000)
    rate_cap=min(profile.requests_per_second,2.0 if active_requested or profile_name in ("safe-active","controlled-active") else 5.0)
    budget_cap=min(profile.max_requests,1000 if active_requested or profile_name in ("safe-active","controlled-active") else 5000)
    if not math.isfinite(rate) or rate <= 0: raise ValueError("--rate must be a finite positive number")
    if rate > rate_cap: raise ValueError(f"--rate exceeds the {rate_cap:g} requests/second cap for this safety/resource mode")
    if budget <= 0: raise ValueError("--max-requests must be positive")
    if budget > budget_cap: raise ValueError(f"--max-requests exceeds the {budget_cap} request cap for this safety/resource mode")
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 120: raise ValueError("--timeout must be finite, greater than 0, and at most 120 seconds")
    from dataclasses import replace
    profile=replace(profile,requests_per_second=rate,max_requests=budget)
    cfg=ScanConfig(target=target, original_target=original, profile_name=profile_name,
        allowed_hosts=allowed, allowed_ips=scope_policy["allowed_ips"],
        allowed_ports=scope_policy["allowed_ports"], allowed_prefixes=scope_policy["allowed_prefixes"],
        excluded_hosts=scope_policy["excluded_hosts"], excluded_paths=scope_policy["excluded_paths"],
        excluded_params=scope_policy["excluded_params"], allowed_methods=scope_policy["allowed_methods"],
        not_before=scope_policy["not_before"], expires_at=scope_policy["expires_at"],
        allow_private=(args.allow_private or local), authorization_confirmed=True,
        verify_tls=not args.insecure, request_timeout=args.timeout, extra_headers=headers,
        request_rate=rate, request_budget=budget, active_requested=active_requested,
        auto_scheme=("://" not in raw), auth_data=auth_data,test_profile=test_profile,
        test_profile_explicit=profile_explicit,verbose=args.verbose,
        scan_id="vf-"+uuid.uuid4().hex[:12])
    # Validate/create the structured database before sending any HTTP requests;
    # this catches incompatible legacy schemas without losing a completed scan.
    store=Store(args.db)
    scan_started=time.time()
    store.start_scan_record(cfg.scan_id,target,profile_name,scan_started)
    store.record_event(cfg.scan_id,{"kind":"scan-started","message":"Authorized scan accepted by the CLI.",
        "timestamp":scan_started,"data":{"scan_id":cfg.scan_id,"target":target,"status":"running"}})
    from .cli_ui import LiveScanDashboard, print_banner
    live_ui=None
    if not args.quiet and not args.json_output:
        if args.verbose:
            print_banner(color=(not args.no_color and sys.stdout.isatty()))
        else:
            live_ui=LiveScanDashboard(target, color=(not args.no_color and sys.stdout.isatty()))
            if live_ui.tty:
                live_ui.draw()
            else:
                print("VULNFORGE · authorized assessment · concise summary will follow")
    def stop(_sig,_frm):
        auth.stop("emergency stop / SIGINT")
        print("\nStopping VULNFORGE; collected state will be persisted.",file=sys.stderr if args.json_output else sys.stdout)
    old=signal.signal(signal.SIGINT,stop)
    base_event_fn=_emit(True) if args.verbose else (live_ui if live_ui else None)
    from .core.redaction import redact_url_query_values
    sensitive_headers=set(headers)
    for identity in auth_data.get("identities",{}).values():
        sensitive_headers.update((identity.get("headers") or {}).keys())
    event_store_warning=[False]
    def event_fn(kind,message,data):
        payload=dict(data or {})
        exchange=payload.pop("exchange",None)
        safe_message=str(message)
        if kind=="http-exchange" and isinstance(exchange,dict):
            try: store.record_exchange(cfg.scan_id,exchange,sensitive_headers=sensitive_headers,redact=True)
            except Exception as exc:
                if not event_store_warning[0]:
                    print(f"Warning: live HTTP history could not be persisted ({type(exc).__name__}); scan will continue.",file=sys.stderr)
                    event_store_warning[0]=True
            payload.pop("error",None)
            payload.update({"exchange_id":exchange.get("exchange_id"),"method":exchange.get("method"),
                "url":redact_url_query_values(str(exchange.get("url") or "")),
                "status":exchange.get("status"),"module":exchange.get("module"),
                "duration_ms":exchange.get("duration_ms"),
                "response_chars":len(exchange.get("response_body","") or "")})
            safe_message=f"{exchange.get('method','HTTP')} exchange · {exchange.get('status') or 'no response'}"
        event={"kind":kind,"message":safe_message,"data":payload,"timestamp":time.time()}
        try: store.record_event(cfg.scan_id,event)
        except Exception as exc:
            if not event_store_warning[0]:
                print(f"Warning: scan events could not be persisted ({type(exc).__name__}); scan will continue.",file=sys.stderr)
                event_store_warning[0]=True
        if base_event_fn: base_event_fn(kind,safe_message,payload)
    try:
        result=run_scan(cfg,auth,event_fn=event_fn)
    except Exception as exc:
        store.finish_scan_record(cfg.scan_id,"failed",time.time())
        try:
            store.record_event(cfg.scan_id,{"kind":"scan-error","message":"Scan failed before completion.",
                "timestamp":time.time(),"data":{"scan_id":cfg.scan_id,"error_type":type(exc).__name__}})
        except Exception: pass
        raise
    finally: signal.signal(signal.SIGINT,old)
    ctx=result.context
    if live_ui: live_ui.finish(ctx)
    # Persist an interruption-safe checkpoint before report rendering.
    if not args.quiet and not args.json_output and args.verbose:
        print("\nPERSISTENCE & REPORTING")
    _set_phase(ctx,"phase-15","RUNNING","Persisting redacted scan state and rendering structured reports.")
    store.save_scan(result)
    if not args.quiet and not args.json_output and args.verbose:
        print("[✓] Redacted scan state and evidence references checkpointed to SQLite")
    outdir=Path(args.out or f"reports/{ctx.scan_id}"); outdir.mkdir(parents=True,exist_ok=True)
    paths={"html":str(outdir/"report.html"),"pdf":str(outdir/"report.pdf"),
           "json":str(outdir/"report.json"),"md":str(outdir/"report.md")}
    result.report_paths=dict(paths)
    # First pass ensures the requested files exist if the process is interrupted.
    write_html_report(result,paths["html"]); write_pdf_report(result,paths["pdf"])
    write_json_report(result,paths["json"]); write_markdown_report(result,paths["md"])
    if not args.quiet and not args.json_output and args.verbose:
        print("[✓] HTML, PDF, JSON, and Markdown generated from structured scan data")
    _set_phase(ctx,"phase-15","COMPLETE","Redacted evidence persisted; HTML, PDF, JSON, and Markdown generated.")
    # Regenerate so every artifact includes the final phase state, then persist it.
    files={"html":write_html_report(result,paths["html"]),"pdf":write_pdf_report(result,paths["pdf"]),
           "json":write_json_report(result,paths["json"]),"md":write_markdown_report(result,paths["md"])}
    store.save_scan(result)
    final_status=("stopped" if result.aborted else ("partial" if ctx.stop_reason else "completed"))
    store.record_event(ctx.scan_id,{"kind":"report-generated","message":"Structured reports generated from the stored scan result.",
        "timestamp":time.time(),"data":{"formats":["html","pdf","json","md"]}})
    store.record_audit("report_generated", object_type="scan", object_id=ctx.scan_id, scan_id=ctx.scan_id, metadata={"formats":["html","pdf","json","md"]})
    store.record_event(ctx.scan_id,{"kind":"scan-complete","message":f"Scan {final_status}.",
        "timestamp":time.time(),"data":{"scan_id":ctx.scan_id,"status":final_status}})
    if args.json_output:
        from .report.json_report import build_report_dict
        print(json.dumps(build_report_dict(result),ensure_ascii=False))
    else:
        _summary(result,files,detailed=args.verbose,quiet=args.quiet)
        if args.interactive:
            from .cli_ui import run_stored_scan_dashboard
            run_stored_scan_dashboard(ctx.scan_id,store)
    return 0


def cmd_lab(args):
    from labs.runtime import serve
    serve(args.level,patched=args.patched)
    return 0


def cmd_dashboard(args):
    import uvicorn
    uvicorn.run("vulnforge.dashboard:app",host=args.host,port=args.port,reload=False)
    return 0


def cmd_tools():
    groups={"DISCOVERY":["subfinder","amass","assetfinder","dnsx","httpx"],"CRAWLING":["katana","hakrawler"],"SCANNING":["nuclei","nikto","nmap"],"FINGERPRINTING":["whatweb"]}
    print("VulnForge TOOLCHAIN")
    for group,tools in groups.items():
        print(group)
        for tool in tools: print(f"  {tool:16} {'AVAILABLE' if shutil.which(tool) else 'NOT INSTALLED'}")
    print("CORE\n  HTTP             BUILT-IN\n  SQLite           AVAILABLE\n  Verification     PARTIAL (BOLA, CORS, redirect, and conservative SQL parser-error checks)")
    return 0


def cmd_status(store):
    from .core.redaction import redact_url_query_values
    scans=store.list_scans()
    if not scans:
        print("No scans stored yet.")
        return 0
    print(f"{'SCAN ID':18} {'TARGET':34} {'DATE':12} {'FINDINGS':>10} {'STATUS':10}")
    for row in scans[:50]:
        stamp=time.strftime('%b %d %H:%M',time.localtime(row.get('started_at') or 0))
        target=redact_url_query_values(str(row.get('target') or ''))
        if len(target)>34: target=target[:31]+'…'
        count=int(row.get('verified_count',0))
        candidates=int(row.get('candidates_count',0))
        findings=f"{count}"+(f" +{candidates} cand." if candidates else "")
        print(f"{row['scan_id']:<18} {target:<34} {stamp:12} {findings:>10} {row.get('status','unknown'):10}")
    print("Open a scan: vulnforge <SCAN-ID> --dashboard | --database | --report")
    return 0


def cmd_report(args,store):
    scan_ref=args.scan_id
    data=store.get_report(scan_ref)
    if data is None:
        try:
            _,normalized=normalize_target(scan_ref)
            requested=urlsplit(normalized)
            matches=[]
            for row in store.list_scans():
                try: observed=urlsplit(row.get("target", ""))
                except ValueError: continue
                if (observed.hostname or "").lower() != (requested.hostname or "").lower(): continue
                if requested.port is not None and observed.port != requested.port: continue
                matches.append(row)
            if matches:
                scan_ref=matches[0]["scan_id"]
                data=store.get_report(scan_ref)
        except ValueError:
            pass
    if data is None: print(f"No stored report found for scan or target: {args.scan_id}"); return 2
    out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    funcs={"html":write_html_report,"pdf":write_pdf_report,"json":write_json_report,"md":write_markdown_report}
    wanted=list(funcs) if args.format=="all" else [args.format]
    for fmt in wanted: print(funcs[fmt](data,str(out/f"{scan_ref}.{fmt}")))
    return 0


def cmd_capture_import(args,store):
    if not args.confirm_authorized:
        print("Refusing import: pass --confirm-authorized only if this captured traffic is authorized under the original scan scope.")
        return 2
    scan=store.get_scan(args.scan_id); report=store.get_report(args.scan_id)
    if not scan or report is None:
        print("A stored scan and report are required before capture import."); return 2
    if str(scan.get("status","")).lower()=="running":
        print("Capture import is allowed only after the original scan has completed."); return 2
    policy=scan.get("scope_policy") or {}
    if not policy.get("confirmed") or not policy.get("allowed_hosts"):
        print("The stored scan has no confirmed explicit scope; capture import is refused."); return 2
    try:
        auth=AuthorizationContext(allowed_hosts=policy.get("allowed_hosts",[]),
            allowed_ips=policy.get("allowed_ips",[]),allowed_ports=policy.get("allowed_ports",[]),
            allowed_prefixes=policy.get("allowed_prefixes",[]),excluded_hosts=policy.get("excluded_hosts",[]),
            excluded_paths=policy.get("excluded_paths",[]),excluded_params=policy.get("excluded_params",[]),
            allowed_methods=policy.get("allowed_methods",["GET","HEAD","OPTIONS"]),
            not_before=policy.get("not_before"),expires_at=policy.get("expires_at"),
            profile_name=policy.get("profile","standard"),allow_private=bool(policy.get("allow_private",False)),
            confirmed=True)
        intelligence=report.get("intelligence",{}) if isinstance(report.get("intelligence"),dict) else {}
        dns=intelligence.get("dns",{}) if isinstance(intelligence.get("dns"),dict) else {}
        dns_map={}
        hostname=str(dns.get("hostname","")).lower().rstrip(".")
        addresses=list(dns.get("observed_addresses",[]) or [])
        if hostname and addresses: dns_map[hostname]=addresses
        target_dns=intelligence.get("target",{}) if isinstance(intelligence.get("target"),dict) else {}
        target_host=str(target_dns.get("hostname","")).lower().rstrip(".")
        target_addresses=list(target_dns.get("resolved_ips",[]) or [])
        if target_host and target_addresses: dns_map.setdefault(target_host,target_addresses)
        def offline_resolve(host):
            try: return [ipaddress.ip_address(host)]
            except ValueError: return [ipaddress.ip_address(ip) for ip in dns_map.get(str(host).lower().rstrip("."),[])]
        # Scope verification uses only DNS addresses already persisted by the original scan.
        # This import command performs neither live DNS lookups nor HTTP requests.
        auth._resolve=offline_resolve
        from .engine.browser_capture import load_har,load_workflow_spec,parse_har_document,validate_configured_workflow
        scope_check=lambda url,method:auth.check(url,purpose="browser-capture-import",method=method)[0]
        har=load_har(args.har_file)
        capture=parse_har_document(har,scope_check,excluded_param=auth.param_excluded)
        workflow_validation=None
        if args.workflow_spec:
            spec=load_workflow_spec(args.workflow_spec)
            base_url=str(report.get("scan",{}).get("target") or scan.get("target") or "")
            workflow_validation=validate_configured_workflow(spec,capture["exchanges"],scope_check,
                base_url=base_url,excluded_param=auth.param_excluded)
        outcome=store.append_browser_capture(args.scan_id,capture,workflow_validation=workflow_validation)
    except (OSError,ValueError,TypeError) as exc:
        print(f"Capture import failed: {exc}"); return 2
    print(json.dumps({"scan_id":args.scan_id,"capture_import":outcome["capture_import"],
        "workflow_observations_summary":outcome["workflow_observations"]["summary"],
        "configured_workflow_validation_summary":(workflow_validation.get("summary") if workflow_validation else None),
        "note":"HAR imported offline; bodies omitted; no requests replayed; capture matches are observations, not security verification."},indent=2))
    return 0


def cmd_history(args,store):
    positional=getattr(args,"scan_id_pos","") or ""
    option=getattr(args,"scan_id_opt",getattr(args,"scan_id","")) or ""
    if positional and option and positional!=option:
        print("Use either positional SCAN_ID or --scan-id, not both."); return 2
    scan_id=positional or option
    path_filter=getattr(args,"path","") or ""
    endpoint_filter=path_filter or getattr(args,"endpoint","")
    has_error=None if args.error=="any" else args.error=="yes"
    rows=store.list_exchanges(scan_id=scan_id,method=args.method,host=args.host,
        endpoint=endpoint_filter,status=args.status,limit=max(args.limit, 1000) if getattr(args, "finding", "") else args.limit,offset=args.offset,
        module=args.module,has_error=has_error,parent_exchange_id=args.parent_exchange)
    finding_filter=getattr(args, "finding", "") or ""
    if finding_filter:
        desired=finding_filter.upper()
        desired_status={"CONFIRMED":"VERIFIED","UNCONFIRMED":"CANDIDATE","KILLED":"KILLED","UNTESTABLE":"UNTESTABLE"}.get(desired, desired)
        allowed_ids=set()
        findings=store.list_all_findings(scan_id=scan_id, limit=1000)
        for finding in findings:
            if desired_status not in {str(finding.get("status","")).upper(), str(finding.get("state","")).upper(), str(finding.get("finding_id","")).upper()}:
                continue
            chain=store.get_evidence_chain(str(finding.get("finding_id") or ""))
            blob=json.dumps(chain, default=str)
            for row in rows:
                if row.get("exchange_id") and row["exchange_id"] in blob: allowed_ids.add(row["exchange_id"])
        rows=[row for row in rows if row.get("exchange_id") in allowed_ids]
        rows=rows[:args.limit]
    if args.format=="json":
        print(json.dumps(rows,indent=2)); return 0
    if not rows:
        print("No stored HTTP exchanges match these filters."); return 0
    command = getattr(args, "command", "history")
    if command in {"traffic", "requests"}:
        print("REQUESTS")
        print(f"{'ID':5} {'METHOD':7} {'STATUS':7} {'HOST':28} {'ENDPOINT':38} {'TIME':>8}")
        for index, row in enumerate(rows, start=args.offset + 1):
            parsed=urlsplit(str(row.get("url") or ""))
            host=parsed.netloc or "—"; endpoint=parsed.path or "/"
            duration=row.get("duration_ms",0)
            print(f"{index:03d}  {str(row.get('method') or '-'):7} {str(row.get('status') or '-'):7} {host[:27]:28} {endpoint[:37]:38} {float(duration):7.1f}ms")
        print(f"{len(rows)} persisted request/response pair(s). Use `vulnforge request 004` for both sides.")
    else:
        print(f"{'EXCHANGE ID':26} {'METHOD':7} {'STATUS':6} {'MS':>8} {'BYTES':>13} URL")
        for row in rows:
            size=f"{row['request_bytes']}/{row['response_bytes']}"
            print(f"{row['exchange_id'][:25]:26} {row['method'] or '-':7} {str(row['status'] or '-'):6} "
                  f"{row['duration_ms']:8.1f} {size:>13} {row['url']}")
        print(f"{len(rows)} redacted exchange(s). Use `vulnforge request 001` or `vulnforge response 001`.")
    return 0


def cmd_exchange_view(side,exchange_id,store):
    exchange=store.resolve_exchange(exchange_id)
    if not exchange:
        print(f"Exchange not found: {exchange_id}"); return 2
    parsed=urlsplit(str(exchange.get("url") or ""))
    target=parsed.path or "/"
    if parsed.query: target += "?" + parsed.query
    request_lines=[f"{exchange.get('method','GET')} {target} {exchange.get('request_version','HTTP/1.1')}"]
    request_lines += [f"{k}: {v}" for k,v in (exchange.get("request_headers") or {}).items()]
    request_lines += ["", str(exchange.get("request_body") or "[No request body stored]")]
    response_lines=[f"status: {exchange.get('status') or 'NO RESPONSE'}", f"{exchange.get('response_version','HTTP/1.1')} {exchange.get('status') or 'NO RESPONSE'} {exchange.get('reason_phrase','')}"]
    response_lines += [f"{k}: {v}" for k,v in (exchange.get("response_headers") or {}).items()]
    response_lines += ["", str(exchange.get("response_body") or "[No response body stored]"),
                       f"Response time: {exchange.get('duration_ms',0)}ms",
                       f"Response size: {len(str(exchange.get('response_body') or '').encode('utf-8'))} bytes"]
    if side == "request":
        _print_http_section("HTTP REQUEST", request_lines)
        print(f"Authentication: {exchange.get('authentication_context_id') or 'Not recorded'}")
        print(f"Query: {parsed.query or 'None'}")
        print(f"Source: {exchange.get('module') or exchange.get('source') or 'Not recorded'}")
        _print_http_section("HTTP RESPONSE", response_lines)
        print(f"exchange_id: {exchange.get('exchange_id',exchange_id)} · request_id: {exchange.get('request_id','not recorded')} · response_id: {exchange.get('response_id','not recorded')}")
    else:
        _print_http_section("HTTP RESPONSE", response_lines)
    return 0


def cmd_diff(exchange_a,exchange_b,store,output="text"):
    a=store.get_exchange(exchange_a); b=store.get_exchange(exchange_b)
    if not a or not b:
        missing=exchange_a if not a else exchange_b
        print(f"Exchange not found: {missing}"); return 2
    from .engine.research import compare_response_bodies
    ah={str(k).lower():v for k,v in (a.get("response_headers") or {}).items()}
    bh={str(k).lower():v for k,v in (b.get("response_headers") or {}).items()}
    body=compare_response_bodies(a.get("response_body") or "",b.get("response_body") or "")
    report={"exchange_a":exchange_a,"exchange_b":exchange_b,
        "request_ids":{"a":a.get("request_id"),"b":b.get("request_id")},
        "response_ids":{"a":a.get("response_id"),"b":b.get("response_id")},
        "status":{"a":a.get("status"),"b":b.get("status"),"different":a.get("status")!=b.get("status")},
        "headers":{"different":ah!=bh,"a":ah,"b":bh},"body":body,
        "interpretation":"Observed response difference only; this output is not a vulnerability determination."}
    if output=="json":
        print(json.dumps(report,indent=2,ensure_ascii=False)); return 0
    print(f"Stored response comparison: {exchange_a} ↔ {exchange_b}")
    print(f"Status: {report['status']['a']} → {report['status']['b']} ({'DIFFERENT' if report['status']['different'] else 'SAME'})")
    print(f"Headers: {'DIFFERENT' if report['headers']['different'] else 'SAME'}")
    print(f"Body: {'DIFFERENT' if body['different'] else 'SAME'} · {body['bytes_a']} / {body['bytes_b']} bytes ({body['format']})")
    if body["format"]=="json":
        for change in body["changes"]:
            print(f"{change['kind']:7} {change['path']}: {change.get('before','<missing>')} → {change.get('after','<missing>')}")
        if body["truncated"]: print("… structured diff truncated at the configured change limit")
    else:
        for line in body.get("unified_diff",[]): print(line)
    print(report["interpretation"])
    return 0

def cmd_evidence(identifier,store):
    f=store.get_finding(identifier)
    if f:
        print(json.dumps({"finding_id":identifier,"title":f["title"],"status":f["status"],"endpoint":f.get("endpoint"),"evidence_chain":store.get_evidence_chain(identifier),"evidence":f.get("evidence",[])},indent=2)); return 0
    s=store.get_scan(identifier)
    if s:
        findings=store.get_findings(identifier)
        print("This identifier belongs to a scan, not a finding.\n\nScan:\n"+identifier+f"\n\nVerified findings: {sum(x.get('status')=='VERIFIED' for x in findings)}\n\nUse: vulnforge evidence <finding-id>")
        return 2
    print("Finding ID not found. Finding IDs and scan IDs are distinct."); return 2


def _print_http_section(title: str, lines: list[str]) -> None:
    width = 66
    print(f"╭──────────────── {title} ────────────────╮")
    for line in lines:
        safe = str(line).replace("\x1b", "")
        print(safe[:width])
    print("╰──────────────────────────────────────────╯")


def cmd_coverage(args, store):
    scan_id = args.scan_id or (store.list_scans()[0]["scan_id"] if store.list_scans() else "")
    if not scan_id:
        print("No stored scans.")
        return 0
    report = store.get_report(scan_id)
    if not report:
        print(f"No stored report available for scan: {scan_id}")
        return 2
    from .core.coverage import coverage_summary
    class _Context:
        vulnerability_matrix = report.get("vulnerability_matrix", [])
        endpoints = {str(i): item for i, item in enumerate(report.get("endpoints", []) or [])}
        parameters = {str(i): item for i, item in enumerate(report.get("parameters", []) or [])}
        requester = type("Requester", (), {"exchanges": report.get("exchanges", []) or report.get("http_history", []) or []})()
    summary = coverage_summary(_Context())
    if args.format == "json":
        print(json.dumps({"scan_id": scan_id, **summary}, indent=2, ensure_ascii=False, default=str))
        return 0
    print(f"COVERAGE · {scan_id}")
    print(f"Classes: {summary['total']} · selected: {summary['selected']} · supported: {summary['supported']} · evidence-backed: {summary['evidence_backed']}")
    if summary["counts"]:
        print("States: " + " · ".join(f"{key} {value}" for key, value in sorted(summary["counts"].items())))
    print(f"{'STATUS':14} {'CATEGORY':34} {'SURFACE':>8} {'EXECUTED':>9} NOTES")
    for row in summary["rows"]:
        state = str(row.get("final_status") or row.get("status") or "NOT_TESTED")
        category = str(row.get("name") or row.get("category") or row.get("class_id") or "Unknown")
        surface = row.get("test_surface_count", 0)
        executed = row.get("executed", 0)
        note = str(row.get("reason") or row.get("notes") or "")
        print(f"{state:14} {category[:33]:34} {str(surface):>8} {str(executed):>9} {note[:100]}")
    return 0


def cmd_finding(args, store):
    finding = store.get_finding(args.finding_id)
    if not finding:
        print(f"Finding not found: {args.finding_id}"); return 2
    chain = store.get_evidence_chain(args.finding_id)
    if args.format == "json":
        print(json.dumps({"finding": finding, "evidence_chain": chain}, indent=2, ensure_ascii=False, default=str)); return 0
    print("FINDING")
    print("────────────────────────────────────────────")
    print(f"ID: {args.finding_id}")
    state_names={"VERIFIED":"CONFIRMED","CANDIDATE":"UNCONFIRMED","REPRODUCED":"UNCONFIRMED","OBSERVED":"UNCONFIRMED","SIGNAL":"UNCONFIRMED","KILLED":"KILLED","UNTESTABLE":"UNTESTABLE"}
    print(f"Status: {state_names.get(str(finding.get('status','')).upper(), finding.get('status','UNCONFIRMED'))}")
    print(f"Type: {finding.get('category') or finding.get('title') or 'Not recorded'}")
    print(f"Title: {finding.get('title','Not recorded')}")
    print(f"Endpoint: {finding.get('endpoint') or 'Not recorded'}")
    print(f"Parameter: {finding.get('parameter') or 'Not recorded'}")
    print(f"Evidence: {len(chain) or len(finding.get('evidence',[]) or [])}")
    print(f"Severity: {str(finding.get('severity','info')).upper()} · confidence {finding.get('confidence','Not recorded')}")
    print("\nTRACEABILITY")
    if not chain:
        print("No persisted evidence chain is available; this record is not confirmed.")
    for item in chain:
        evidence = item.get("evidence") or {}
        test = item.get("test") or {}
        print(f"  Evidence {item.get('evidence_id')} → Test {item.get('test_id') or 'not recorded'} → {test.get('status','not recorded')}")
        for exchange in item.get("exchanges", [])[:8]:
            _print_http_section("HTTP REQUEST / RESPONSE", [
                f"{exchange.get('method','GET')} {exchange.get('url','')}",
                f"Status: {exchange.get('status') or 'No response'} · {exchange.get('duration_ms',0)} ms",
                f"Request ID: {exchange.get('request_id','not recorded')}",
                f"Response ID: {exchange.get('response_id','not recorded')}",
                "", str(exchange.get('response_body') or "[No response body stored]")])
        if evidence:
            print("Evidence detail:", json.dumps(evidence, ensure_ascii=False, default=str)[:1200])
    print("\nUse `vulnforge export finding %s --format md` for a shareable redacted report." % args.finding_id)
    return 0


def cmd_endpoint(args, store):
    endpoint = store.get_endpoint_detail(args.endpoint_id)
    if not endpoint:
        print(f"Endpoint not found: {args.endpoint_id}"); return 2
    if args.format == "json":
        print(json.dumps(endpoint, indent=2, ensure_ascii=False, default=str)); return 0
    print(f"ENDPOINT #{endpoint.get('id') or endpoint.get('endpoint_id')}")
    print("\n%s %s" % (endpoint.get("method","GET"), endpoint.get("path") or endpoint.get("url","/")))
    print(f"Host: {endpoint.get('host') or 'Not recorded'}")
    print(f"Authentication: {endpoint.get('auth_hint') or 'Not recorded'}")
    print(f"Parameters: {endpoint.get('parameter_count', 'See parameter inventory')}")
    print(f"Requests: {endpoint.get('request_count',0)}")
    print(f"Tests: {endpoint.get('test_count',0)}")
    print(f"Findings: {endpoint.get('finding_count',0)}")
    print("\nRecent Activity:")
    for request in endpoint.get("requests",[])[:20]:
        print(f"  {request.get('method','GET')} {request.get('path','/')} · {request.get('request_id','')} · {request.get('source','')}")
    return 0


def cmd_db(args):
    store = Store(args.db)
    action = args.db_action
    if action == "status":
        data = store.database_status()
        print("DATABASE")
        print(f"Engine: {data['engine']}")
        print(f"Path: {Path(data['path']).expanduser()}")
        print(f"Schema version: {data['schema_version']} · migration: {'APPLIED' if data['migration']['applied'] else 'PENDING'}")
        for key, value in data["counts"].items(): print(f"{key.replace('_',' ').title():22} {value}")
        return 0
    if action == "migrate":
        result = store.migrate(); print(f"Migration {result['migration_id']}: {'APPLIED' if result['applied'] else 'PENDING'}"); return 0
    if action == "backup":
        destination = args.destination or (str(args.db) + ".backup.sqlite")
        print(f"Backup: {store.backup(destination)}"); return 0
    data = store.relational_metrics()
    print(json.dumps(data, indent=2, sort_keys=True)); return 0


def cmd_search(args, store):
    result = store.global_search(args.query, args.limit)
    if args.format == "json": print(json.dumps(result, indent=2, ensure_ascii=False, default=str)); return 0
    print(f"SEARCH · {args.query}")
    for kind, rows in result.items():
        if rows:
            print(f"\n{kind.upper()} ({len(rows)})")
            for row in rows[:args.limit]: print("  " + json.dumps(row, ensure_ascii=False, default=str)[:260])
    if not any(result.values()): print("No data available")
    return 0


def _exchange_to_har_entry(exchange):
    parsed = urlsplit(str(exchange.get("url") or ""))
    return {"startedDateTime": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(exchange.get('timestamp') or time.time())), "time": exchange.get("duration_ms", 0), "request": {"method": exchange.get("method", "GET"), "url": exchange.get("url", ""), "httpVersion": exchange.get("request_version", "HTTP/1.1"), "headers": [{"name": k, "value": v} for k, v in (exchange.get("request_headers") or {}).items()], "queryString": [{"name": k, "value": v} for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]}, "response": {"status": exchange.get("status", 0), "statusText": exchange.get("reason_phrase", ""), "httpVersion": exchange.get("response_version", "HTTP/1.1"), "headers": [{"name": k, "value": v} for k, v in (exchange.get("response_headers") or {}).items()], "content": {"size": len(str(exchange.get("response_body") or "").encode()), "mimeType": next((v for k, v in (exchange.get("response_headers") or {}).items() if k.lower() == "content-type"), "")}}}


def cmd_export(args, store):
    if args.kind == "finding":
        finding = store.get_finding(args.identifier)
        if not finding: print(f"Finding not found: {args.identifier}"); return 2
        doc = {"finding": finding, "evidence_chain": store.get_evidence_chain(args.identifier)}
        default_name = f"finding-{args.identifier}.{args.format}"
        content = json.dumps(doc, indent=2, ensure_ascii=False, default=str)
        if args.format == "md": content = "# " + str(finding.get("title", "Finding")) + "\n\n" + "```json\n" + json.dumps(doc, indent=2, ensure_ascii=False, default=str) + "\n```\n"
        destination = args.out or default_name
    else:
        scan = store.get_scan(args.identifier)
        if scan:
            exchanges = [store.get_exchange(item.get("exchange_id", "")) for item in store.list_exchanges(scan_id=args.identifier, limit=1000, offset=0)]
            exchanges = [item for item in exchanges if item]
            if args.format == "har":
                content = json.dumps({"log": {"version": "1.2", "creator": {"name": "VulnForge", "version": "0.5"}, "entries": [_exchange_to_har_entry(item) for item in exchanges]}}, indent=2, ensure_ascii=False, default=str)
            elif args.format == "raw":
                chunks=[]
                for item in exchanges:
                    parsed=urlsplit(str(item.get("url") or "")); target=parsed.path or "/"; target += (("?"+parsed.query) if parsed.query else "")
                    chunks.append("\\n".join([f"{item.get('method','GET')} {target} HTTP/1.1", *[f"{k}: {v}" for k,v in (item.get('request_headers') or {}).items()], "", str(item.get('request_body') or ""), "", "# RESPONSE", f"HTTP/1.1 {item.get('status') or 0} {item.get('reason_phrase','')}", *[f"{k}: {v}" for k,v in (item.get('response_headers') or {}).items()], "", str(item.get('response_body') or "")]))
                content="\\n\\n".join(chunks)
            else:
                content=json.dumps(exchanges, indent=2, ensure_ascii=False, default=str)
            destination=args.out or f"traffic-{args.identifier}.{args.format}"
            Path(destination).write_text(content, encoding="utf-8")
            print(destination); return 0
        exchange = store.resolve_exchange(args.identifier)
        if not exchange: print(f"HTTP exchange not found: {args.identifier}"); return 2
        if args.format == "raw":
            parsed = urlsplit(str(exchange.get("url") or "")); target = parsed.path or "/"
            if parsed.query: target += "?" + parsed.query
            req = [f"{exchange.get('method','GET')} {target} HTTP/1.1"] + [f"{k}: {v}" for k,v in (exchange.get('request_headers') or {}).items()] + ["", str(exchange.get('request_body') or "")]
            res = [f"HTTP/1.1 {exchange.get('status') or 0} {exchange.get('reason_phrase','')}"] + [f"{k}: {v}" for k,v in (exchange.get('response_headers') or {}).items()] + ["", str(exchange.get('response_body') or "")]
            content = "\n".join(req + ["", "# RESPONSE"] + res)
        elif args.format == "har":
            parsed = urlsplit(str(exchange.get("url") or ""))
            content = json.dumps({"log":{"version":"1.2","creator":{"name":"VulnForge","version":"0.5"},"entries":[{"startedDateTime":time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),"time":exchange.get("duration_ms",0),"request":{"method":exchange.get("method","GET"),"url":exchange.get("url",""),"httpVersion":exchange.get("request_version","HTTP/1.1"),"headers":[{"name":k,"value":v} for k,v in (exchange.get("request_headers") or {}).items()],"queryString":[{"name":k,"value":v} for k,v in urllib.parse.parse_qsl(parsed.query,keep_blank_values=True)]},"response":{"status":exchange.get("status",0),"statusText":exchange.get("reason_phrase",""),"httpVersion":exchange.get("response_version","HTTP/1.1"),"headers":[{"name":k,"value":v} for k,v in (exchange.get("response_headers") or {}).items()],"content":{"size":len(str(exchange.get("response_body") or "").encode()),"mimeType":next((v for k,v in (exchange.get("response_headers") or {}).items() if k.lower()=='content-type'),'' )}}}] }}, indent=2, ensure_ascii=False, default=str)
        else:
            content = json.dumps(exchange, indent=2, ensure_ascii=False, default=str)
        destination = args.out or f"traffic-{args.identifier}.{args.format}"
    Path(destination).write_text(content, encoding="utf-8")
    print(destination); return 0


_BUILTIN_COMMANDS={"scan","tools","status","lab","dashboard","scans","results","report","capture","evidence","resume","findings","coverage","finding","endpoint","db","search","export","history","traffic","requests","request","response","diff","plugins"}


def _scan_id_shortcut_parser():
    parser=argparse.ArgumentParser(prog="vulnforge",description="Open stored data for one scan ID")
    parser.add_argument("scan_id")
    actions=parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--dashboard",action="store_true",help="Open that scan's stored interactive workbench")
    actions.add_argument("--database",action="store_true",help="Show data stored for that scan")
    actions.add_argument("--report",action="store_true",help="Export that scan's report")
    parser.add_argument("--format",choices=["html","pdf","json","md"],default="html")
    parser.add_argument("--out",default="",help="Report output directory")
    parser.add_argument("--db",default=DEFAULT_DB,help=argparse.SUPPRESS)
    parser.add_argument("--verbose",action="store_true",help="Include full stored records and database path")
    return parser


def _redact_display_urls(value,key=""):
    from .core.redaction import redact_url_query_values
    if isinstance(value,dict):
        return {k:(_redact_display_urls(v,str(k).lower())) for k,v in value.items()}
    if isinstance(value,list): return [_redact_display_urls(item,key) for item in value]
    if isinstance(value,str) and (key in {"url","target","endpoint","location","referer"} or key.endswith("_url")):
        return redact_url_query_values(value)
    return value


def _scan_data_sections(bundle):
    report=bundle.get("report") or {}; intel=report.get("intelligence",{}) or {}
    nodes=report.get("asset_nodes",[]) or []; edges=report.get("asset_edges",[]) or []
    exchanges=bundle.get("exchanges",[]) or []
    findings=(report.get("findings",[]) or [])+(report.get("candidates",[]) or [])
    tests=report.get("tests",[]) or []; plans=report.get("test_plan",[]) or []
    controls=[]; differentials=[]
    def collect(obj,needle,out,prefix=""):
        if isinstance(obj,dict):
            for key,val in obj.items():
                current=f"{prefix}.{key}" if prefix else str(key)
                if needle in str(key).lower(): out.append({"path":current,"value":val})
                elif isinstance(val,(dict,list)): collect(val,needle,out,current)
        elif isinstance(obj,list):
            for index,val in enumerate(obj): collect(val,needle,out,f"{prefix}[{index}]")
    for test in tests:
        collect(test,"control",controls,str(test.get("test_id",test.get("type","test"))))
        collect(test,"differential",differentials,str(test.get("test_id",test.get("type","test"))))
    for plan in plans:
        methodology=plan.get("methodology",{}) if isinstance(plan,dict) else {}
        for control in methodology.get("negative_controls",[]) if isinstance(methodology,dict) else []:
            controls.append({"test_id":plan.get("test_id"),"kind":"planned negative control","value":control})
    hosts=[]
    dns=intel.get("dns",{}) or {}
    if dns.get("hostname"): hosts.append({"hostname":dns.get("hostname"),"addresses":dns.get("observed_addresses",[])})
    for node in nodes:
        if str(node.get("asset_type","")).lower() in {"host","hostname","domain","ip","ip-address"}:
            hosts.append(node)
    observations=(report.get("discovery_signals",[]) or [])+(report.get("live_observations",[]) or [])
    return {
        "TARGET":[{"url":report.get("scan",{}).get("target") or bundle.get("scan",{}).get("target"),"profile":bundle.get("scan",{}).get("profile"),"status":bundle.get("scan",{}).get("status")}],
        "ASSETS":nodes+edges,"HOSTS":hosts,"SERVICES":intel.get("services",[]) or [],
        "TECHNOLOGIES":report.get("technologies",[]) or [],"ENDPOINTS":report.get("endpoints",[]) or [],
        "PARAMETERS":report.get("parameters",[]) or [],
        "REQUESTS":[{k:e.get(k) for k in ("request_id","exchange_id","method","url","module","duration_ms","request_body","request_headers")} for e in exchanges],
        "RESPONSES":[{k:e.get(k) for k in ("response_id","exchange_id","status","reason_phrase","response_headers","response_body","error","duration_ms")} for e in exchanges],
        "OBSERVATIONS":observations,"HYPOTHESES":report.get("hypotheses",[]) or [],"TESTS":tests,
        "CONTROLS":controls,"DIFFERENTIALS":differentials,
        "EVIDENCE":bundle.get("evidence_records",[]) or [],"FINDINGS":findings,
        "EVENTS":bundle.get("events",[]) or [],
    }


def cmd_scan_database(scan_id,store,*,verbose=False):
    bundle=store.get_scan_bundle(scan_id)
    if bundle is None:
        print(f"Error: scan ID not found: {scan_id}. Run `vulnforge results` to list saved scans.",file=sys.stderr)
        return 2
    from .core.redaction import redact_any
    safe_bundle=redact_any(_redact_display_urls(bundle))
    if verbose:
        safe_bundle["storage"]={"database_path":str(Path(store.path).resolve())}
        print(json.dumps(safe_bundle,indent=2,ensure_ascii=False,default=str))
        return 0
    scan=bundle["scan"]
    print(f"SCAN DATABASE · {scan_id}")
    print(f"Status: {scan.get('status','unknown')} · Target: {_redact_display_urls(scan.get('target',''), 'target')}")
    print(f"Profile: {scan.get('profile','unknown')} · Started: {time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(scan.get('started_at') or 0))}")
    print("Stored sections (full exchange bodies are available in --dashboard; use --verbose for complete JSON):")
    for title,records in _scan_data_sections(safe_bundle).items():
        print(f"\n{title} · {len(records)} record(s)")
        for record in records[:20]:
            if isinstance(record,dict):
                compact={k:v for k,v in record.items() if k not in {"request_body","response_body"}}
                text=json.dumps(compact,ensure_ascii=False,default=str)
            else: text=str(record)
            print("  "+text[:220])
        if len(records)>20: print(f"  … {len(records)-20} more; use --verbose for all records")
    return 0


def cmd_scan_id(args,store):
    scan=store.get_scan(args.scan_id)
    if scan is None:
        print(f"Error: scan ID not found: {args.scan_id}. Run `vulnforge results` to list saved scans.",file=sys.stderr)
        return 2
    if args.dashboard:
        from .cli_ui import run_stored_scan_dashboard
        return 0 if run_stored_scan_dashboard(args.scan_id,store) else 2
    if args.database:
        return cmd_scan_database(args.scan_id,store,verbose=args.verbose)
    report=store.get_report(args.scan_id)
    if report is None:
        print(f"Error: no stored report is available for scan ID {args.scan_id}.",file=sys.stderr)
        return 2
    out=Path(args.out or Path("reports")/args.scan_id); out.mkdir(parents=True,exist_ok=True)
    writer={"html":write_html_report,"pdf":write_pdf_report,"json":write_json_report,"md":write_markdown_report}[args.format]
    extension="md" if args.format=="md" else args.format
    destination=out/f"report.{extension}"
    print(writer(report,str(destination)))
    return 0


def main(argv=None):
    raw_argv=list(sys.argv[1:] if argv is None else argv)
    # Preserve the pre-0.5 `request show ID` spelling while making the
    # documented `request ID` form the canonical parser shape.
    if len(raw_argv) >= 3 and raw_argv[0] in {"request", "response"} and raw_argv[1] == "show":
        raw_argv = [raw_argv[0], raw_argv[2], *raw_argv[3:]]
    try:
        if raw_argv and not raw_argv[0].startswith("-") and raw_argv[0] not in _BUILTIN_COMMANDS:
            shortcut=_scan_id_shortcut_parser().parse_args(raw_argv)
            return cmd_scan_id(shortcut,Store(shortcut.db))
        args=build_parser().parse_args(raw_argv)
        if args.command=="scan": return cmd_scan(args)
        if args.command=="tools": return cmd_tools()
        if args.command=="lab": return cmd_lab(args)
        if args.command=="dashboard": return cmd_dashboard(args)
        if args.command in ("status","scans","results"): return cmd_status(Store(args.db))
        if args.command=="report": return cmd_report(args,Store(args.db))
        if args.command=="capture" and args.capture_command=="import-har": return cmd_capture_import(args,Store(args.db))
        if args.command=="evidence": return cmd_evidence(args.identifier,Store(args.db))
        if args.command=="history": return cmd_history(args,Store(args.db))
        if args.command in {"traffic", "requests"}: return cmd_history(args,Store(args.db))
        if args.command=="request": return cmd_exchange_view("request",args.exchange_id,Store(args.db))
        if args.command=="response": return cmd_exchange_view("response",args.exchange_id,Store(args.db))
        if args.command=="finding": return cmd_finding(args,Store(args.db))
        if args.command=="endpoint": return cmd_endpoint(args,Store(args.db))
        if args.command=="db": return cmd_db(args)
        if args.command=="search": return cmd_search(args,Store(args.db))
        if args.command=="export": return cmd_export(args,Store(args.db))
        if args.command=="diff": return cmd_diff(args.exchange_a,args.exchange_b,Store(args.db),args.format)
        if args.command=="coverage": return cmd_coverage(args,Store(args.db))
        if args.command=="findings":
            finding_store=Store(args.db)
            scan_id=args.scan_id or (finding_store.list_scans()[0]["scan_id"] if finding_store.list_scans() else None)
            if not scan_id: print("No stored scans."); return 0
            rows=finding_store.get_findings(scan_id)
            if args.format=="json": print(json.dumps(rows,indent=2))
            else:
                state_names={"VERIFIED":"CONFIRMED","CANDIDATE":"UNCONFIRMED","REPRODUCED":"UNCONFIRMED","OBSERVED":"UNCONFIRMED","SIGNAL":"UNCONFIRMED","KILLED":"KILLED","UNTESTABLE":"UNTESTABLE"}
                for f in rows:
                    state=state_names.get(str(f.get('status','')).upper(), str(f.get('status','UNKNOWN')).upper())
                    print(f"[{state:10}] {f['severity'].upper():8} {f['title']} {f.get('endpoint','')}")
                print(f"{sum(1 for x in rows if x.get('status')=='VERIFIED')} confirmed · {sum(1 for x in rows if x.get('status')!='VERIFIED')} unconfirmed/observation record(s)")
            return 0
        if args.command=="plugins":
            from .plugins.base import load_builtin_plugins
            for p in load_builtin_plugins(): print(f"{p.id:34} {'PASSIVE' if p.passive else 'ACTIVE'}  {p.name}")
            return 0
        if args.command=="resume":
            store=Store(args.db); row=store.get_scan(args.scan_id) if args.scan_id else (store.list_scans()[0] if store.list_scans() else None)
            if not row: print("No scan available to resume."); return 2
            print(f"Restarting assessment for {row['target']}; this creates a new scan ID (previous observations are retained).")
            return main(["scan",row["target"],"--yes","--db",args.db])
        build_parser().print_help(); return 0
    except (ValueError,PermissionError) as e:
        print(f"Error: {e}",file=sys.stderr); return 2

if __name__=="__main__": raise SystemExit(main())
