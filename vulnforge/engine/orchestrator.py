"""
VulnForge — scan orchestrator (spec §52).

Runs the pipeline as explicit stages over a shared ScanContext:

  AuthGate → HttpConfigure → PassiveRecon → Crawl → JsAnalysis →
  Inventory → TechDetect → PassiveChecks → (later phases: ActiveCheck,
  Verify, Correlate, Risk) → Persist

Every stage is small, independently testable, receives the context, and
returns it mutated. The orchestrator owns:
  • stage ordering & progress events
  • the emergency-stop checks between stages
  • structured statistics for the report
"""
from __future__ import annotations

import asyncio
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin, urlsplit

from ..core.models import ScanContext, ScanStats
from ..core.profiles import Profile, get_profile
from .crawler import Crawler
from .fingerprint import fingerprint_pages
from .inventory import InventoryBuilder, make_endpoint
from .jsanalysis import analyze_js
from .normalize import canonicalize


@dataclass
class ScanConfig:
    target: str
    profile_name: str = "standard"
    allowed_hosts: List[str] = field(default_factory=list)
    allowed_ips: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    allowed_prefixes: List[str] = field(default_factory=list)
    excluded_hosts: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    excluded_params: List[str] = field(default_factory=list)
    allowed_methods: List[str] = field(default_factory=lambda: ["GET", "HEAD", "OPTIONS"])
    not_before: Optional[float] = None
    expires_at: Optional[float] = None
    allow_private: bool = False
    authorization_confirmed: bool = False
    verify_tls: bool = True
    request_timeout: float = 10.0
    extra_headers: Dict[str, str] = field(default_factory=dict)
    identity_headers: Dict[str, str] = field(default_factory=dict)
    original_target: str = ""
    request_rate: Optional[float] = None
    request_budget: Optional[int] = None
    active_requested: bool = False
    auto_scheme: bool = False
    auth_data: Dict[str, Any] = field(default_factory=dict)
    test_profile: str = "full"
    test_profile_explicit: bool = False
    verbose: bool = False
    scan_id: str = ""
    store_sensitive_http: bool = False


@dataclass
class ScanResult:
    context: ScanContext
    stage_timings: Dict[str, float] = field(default_factory=dict)
    aborted: bool = False
    report_paths: Dict[str, str] = field(default_factory=dict)


class Stage:
    name = "stage"
    title = "Stage"

    async def run(self, ctx: ScanContext) -> ScanContext:  # pragma: no cover
        raise NotImplementedError


# ---------------------------------------------------------------------------
class AuthGateStage(Stage):
    name, title = "auth", "Authorization & scope validation"

    async def run(self, ctx: ScanContext) -> ScanContext:
        auth = ctx.authorization
        from .normalize import canonicalize
        original=ctx.config.original_target or ctx.config.target
        raw_parts=urlsplit(ctx.config.target)
        if raw_parts.username or raw_parts.password:
            raise ValueError("Credentials in target URLs are not accepted.")
        normalized=canonicalize(ctx.config.target,drop_tracking=False)
        parsed=urlsplit(normalized)
        if parsed.scheme not in ("http","https") or not parsed.hostname:
            raise ValueError("Target normalization requires a valid HTTP(S) target.")
        ctx.config.original_target=original
        ctx.config.target=normalized
        ctx.target_normalization={"original_input":original,"normalized_target":normalized,
            "scheme":parsed.scheme,"host":parsed.hostname,"port":parsed.port or (443 if parsed.scheme=="https" else 80)}
        auth.require_confirmation()
        ok, reason = auth.check(ctx.config.target, purpose="primary-target")
        if not ok:
            raise PermissionError(f"Target refused by scope: {reason}")
        auth.note("scan_start", f"target={ctx.config.target} profile={ctx.config.profile_name}")
        ctx.emit("stage", f"Scope validated ({len(auth.allowed_hosts)} host rules, "
                          f"{len(auth.excluded_path_res)} excluded paths)")
        return ctx


class HttpConfigureStage(Stage):
    name, title = "http", "HTTP configuration"

    async def run(self, ctx: ScanContext) -> ScanContext:
        from ..http.client import Requester
        from ..core.profiles import get_profile
        profile = get_profile(ctx.config.profile_name)
        if ctx.config.request_rate is not None or ctx.config.request_budget is not None:
            from dataclasses import replace
            profile = replace(profile,
                requests_per_second=ctx.config.request_rate if ctx.config.request_rate is not None else profile.requests_per_second,
                max_requests=ctx.config.request_budget if ctx.config.request_budget is not None else profile.max_requests)
        ctx.requester = Requester(
            authorization=ctx.authorization,
            profile=profile,
            verify_tls=ctx.config.verify_tls,
            timeout=ctx.config.request_timeout,
            extra_headers=ctx.config.extra_headers,
            identity_headers=ctx.config.identity_headers,
        )
        def publish_exchange(exchange):
            path=urlsplit(exchange.url).path or "/"
            ctx.emit("http-exchange",f"{exchange.method} {path} → {exchange.status or 'NO RESPONSE'}",
                exchange=exchange.to_dict(),exchange_id=exchange.exchange_id,method=exchange.method,
                url=exchange.url,status=exchange.status,module=exchange.module,
                duration_ms=exchange.duration_ms,error=exchange.error,
                response_chars=len(exchange.response_body or ""))
        ctx.requester.on_exchange=publish_exchange
        ctx.emit("stage", f"HTTP ready (rps={profile.requests_per_second}, "
                          f"concurrency={profile.max_concurrency}, "
                          f"budget={profile.max_requests})")
        return ctx


class TargetServiceStage(Stage):
    name, title = "services", "HTTP and HTTPS service discovery"

    async def run(self, ctx: ScanContext) -> ScanContext:
        import socket
        from urllib.parse import urlsplit, urlunsplit
        target = ctx.config.target
        p = urlsplit(target)
        try:
            addresses=sorted({row[4][0] for row in socket.getaddrinfo(p.hostname,None,type=socket.SOCK_STREAM)})
        except (OSError,UnicodeError):
            addresses=[]
        ctx.observed_ips=addresses
        ctx.emit("stage", f"DNS address lookup: {len(addresses)} A/AAAA address(es) observed via system resolver")
        if not ctx.config.auto_scheme:
            ctx.emit("stage", "Scheme explicitly supplied; alternate scheme not probed")
            return ctx
        primary = await ctx.requester.send("HEAD", target, module="service-discovery")
        # Bare host input allows a same-host, default-port alternate-scheme check.
        if p.port is not None:
            ctx.emit("stage", "Explicit port supplied; alternate scheme not assumed")
            return ctx
        other = "http" if p.scheme == "https" else "https"
        alt = urlunsplit((other, p.netloc, p.path or "/", p.query, ""))
        alternate = await ctx.requester.send("HEAD", alt, module="service-discovery")
        primary_failed = not primary.ok
        if primary_failed and alternate.ok:
            ctx.config.target = alt
            ctx.emit("stage", f"Primary {p.scheme.upper()} unavailable; observed {other.upper()} service selected")
        else:
            ctx.emit("stage", f"Observed {p.scheme.upper()} and {other.upper()} availability")
        return ctx


class PassiveReconStage(Stage):
    """robots.txt + sitemap.xml — read-only, in-scope of course."""
    name, title = "recon", "Passive reconnaissance"

    async def run(self, ctx: ScanContext) -> ScanContext:
        import html
        from ..http.client import ScanAborted
        base = _base(ctx.config.target)
        found: List[str] = []
        provenance: Dict[str,List[str]] = {}
        if ctx.requester.budget.sent>=ctx.requester.budget.max_requests or ctx.authorization.stopped:
            if ctx.requester.budget.sent>=ctx.requester.budget.max_requests and not ctx.authorization.stopped:
                ctx.authorization.stop("request budget exhausted")
            ctx.pages_seed=[]; ctx.seed_provenance={}
            return ctx
        try:
            robots = await ctx.requester.send("GET", urljoin(base, "/robots.txt"), module="recon")
        except ScanAborted:
            ctx.pages_seed=[]; ctx.seed_provenance={}
            return ctx
        sitemap_urls: List[str] = []
        if robots.ok and robots.status == 200 and "text" in (robots.header("content-type") or "text"):
            for line in robots.response_body.splitlines():
                clean=line.split("#",1)[0].strip()
                if clean.lower().startswith(("disallow:", "allow:")):
                    path = clean.split(":", 1)[1].strip()
                    if path and path != "/" and "*" not in path and len(found) < 25:
                        url=urljoin(base,path); found.append(url)
                        provenance.setdefault(url,[]).append(robots.exchange_id)
                elif clean.lower().startswith("sitemap:"):
                    candidate=clean.split(":",1)[1].strip()
                    if candidate:
                        sitemap_urls.append(urljoin(base,candidate))
        if not sitemap_urls:
            sitemap_urls = [urljoin(base, "/sitemap.xml")]

        # Bounded sitemap-index support: at most four XML documents total and
        # sixty page URLs; all requests still pass the shared scope/budget gate.
        queue=list(dict.fromkeys(sitemap_urls))[:2]
        seen_sitemaps=set()
        documents_fetched=0
        while queue and documents_fetched<4 and len(found)<85 and not ctx.authorization.stopped:
            sm=queue.pop(0)
            if sm in seen_sitemaps:
                continue
            if ctx.requester.budget.sent>=ctx.requester.budget.max_requests:
                ctx.authorization.stop("request budget exhausted")
                break
            seen_sitemaps.add(sm)
            try:
                sm_ex=await ctx.requester.send("GET",sm,module="recon")
            except ScanAborted:
                break
            documents_fetched+=1
            if not sm_ex.ok or sm_ex.status!=200:
                continue
            locs=[]
            for raw_loc in re.findall(r"<(?:[A-Za-z0-9_-]+:)?loc\b[^>]*>(.*?)</(?:[A-Za-z0-9_-]+:)?loc\s*>",sm_ex.response_body,re.I|re.S):
                loc=html.unescape(re.sub(r"<[^>]*>","",raw_loc)).strip()
                if loc and len(loc)<=4096:
                    locs.append(urljoin(sm,loc))
            is_index=bool(re.search(r"<(?:[A-Za-z0-9_-]+:)?sitemapindex\b",sm_ex.response_body,re.I))
            if is_index:
                for loc in locs:
                    if len(queue)+documents_fetched>=4:
                        break
                    if loc not in seen_sitemaps and loc not in queue:
                        queue.append(loc)
            else:
                for loc in locs[:60]:
                    found.append(loc)
                    provenance.setdefault(loc,[]).append(sm_ex.exchange_id)
                    if len(found)>=85:
                        break
        ctx.pages_seed = [u for u in dict.fromkeys(found)]
        ctx.seed_provenance=provenance
        ctx.emit("stage", f"Recon: robots.txt={'yes' if robots.ok and robots.status == 200 else 'no'}, "
                          f"{len(ctx.pages_seed)} URL hints from robots/sitemap; {documents_fetched} sitemap document(s) fetched")
        return ctx


class CrawlStage(Stage):
    name, title = "crawl", "Crawling"

    async def run(self, ctx: ScanContext) -> ScanContext:
        profile = get_profile(ctx.config.profile_name)
        def crawl_event(kind, message, **data):
            data.update({"requests_used":ctx.requester.budget.sent,
                         "request_budget":ctx.requester.budget.max_requests,
                         "current_rps":ctx.requester.limiter.current_rps,
                         "request_errors":ctx.requester.stats()["errors"]})
            ctx.emit(kind,message,**data)
        crawler = Crawler(ctx.requester, ctx.authorization, profile, emit=crawl_event)
        seeds = [ctx.config.target] + list(getattr(ctx, "pages_seed", []))
        result = await crawler.run(seeds)
        ctx.pages = result.pages
        ctx._crawl_result = result
        ctx.stats.pages_crawled = len(result.pages)
        if ctx.authorization.stopped:
            ctx.stop_reason=ctx.stop_reason or ctx.authorization.stop_reason
        ctx.stats.crawl_errors = result.errors
        ctx.stats.crawl_cancelled = result.cancelled
        ctx.stats.crawl_timeouts = result.timeouts
        ctx.stats.crawl_scope_rejected = result.scope_rejected
        ctx.stats.crawl_budget_rejected = result.budget_rejected
        ctx.crawl_status_counts = dict(result.status_counts)
        from .live import classify_live_state
        from ..core.redaction import redact_any, redact_url
        ctx.live_observations=[]
        for outcome in result.outcomes:
            exchange=outcome.exchange
            status=exchange.status if exchange and exchange.status else None
            error=(outcome.error or (exchange.error if exchange else ""))
            ctx.live_observations.append({
                "request_id":exchange.exchange_id if exchange else "",
                "method":exchange.method if exchange else "GET",
                "url":redact_url(exchange.url if exchange else outcome.url),
                "final_url":redact_url(exchange.url) if exchange else "",
                "status":status,
                "content_type":exchange.header("content-type") if exchange else "",
                "live_state":classify_live_state(status,error,
                    getattr(exchange,"redirect_chain",[]) if exchange else []),
                "crawl_status":outcome.status,
                "source":"static-crawler",
                "error":redact_any(error) if error else "",
                "redirect_chain":redact_any(getattr(exchange,"redirect_chain",[])) if exchange else [],
            })
        live_counts={}
        for observation in ctx.live_observations:
            state=observation["live_state"]
            live_counts[state]=live_counts.get(state,0)+1
        ctx.live_state_counts=live_counts
        counts_text=", ".join(f"{key} {live_counts[key]}" for key in sorted(live_counts)) or "no classified responses"
        ctx.emit("stage", f"Crawl: {len(result.pages)} pages, {len(result.js_assets)} JS assets; "
                          f"{result.errors} errors, {result.cancelled} cancelled; reachability: {counts_text}")
        return ctx


class JsAnalysisStage(Stage):
    name, title = "js", "JavaScript analysis"

    async def run(self, ctx: ScanContext) -> ScanContext:
        result = getattr(ctx, "_crawl_result", None)
        js_urls = sorted(result.js_assets) if result else []
        total_candidates: set = set()
        candidate_sources: Dict[str,set] = {}
        analyzed = 0
        # analyze inline JS of pages too (cheap: regex over bodies)
        for ex in ctx.pages:
            body = ex.response_body or ""
            if "<script" in body:
                for chunk in re.findall(r"<script[^>]*>(.*?)</script>", body, re.S | re.I):
                    if len(chunk.strip()) < 20:
                        continue
                    sigs, cands = analyze_js(f"inline:{ex.url}", chunk, ex.url)
                    ctx.signals.extend(sigs)
                    total_candidates |= cands
                    for candidate in cands:
                        candidate_sources.setdefault(candidate,set()).add(ex.exchange_id)
        for js_url in js_urls[:40]:
            if ctx.stopped:
                break
            ex = await ctx.requester.send("GET", js_url, module="js-analysis")
            if not ex.ok:
                continue
            analyzed += 1
            sigs, cands = analyze_js(js_url, ex.response_body, js_url)
            ctx.signals.extend(sigs)
            total_candidates |= cands
            for candidate in cands:
                candidate_sources.setdefault(candidate,set()).add(ex.exchange_id)
        ctx._js_candidates = sorted(total_candidates)
        ctx._js_candidate_sources={key:sorted(value) for key,value in candidate_sources.items()}
        ctx.js_analyzed = analyzed
        ctx.stats.signals = len(ctx.signals)
        ctx.emit("stage", f"JS: {analyzed} bundles + inline analyzed, "
                          f"{len(ctx.signals)} signals, {len(total_candidates)} URL candidates")
        return ctx


class FrontendIntelligenceStage(Stage):
    name, title = "frontend-intel", "Frontend intelligence aggregation"
    async def run(self,ctx):
        result=getattr(ctx,"_crawl_result",None)
        signal_counts={}
        for signal in ctx.signals:
            signal_counts[signal.kind]=signal_counts.get(signal.kind,0)+1
        ctx.frontend_intelligence={
            "javascript_assets_observed":len(result.js_assets) if result else 0,
            "javascript_assets_analyzed":ctx.js_analyzed,
            "signals_by_kind":signal_counts,
            "candidate_urls":len(getattr(ctx,"_js_candidates",[])),
            "browser_execution":"NOT_TESTED",
        }
        ctx.emit("stage",f"Frontend intelligence: {ctx.frontend_intelligence['javascript_assets_observed']} assets observed; "
                  f"{len(ctx.signals)} evidence-linked static signals; browser execution not tested")
        return ctx


class InventoryStage(Stage):
    name, title = "inventory", "Endpoint & parameter inventory"

    async def run(self, ctx: ScanContext) -> ScanContext:
        from ..core.models import Signal
        builder = InventoryBuilder()
        result = getattr(ctx, "_crawl_result", None)
        if result:
            builder.from_crawler(result)
        seeds = getattr(ctx, "pages_seed", [])
        if seeds:
            seed_endpoints=builder.from_url_list(seeds, "robots/sitemap")
            seed_provenance=getattr(ctx,"seed_provenance",{})
            for endpoint in seed_endpoints:
                source_refs=[]
                for raw_url,refs in seed_provenance.items():
                    if canonicalize(raw_url)==endpoint.url:
                        source_refs.extend(refs)
                endpoint.evidence_ids=sorted(set(endpoint.evidence_ids+source_refs))
        # JS-discovered candidates: same-host only, scope-checked
        js_sources=getattr(ctx,"_js_candidate_sources",{})
        for cand in getattr(ctx, "_js_candidates", []):
            ok, reason = ctx.authorization.check(cand, purpose="js-candidate",method="GET")
            if ok:
                candidates=builder.from_url_list([cand], "javascript")
                for endpoint in candidates:
                    endpoint.scope_status="IN_SCOPE"
                    endpoint.evidence_ids=sorted(set(endpoint.evidence_ids+js_sources.get(cand,[])))
            else:
                ctx.signals.append(Signal("out_of_scope_candidate",f"JavaScript URL candidate not inventoried because scope rejected it ({reason})",source="javascript-static-analysis",url=cand))
        for ep in builder.endpoints:
            allowed,reason=ctx.authorization.check(ep.url,purpose="endpoint-inventory",method=ep.method)
            ep.scope_status="IN_SCOPE" if allowed else "OUT_OF_SCOPE"
            ep.scope_reason="" if allowed else reason
            ctx.add_endpoint(ep)
        ctx.stats.endpoints_discovered = len(ctx.endpoints)
        ctx.stats.parameters_discovered = len(ctx.parameters)
        ctx.emit("stage", f"Inventory: {len(ctx.endpoints)} endpoints, "
                          f"{len(ctx.parameters)} parameters")
        return ctx


class TechDetectStage(Stage):
    name, title = "tech", "Technology detection"

    async def run(self, ctx: ScanContext) -> ScanContext:
        result = getattr(ctx, "_crawl_result", None)
        pages = result.parsed if result else []
        fingerprint_pages(ctx, pages)
        ctx.emit("stage", f"Tech: {len(ctx.technologies)} technologies identified")
        return ctx


class IntelligenceStage(Stage):
    name, title = "intelligence", "Passive target intelligence"

    async def run(self, ctx: ScanContext) -> ScanContext:
        from .intelligence import collect_intelligence
        data = collect_intelligence(ctx)
        ctx.emit("stage", f"Intelligence: {len(data['services'])} observed services, "
                          f"{len(data['cookies'])} cookie names; unavailable facts remain unknown")
        return ctx


class ApiModelStage(Stage):
    name, title = "api-model", "Endpoint and API model"
    async def run(self, ctx):
        from urllib.parse import urlsplit
        from .api_schema import parse_openapi_json
        ctx.api_inventory=[]
        for ep in ctx.endpoints.values():
            path=urlsplit(ep.url).path
            low=path.lower()
            indicators=[]
            if low.startswith("/api") or "/api/" in low: indicators.append("API-like path")
            if any(x in low for x in ("openapi","swagger","graphql")): indicators.append("API schema/route term")
            if indicators:
                ctx.api_inventory.append({"endpoint":ep.url,"method":ep.method,
                    "signals":indicators,"source":ep.source,"contract":"NOT DETERMINED"})

        # Fetch only schema-like links explicitly observed in parsed same-scan
        # pages. The central Requester rechecks authorization, scope, budget,
        # redirects, stop state, and response size for every document request.
        result=getattr(ctx,"_crawl_result",None)
        candidates={}
        if result:
            import re
            schema_path=re.compile(r"(?:openapi|swagger|api[-_]?docs)(?:[-_.][^/]*)?$|/v\d+/api-docs(?:\.[^/]*)?$",re.I)
            for page,parser in result.parsed:
                for link in parser.links:
                    path=urlsplit(link).path.rstrip("/")
                    low_path=path.lower()
                    basename=low_path.rsplit("/",1)[-1]
                    json_or_known_route=low_path.endswith(".json") or basename in {"openapi","swagger","api-docs"} or re.search(r"/v[0-9]+/api-docs$",low_path)
                    if json_or_known_route and not low_path.endswith((".yaml",".yml")) and schema_path.search(path):
                        candidates.setdefault(link,page.exchange_id)
        if hasattr(ctx, "_js_candidates"):
            import re
            schema_path_js=re.compile(r"(?:openapi|swagger|api[-_]?docs)(?:[-_.][^/]*)?$|/v\d+/api-docs(?:\.[^/]*)?$",re.I)
            js_sources=getattr(ctx,"_js_candidate_sources",{})
            for link in getattr(ctx,"_js_candidates",[]):
                path=urlsplit(link).path.rstrip("/")
                low_path=path.lower()
                basename=low_path.rsplit("/",1)[-1]
                json_or_known_route=low_path.endswith(".json") or basename in {"openapi","swagger","api-docs"} or re.search(r"/v[0-9]+/api-docs$",low_path)
                if json_or_known_route and not low_path.endswith((".yaml",".yml")) and schema_path_js.search(path):
                    src_ids=js_sources.get(link,[])
                    candidates.setdefault(link,src_ids[0] if src_ids else "")
        ctx.api_documents=[]
        for url,source_exchange_id in list(candidates.items())[:3]:
            if ctx.authorization.stopped or ctx.requester.budget.sent>=ctx.requester.budget.max_requests:
                break
            allowed,reason=ctx.authorization.check(url,purpose="api-schema")
            if not allowed:
                ctx.api_documents.append({"document_url":url,"status":"SCOPE_REJECTED",
                    "source_exchange_id":source_exchange_id,"reason":reason})
                continue
            exchange=await ctx.requester.send("GET",url,module="api-schema")
            if not exchange.ok or exchange.status!=200:
                ctx.api_documents.append({"document_url":url,"status":"FETCH_FAILED",
                    "source_exchange_id":source_exchange_id,"exchange_id":exchange.exchange_id,
                    "http_status":exchange.status,"error":exchange.error or "non-200 response"})
                continue
            document=parse_openapi_json(exchange.response_body,document_url=exchange.url,
                                        exchange_id=exchange.exchange_id)
            document["source_exchange_id"]=source_exchange_id
            ctx.api_documents.append(document)
            if document.get("status")=="PARSED":
                for operation in document.get("operations",[]):
                    ctx.api_inventory.append({**operation,"document_url":document["document_url"],
                        "exchange_id":exchange.exchange_id,"source_exchange_id":source_exchange_id,
                        "contract":"DECLARED_NOT_VALIDATED"})
        declared=sum(1 for item in ctx.api_inventory if item.get("contract")=="DECLARED_NOT_VALIDATED")
        ctx.emit("stage",f"API model: {len(ctx.api_inventory)-declared} observed API-like endpoint(s); "
                  f"{declared} declared operation(s) from {len(ctx.api_documents)} linked document(s), not validated")
        return ctx


class ApplicationModelStage(Stage):
    name, title = "application-model", "Application model construction"
    async def run(self,ctx):
        import hashlib
        from urllib.parse import urlsplit
        from ..core.models import ApplicationModel
        def ident(kind,value):
            return "asset-"+hashlib.sha256((str(kind)+":"+str(value)).encode()).hexdigest()[:12]
        services=ctx.intelligence.get("services",[])
        service_urls=sorted({str(x.get("url")) for x in services if x.get("url")})
        endpoints=[]; out_of_scope_endpoints=[]; parameters=[]; relationships=[]; evidence=[]
        app_id=ident("APPLICATION",urlsplit(ctx.config.target).netloc)
        service_ids={}
        for service in service_urls:
            service_id=ident("WEB_SERVICE",service); service_ids[service]=service_id
            relationships.append({"source_id":app_id,"target_id":service_id,"relation":"contains-service"})

        page_ids=[]
        page_id_by_exchange={}
        for page in ctx.pages:
            page_id=ident("PAGE",page.url); page_ids.append(page_id)
            page_id_by_exchange[page.exchange_id]=page_id
            service=f"{urlsplit(page.url).scheme}://{urlsplit(page.url).netloc}"
            if service in service_ids:
                relationships.append({"source_id":service_ids[service],"target_id":page_id,
                                      "relation":"serves-page"})
            evidence.append(page.exchange_id)

        js_asset_ids=[]
        crawl=getattr(ctx,"_crawl_result",None)
        if crawl:
            for js_url in sorted(crawl.js_assets):
                js_id=ident("JAVASCRIPT_ASSET",js_url); js_asset_ids.append(js_id)
                for page,parser in crawl.parsed:
                    if js_url in parser.assets:
                        relationships.append({"source_id":ident("PAGE",page.url),"target_id":js_id,
                                              "relation":"loads-script","evidence_id":page.exchange_id})
                        evidence.append(page.exchange_id)

        api_doc_ids=[]
        for document in getattr(ctx,"api_documents",[]):
            doc_url=str(document.get("document_url", ""))
            if not doc_url:
                continue
            doc_id=ident("API_DOCUMENT",doc_url); api_doc_ids.append(doc_id)
            source_page=page_id_by_exchange.get(document.get("source_exchange_id"))
            if source_page:
                relationships.append({"source_id":source_page,"target_id":doc_id,
                                      "relation":"links-api-document",
                                      "evidence_id":str(document.get("source_exchange_id", ""))})
            if document.get("exchange_id"):
                evidence.append(str(document["exchange_id"]))

        declared_operation_ids=[]
        for operation in getattr(ctx,"api_inventory",[]):
            if operation.get("contract")!="DECLARED_NOT_VALIDATED":
                continue
            doc_url=str(operation.get("document_url", ""))
            operation_key="|".join((doc_url,str(operation.get("method","")),
                                    str(operation.get("path","")),str(operation.get("operation_id",""))))
            operation_id=ident("DECLARED_API_OPERATION",operation_key)
            declared_operation_ids.append(operation_id)
            doc_id=ident("API_DOCUMENT",doc_url)
            relationships.append({"source_id":doc_id,"target_id":operation_id,
                                  "relation":"declares-operation",
                                  "evidence_id":str(operation.get("exchange_id", "")),
                                  "validation_status":"DECLARED_NOT_VALIDATED"})

        for ep in ctx.endpoints.values():
            endpoint_id=ident("ENDPOINT",ep.method+":"+ep.normalized)
            if ep.scope_status=="IN_SCOPE":
                endpoints.append(endpoint_id)
            else:
                out_of_scope_endpoints.append(endpoint_id)
                relationships.append({"source_id":app_id,"target_id":endpoint_id,
                    "relation":"observed-out-of-scope-declaration","scope_status":ep.scope_status})
            service=f"{urlsplit(ep.url).scheme}://{urlsplit(ep.url).netloc}"
            if service in service_ids and ep.scope_status=="IN_SCOPE":
                relationships.append({"source_id":service_ids[service],"target_id":endpoint_id,"relation":"exposes-endpoint"})
            exchange_ids=list(ep.evidence_ids)
            evidence.extend(exchange_ids)
            for param in ep.params:
                parameter_id=ident("PARAMETER",param.key()); parameters.append(parameter_id)
                relationships.append({"source_id":endpoint_id,"target_id":parameter_id,"relation":"accepts-parameter"})
        for tech in ctx.technologies.values():
            relationships.append({"source_id":app_id,"target_id":ident("TECHNOLOGY",tech.name),"relation":"observed-technology"})
        ctx.application_model=ApplicationModel(
            application_id=app_id,target=ctx.config.target,service_urls=service_urls,
            endpoint_ids=sorted(set(endpoints)),parameter_ids=sorted(set(parameters)),
            technologies=sorted(t.name for t in ctx.technologies.values()),
            relationships=relationships,evidence_ids=sorted(set(evidence)),completeness="PARTIAL",
            observed_page_ids=sorted(set(page_ids)),javascript_asset_ids=sorted(set(js_asset_ids)),
            api_document_ids=sorted(set(api_doc_ids)),declared_operation_ids=sorted(set(declared_operation_ids)),
            out_of_scope_endpoint_ids=sorted(set(out_of_scope_endpoints)))
        ctx.emit("stage",f"Application model: {len(service_urls)} services, {len(set(page_ids))} pages, "
                  f"{len(set(endpoints))} observed endpoints, {len(set(parameters))} parameters, "
                  f"{len(set(declared_operation_ids))} declared API operations, {len(relationships)} provenance-backed relationships")
        return ctx


class SecurityModelStage(Stage):
    name, title = "security-model", "Evidence-backed security model"
    async def run(self,ctx):
        import hashlib
        from urllib.parse import urlsplit
        from ..core.models import AssetNode, AssetEdge, Actor, Resource, SecurityProperty
        from ..core.redaction import redact_url
        def aid(kind,value): return f"asset-{hashlib.sha256((kind+':'+str(value)).encode()).hexdigest()[:12]}"
        nodes={}
        def add_node(node):
            if node.asset_id not in nodes:
                nodes[node.asset_id]=node
                ctx.asset_nodes.append(node)
            elif node.evidence_ids:
                prior=nodes[node.asset_id]
                prior.evidence_ids=sorted(set(prior.evidence_ids+node.evidence_ids))
            return node.asset_id
        def edge(source,target,relation,source_name,evidence=(),confidence=1.0):
            ctx.asset_edges.append(AssetEdge(source,target,relation,source_name,confidence,
                                              evidence_ids=sorted(set(evidence))))

        target=urlsplit(ctx.config.target); host=target.hostname or ""
        app_id=aid("APPLICATION",target.netloc)
        add_node(AssetNode(app_id,"APPLICATION",target.netloc,"explicit target",1.0,"IN_SCOPE",evidence_ids=["target-input"]))
        host_id=aid("HOSTNAME",host)
        scope_ok,_=ctx.authorization.check(ctx.config.target,purpose="asset-model")
        add_node(AssetNode(host_id,"HOSTNAME",host,"explicit target",1.0,"IN_SCOPE" if scope_ok else "OUT_OF_SCOPE",evidence_ids=["target-input"]))
        edge(app_id,host_id,"uses-host","explicit target",["target-input"])

        for ip in ctx.intelligence.get("dns",{}).get("observed_addresses",[]):
            ip_id=aid("IP_ADDRESS",ip); dns_ref=f"dns-observation:{host}:{ip}"
            add_node(AssetNode(ip_id,"IP_ADDRESS",ip,"system resolver observation",1.0,"OBSERVED_NOT_TESTED",evidence_ids=[dns_ref]))
            edge(host_id,ip_id,"resolves-to","system resolver",[dns_ref])

        all_exchanges=list(getattr(ctx.requester,"exchanges",[]))
        service_ids={}
        for service in ctx.intelligence.get("services",[]):
            value=service.get("url","")
            if not value: continue
            sid=aid("WEB_SERVICE",value); service_ids[value]=sid
            exchange_refs=[ex.exchange_id for ex in all_exchanges
                if f"{urlsplit(ex.url).scheme}://{urlsplit(ex.url).netloc}"==value]
            add_node(AssetNode(sid,"WEB_SERVICE",value,"observed HTTP exchange",1.0,"IN_SCOPE",evidence_ids=exchange_refs))
            edge(host_id,sid,"exposes","observed HTTP exchange",exchange_refs)

        page_ids={}
        for page in ctx.pages:
            pid=aid("PAGE",page.url); page_ids[page.exchange_id]=pid
            add_node(AssetNode(pid,"PAGE",redact_url(page.url),"observed HTML response",1.0,"IN_SCOPE",evidence_ids=[page.exchange_id]))
            service=f"{urlsplit(page.url).scheme}://{urlsplit(page.url).netloc}"
            if service in service_ids:
                edge(service_ids[service],pid,"serves-page","observed HTML response",[page.exchange_id])

        crawl=getattr(ctx,"_crawl_result",None)
        if crawl:
            for js_url in sorted(crawl.js_assets):
                js_id=aid("JAVASCRIPT_ASSET",js_url)
                allowed,reason=ctx.authorization.check(js_url,purpose="asset-model-js")
                source_refs=[]
                for page,parser in crawl.parsed:
                    if js_url in parser.assets:
                        source_refs.append(page.exchange_id)
                        if page.exchange_id in page_ids:
                            edge(page_ids[page.exchange_id],js_id,"loads-script","observed HTML reference",[page.exchange_id])
                fetched=[ex.exchange_id for ex in all_exchanges if ex.url==js_url]
                add_node(AssetNode(js_id,"JAVASCRIPT_ASSET",redact_url(js_url),"observed script reference",0.9,
                    "IN_SCOPE" if allowed else "OUT_OF_SCOPE",evidence_ids=sorted(set(source_refs+fetched))))
                service=f"{urlsplit(js_url).scheme}://{urlsplit(js_url).netloc}"
                if service in service_ids:
                    edge(service_ids[service],js_id,"hosts-script","observed HTTP origin",fetched or source_refs)

        api_doc_ids={}
        for document in getattr(ctx,"api_documents",[]):
            doc_url=str(document.get("document_url", ""))
            if not doc_url:
                continue
            doc_id=aid("API_DOCUMENT",doc_url); api_doc_ids[doc_url]=doc_id
            source_id=page_ids.get(document.get("source_exchange_id"))
            evidence_refs=[str(document[x]) for x in ("exchange_id","source_exchange_id") if document.get(x)]
            allowed=bool(document.get("exchange_id"))
            if not allowed:
                allowed,_reason=ctx.authorization.check(doc_url,purpose="asset-model-api-doc")
            add_node(AssetNode(doc_id,"API_DOCUMENT",redact_url(doc_url),"linked API declaration",0.9,
                "IN_SCOPE" if allowed else "OUT_OF_SCOPE",evidence_ids=evidence_refs))
            if source_id:
                edge(source_id,doc_id,"links-api-document","observed HTML reference",evidence_refs)

        for operation in getattr(ctx,"api_inventory",[]):
            if operation.get("contract")!="DECLARED_NOT_VALIDATED":
                continue
            doc_url=str(operation.get("document_url", ""))
            key="|".join((doc_url,str(operation.get("method","")),str(operation.get("path","")),
                          str(operation.get("operation_id",""))))
            operation_id=aid("DECLARED_API_OPERATION",key)
            label=f"{operation.get('method','')} {operation.get('path','')}"
            evidence_refs=[str(operation[x]) for x in ("exchange_id","source_exchange_id") if operation.get(x)]
            add_node(AssetNode(operation_id,"DECLARED_API_OPERATION",label,"observed OpenAPI declaration",0.8,
                "DECLARED_NOT_VALIDATED",evidence_ids=evidence_refs))
            if doc_url in api_doc_ids:
                edge(api_doc_ids[doc_url],operation_id,"declares-operation","OpenAPI declaration",evidence_refs,0.8)

        for ep in ctx.endpoints.values():
            eid=aid("ENDPOINT",ep.method+":"+ep.normalized)
            exchange_refs=list(ep.evidence_ids)
            add_node(AssetNode(eid,"ENDPOINT",ep.method+" "+ep.normalized,"observed application endpoint",1.0,
                               ep.scope_status,evidence_ids=exchange_refs))
            service=f"{urlsplit(ep.url).scheme}://{urlsplit(ep.url).netloc}"
            if service in service_ids and ep.scope_status=="IN_SCOPE":
                edge(service_ids[service],eid,"serves-endpoint","observed crawl result",exchange_refs)
            for param in ep.params:
                param_id=aid("PARAMETER",param.key())
                add_node(AssetNode(param_id,"PARAMETER",f"{param.location}:{param.name}",param.source,
                    min(max(float(param.confidence),0.0),1.0),ep.scope_status,evidence_ids=exchange_refs))
                edge(eid,param_id,"accepts-parameter",param.source,exchange_refs)

        for tech in ctx.technologies.values():
            tech_id=aid("TECHNOLOGY",tech.name)
            add_node(AssetNode(tech_id,"TECHNOLOGY",tech.name,"passive response fingerprint",0.7,
                               "OBSERVED_NOT_TESTED",evidence_ids=[]))
            edge(app_id,tech_id,"observed-technology","passive fingerprint")

        identities=ctx.config.auth_data.get("identities",{})
        for label,spec in identities.items():
            ctx.actors.append(Actor("actor-"+str(label),str(label),str(spec.get("role","UNKNOWN")),str(spec.get("tenant","UNKNOWN")),"researcher-config","DECLARED_NOT_INDEPENDENTLY_VERIFIED"))
        from .verification import expand_authorization_specs
        for i,spec in enumerate(expand_authorization_specs(ctx.config.auth_data)):
            try:
                rid="resource-"+hashlib.sha256((str(spec["url"])+str(i)).encode()).hexdigest()[:12]
                ctx.resources.append(Resource(rid,str(spec.get("resource_type","researcher-declared object")),str(spec["url"]),str(spec["owner_identity"])))
                ctx.security_properties.append(SecurityProperty("property-"+str(i),"Object ownership authorization",
                    "actor-"+str(spec["other_identity"]),rid,"read","non-owner must not receive owner-bound sensitive fields"))
            except (KeyError,TypeError):
                continue
        ctx.emit("stage",f"Model: {len(ctx.asset_nodes)} evidence-backed assets, {len(ctx.asset_edges)} relationships, "
                          f"{len(ctx.actors)} declared actors, {len(ctx.resources)} declared resources; "
                          "declarations remain distinct from observed/reachable assets")
        return ctx


class HypothesisStage(Stage):
    name, title = "hypotheses", "Security hypothesis generation"
    async def run(self,ctx):
        from ..core.models import HypothesisRecord
        interesting={"id","user_id","account_id","order_id","file","url","redirect","return","next","callback","token","role","permission","query","search"}
        for p in ctx.parameters.values():
            if p.name.lower() in interesting:
                ctx.hypotheses.append(HypothesisRecord("hyp-"+uuid.uuid4().hex[:12],"parameter-review","KEEP",
                    endpoint=p.endpoint_url,parameter=p.name,
                    reason="Parameter name is a review lead only; behavior and security impact have not been tested.",
                    evidence=[p.source],confidence=min(p.confidence,0.5),test_strategy="Manual, authorized review; no supported active test mapped."))
        from .verification import expand_authorization_specs
        for i,spec in enumerate(expand_authorization_specs(ctx.config.auth_data)):
            h_id="hyp-"+uuid.uuid4().hex[:12]
            ctx.hypotheses.append(HypothesisRecord(h_id,"object-level-authorization","KEEP",
                endpoint=str(spec.get("url","")),actor_id="actor-"+str(spec.get("other_identity","")),
                resource_id=(ctx.resources[i].resource_id if i<len(ctx.resources) else ""),operation="read",
                security_property="non-owner must not receive owner-bound sensitive fields",
                reason="Researcher supplied two identities, an owner invariant and explicit read-only test configuration.",
                evidence=["researcher-config"],confidence=0.5,test_strategy="bounded repeated GET comparison",request_cost=3,risk="SAFE_ACTIVE"))
        cors_seen=set()
        cors_surfaces={str(item.url):item for item in ctx.endpoints.values()}
        from types import SimpleNamespace
        for exchange in getattr(getattr(ctx,"requester",None),"exchanges",[]):
            if exchange.method.upper()=="GET" and 200<=int(exchange.status or 0)<300:
                cors_surfaces.setdefault(str(exchange.url),SimpleNamespace(url=exchange.url,method="GET",
                    status=exchange.status,scope_status="IN_SCOPE",evidence_ids=[exchange.exchange_id]))
        def _cors_surface_order(endpoint):
            exchange=next((item for item in getattr(getattr(ctx,"requester",None),"exchanges",[])
                           if item.url==endpoint.url),None)
            marker=bool(exchange and (exchange.header("access-control-allow-origin") or
                exchange.header("access-control-allow-credentials").lower()=="true" or
                "origin" in exchange.header("vary").lower()))
            return (not marker,str(endpoint.url))
        for endpoint in sorted(cors_surfaces.values(),key=_cors_surface_order):
            url=str(endpoint.url)
            if (endpoint.method.upper()!="GET" or endpoint.scope_status!="IN_SCOPE" or
                    not 200<=int(endpoint.status or 0)<300 or url in cors_seen):
                continue
            allowed,reason=ctx.authorization.check(url,purpose="cors-hypothesis",method="GET")
            if not allowed: continue
            cors_seen.add(url)
            evidence=list(getattr(endpoint,"evidence_ids",[]) or [])
            ctx.hypotheses.append(HypothesisRecord("hyp-"+uuid.uuid4().hex[:12],"cors-policy-review","KEEP",
                endpoint=url,security_property="untrusted origins must not be reflected with credentialed cross-origin access",
                reason="Observed in-scope GET response is an eligible surface for a bounded CORS policy check; no CORS behavior is inferred from the route alone.",
                evidence=evidence,confidence=0.25,test_strategy="three read-only GET requests with distinct reserved Origin values",
                request_cost=3,risk="SAFE_ACTIVE"))
            if len(cors_seen)>=3: break
        redirect_names={"url","uri","next","continue","return","return_url","redirect",
                        "redirect_url","redirect_uri","destination","dest","callback","target"}
        redirect_candidates=[]
        redirect_seen=set()
        from types import SimpleNamespace
        from urllib.parse import parse_qsl
        redirect_surfaces=list(ctx.endpoints.values())
        for exchange in getattr(getattr(ctx,"requester",None),"exchanges",[]):
            if exchange.method.upper()!="GET" or not 200<=int(exchange.status or 0)<400:
                continue
            query_params=[SimpleNamespace(name=name,location="query")
                          for name,_ in parse_qsl(urlsplit(exchange.url).query,keep_blank_values=True)]
            if query_params:
                redirect_surfaces.append(SimpleNamespace(url=exchange.url,method="GET",status=exchange.status,
                    scope_status="IN_SCOPE",params=query_params,evidence_ids=[exchange.exchange_id]))
        for endpoint in redirect_surfaces:
            if (endpoint.method.upper()!="GET" or endpoint.scope_status!="IN_SCOPE" or
                    not 200<=int(endpoint.status or 0)<400):
                continue
            for parameter in endpoint.params:
                name=str(parameter.name).strip()
                if (parameter.location!="query" or name.lower() not in redirect_names or
                        ctx.authorization.param_excluded(name)):
                    continue
                key=(str(endpoint.url),name)
                if key in redirect_seen: continue
                allowed,reason=ctx.authorization.check(str(endpoint.url),purpose="open-redirect-hypothesis",method="GET")
                if not allowed: continue
                redirect_seen.add(key)
                redirect_candidates.append((endpoint,parameter,name))
        redirect_candidates.sort(key=lambda item:(item[2].lower(),item[0].url))
        for endpoint,parameter,name in redirect_candidates[:3]:
            ctx.hypotheses.append(HypothesisRecord("hyp-"+uuid.uuid4().hex[:12],"open-redirect-review","KEEP",
                endpoint=str(endpoint.url),parameter=name,
                reason="An observed GET query parameter has a redirect-like name; control of the Location response has not been tested.",
                evidence=list(getattr(endpoint,"evidence_ids",[]) or []),confidence=0.25,
                test_strategy="paired external reserved-marker and same-origin-control GETs; redirects are never followed",
                request_cost=2,risk="SAFE_ACTIVE"))
        from .sql_injection_verification import collect_sql_injection_candidates
        sql_candidates=collect_sql_injection_candidates(ctx)
        ctx._sql_injection_candidate_specs=[]
        from urllib.parse import urlunsplit
        for candidate in sql_candidates:
            parts=urlsplit(candidate["url"])
            safe_endpoint=urlunsplit((parts.scheme,parts.netloc,parts.path or "/","",""))
            hypothesis_id="hyp-"+uuid.uuid4().hex[:12]
            ctx.hypotheses.append(HypothesisRecord(hypothesis_id,"sql-injection-review","KEEP",
                endpoint=safe_endpoint,parameter=candidate["parameter"],
                reason="An observed, in-scope successful GET endpoint has a bounded non-sensitive query value; no injection behavior is inferred.",
                evidence=list(candidate.get("evidence_ids",[])),confidence=0.2,
                test_strategy="original and benign controls followed by repeated single-quote parser-error check; no extraction or writes",
                request_cost=4,risk="LOW_READ_ONLY"))
            candidate["hypothesis_id"]=hypothesis_id
            candidate["safe_endpoint"]=safe_endpoint
            ctx._sql_injection_candidate_specs.append(candidate)
        ctx.intelligence.setdefault("coverage",{})["hypotheses"]=len(ctx.hypotheses)
        ctx.emit("stage",f"Hypotheses: {len(ctx.hypotheses)} explicit leads; none are findings")
        return ctx


class TestPlanningStage(Stage):
    name, title = "test-plan", "Auditable, bounded test planning"
    async def run(self,ctx):
        from ..core.models import PlannedTest
        from ..core.profiles import get_profile
        from .methodology import build_test_methodology
        from .vulnerability_registry import VULNERABILITY_CLASSES, build_vulnerability_matrix
        from .verification import expand_authorization_specs
        specs=expand_authorization_specs(ctx.config.auth_data)
        bola_hypotheses=[h for h in ctx.hypotheses if h.category=="object-level-authorization"]
        cors_hypotheses=[h for h in ctx.hypotheses if h.category=="cors-policy-review"]
        redirect_hypotheses=[h for h in ctx.hypotheses if h.category=="open-redirect-review"]
        sql_hypotheses=[h for h in ctx.hypotheses if h.category=="sql-injection-review"]
        profile=get_profile(ctx.config.profile_name)
        test_profile=getattr(ctx.config,"test_profile","full")
        bola_selected=(test_profile=="full" or test_profile in VULNERABILITY_CLASSES["bola"]["profiles"])
        cors_selected=(test_profile=="full" or test_profile in VULNERABILITY_CLASSES["cors"]["profiles"])
        redirect_selected=(test_profile=="full" or test_profile in VULNERABILITY_CLASSES["open_redirect"]["profiles"])
        sqli_selected=(test_profile=="full" or test_profile in VULNERABILITY_CLASSES["sqli"]["profiles"])
        ctx._authorization_test_specs=[]
        ctx._cors_test_specs=[]
        ctx._open_redirect_test_specs=[]
        ctx._sql_injection_test_specs=[]
        can_run=bool(ctx.config.active_requested and profile.allows_active and not ctx.authorization.stopped)
        reserved=0
        budget=getattr(getattr(ctx,"requester",None),"budget",None)
        available=(budget.max_requests-budget.sent) if budget else profile.max_requests
        if bola_selected:
            for spec,hypothesis in zip(specs,bola_hypotheses):
                enough=reserved+3<=available
                plan_status="PLANNED" if can_run and enough else "BLOCKED"
                planned=PlannedTest("test-"+uuid.uuid4().hex[:12],hypothesis.hypothesis_id,
                    "cross-account-object-authorization",str(spec.get("url","")),"GET",3,"LOW_READ_ONLY",True,
                    plan_status,methodology=build_test_methodology("cross-account-object-authorization",str(spec.get("url",""))))
                ctx.test_plan.append(planned)
                if plan_status=="PLANNED":
                    ctx._authorization_test_specs.append(spec);reserved+=3
                else:
                    hypothesis.status="KEEP"
                    if can_run and not enough: planned.methodology["status"]="BLOCKED_BUDGET"
        if cors_selected and can_run:
            for hypothesis in cors_hypotheses[:3]:
                enough=reserved+3<=available
                allowed,reason=ctx.authorization.check(hypothesis.endpoint,purpose="cors-test-plan",method="GET")
                plan_status="PLANNED" if can_run and enough and allowed else "BLOCKED"
                if not allowed:
                    hypothesis.status="BLOCKED"
                methodology=build_test_methodology("cors-origin-reflection",hypothesis.endpoint)
                if can_run and not enough:
                    methodology["status"]="BLOCKED_BUDGET"
                    methodology["planning_note"]="Three requests do not fit within the remaining request budget."
                elif not allowed:
                    methodology["status"]="BLOCKED_SCOPE"
                    methodology["planning_note"]=reason
                planned=PlannedTest("test-"+uuid.uuid4().hex[:12],hypothesis.hypothesis_id,
                    "cors-origin-reflection",hypothesis.endpoint,"GET",3,"LOW_READ_ONLY",True,
                    plan_status,methodology=methodology)
                ctx.test_plan.append(planned)
                if plan_status=="PLANNED":
                    ctx._cors_test_specs.append({"url":hypothesis.endpoint,"test_id":planned.test_id,
                                                "hypothesis_id":hypothesis.hypothesis_id})
                    reserved+=3
        if redirect_selected and can_run:
            for hypothesis in redirect_hypotheses[:3]:
                enough=reserved+2<=available
                allowed,reason=ctx.authorization.check(hypothesis.endpoint,purpose="open-redirect-test-plan",method="GET")
                plan_status="PLANNED" if enough and allowed else "BLOCKED"
                methodology=build_test_methodology("open-redirect-validation",hypothesis.endpoint)
                if not enough:
                    methodology["status"]="BLOCKED_BUDGET"
                    methodology["planning_note"]="The paired two-request check does not fit within the remaining request budget."
                elif not allowed:
                    methodology["status"]="BLOCKED_SCOPE"
                    methodology["planning_note"]=reason
                planned=PlannedTest("test-"+uuid.uuid4().hex[:12],hypothesis.hypothesis_id,
                    "open-redirect-validation",hypothesis.endpoint,"GET",2,"LOW_READ_ONLY",True,
                    plan_status,methodology=methodology)
                ctx.test_plan.append(planned)
                if plan_status=="PLANNED":
                    ctx._open_redirect_test_specs.append({"url":hypothesis.endpoint,"parameter":hypothesis.parameter,
                        "test_id":planned.test_id,"hypothesis_id":hypothesis.hypothesis_id})
                    reserved+=2
        if sqli_selected:
            candidates={str(item.get("hypothesis_id")):item for item in getattr(ctx,"_sql_injection_candidate_specs",[])}
            for hypothesis in sql_hypotheses[:3]:
                candidate=candidates.get(hypothesis.hypothesis_id)
                if not candidate: continue
                enough=reserved+4<=available
                allowed,reason=ctx.authorization.check(candidate["url"],purpose="sql-injection-test-plan",method="GET")
                plan_status="PLANNED" if can_run and enough and allowed else "BLOCKED"
                methodology=build_test_methodology("sql-injection-validation",hypothesis.endpoint)
                if not can_run:
                    methodology["status"]="BLOCKED_ACTIVE_MODE"
                    methodology["planning_note"]="Explicit active request and an active-capable safety mode are required."
                elif not enough:
                    methodology["status"]="BLOCKED_BUDGET"
                    methodology["planning_note"]="Four bounded control/probe requests do not fit within the remaining budget."
                elif not allowed:
                    methodology["status"]="BLOCKED_SCOPE"
                    methodology["planning_note"]=reason
                planned=PlannedTest("test-"+uuid.uuid4().hex[:12],hypothesis.hypothesis_id,
                    "sql-injection-validation",hypothesis.endpoint,"GET",4,"LOW_READ_ONLY",True,
                    plan_status,methodology=methodology)
                ctx.test_plan.append(planned)
                if plan_status=="PLANNED":
                    ctx._sql_injection_test_specs.append({**candidate,"test_id":planned.test_id})
                    reserved+=4
        if sql_hypotheses and not sqli_selected:
            ctx.emit("stage",f"SQL input leads retained as review hypotheses; no SQLi checks selected by `{test_profile}` portfolio")
        if sqli_selected and sql_hypotheses and not can_run:
            ctx.emit("stage","SQLi checks blocked: explicit active request and an active-capable safety mode are required")
        from .workflow_execution import plan_read_only_workflows
        configured_workflows=ctx.config.auth_data.get("workflow_tests",[])
        ctx._workflow_test_specs=[]
        workflow_plans,workflow_runnable,workflow_reserved,workflow_errors=plan_read_only_workflows(
            configured_workflows,ctx.config.target,ctx.authorization,can_run=can_run,
            available_requests=max(0,available-reserved))
        ctx.test_plan.extend(workflow_plans)
        ctx._workflow_test_specs=workflow_runnable
        ctx.workflow_plan_errors=workflow_errors
        reserved+=workflow_reserved
        if workflow_errors:
            ctx.emit("stage",f"Configured workflow spec issue(s): {len(workflow_errors)} entry/entries rejected; see report")
        if configured_workflows and not can_run:
            ctx.emit("stage","Configured read-only workflows blocked: explicit active request and active-capable safety profile are required")
        import importlib.util
        from .browser_workflow import plan_browser_workflows
        browser_specs=ctx.config.auth_data.get("browser_workflows",[])
        browser_available=importlib.util.find_spec("playwright") is not None
        ctx._browser_workflow_specs=[]
        browser_plans,browser_runnable,browser_reserved,browser_errors=plan_browser_workflows(
            browser_specs,ctx.config.target,ctx.authorization,can_run=can_run,
            available_requests=max(0,available-reserved),browser_available=browser_available)
        ctx.test_plan.extend(browser_plans)
        ctx._browser_workflow_specs=browser_runnable
        ctx.workflow_plan_errors.extend(browser_errors)
        reserved+=browser_reserved
        if browser_errors:
            ctx.emit("stage",f"Browser workflow spec issue(s): {len(browser_errors)} entry/entries rejected; see report")
        if browser_specs and not browser_available:
            ctx.emit("stage","Configured browser workflows blocked: optional Playwright/Chromium support is not installed")
        if specs and bola_selected and not can_run:
            ctx.emit("stage","Configured authorization tests blocked: explicit active mode and an active-capable safety mode are required")
        if specs and not bola_selected:
            ctx.emit("stage",f"Authorization test not selected by `{test_profile}` vulnerability profile")
        if cors_hypotheses and not cors_selected:
            ctx.emit("stage",f"CORS hypotheses retained as review leads; no CORS requests selected by `{test_profile}` portfolio")
        if cors_selected and cors_hypotheses and not can_run:
            ctx.emit("stage","CORS checks planned as blocked: explicit active mode and an active-capable safety mode are required")
        if redirect_hypotheses and not redirect_selected:
            ctx.emit("stage",f"Redirect hypotheses retained as review leads; no open-redirect requests selected by `{test_profile}` portfolio")
        if redirect_selected and redirect_hypotheses and not can_run:
            ctx.emit("stage","Open-redirect checks retained as hypotheses: explicit active mode and an active-capable safety mode are required")
        ctx.vulnerability_matrix=build_vulnerability_matrix(ctx,test_profile)
        selected_supported=sum(1 for item in ctx.vulnerability_matrix if item["selected"] and item["supported"])
        unsupported=sum(1 for item in ctx.vulnerability_matrix if item["selected"] and not item["supported"])
        ctx.emit("stage",f"Vulnerability matrix `{test_profile}`: {selected_supported} supported class(es), "
                          f"{unsupported} unsupported selected class(es); unsupported classes will not execute")
        if getattr(ctx.config,"verbose",False):
            from ..core.outcomes import class_result_status
            for item in ctx.vulnerability_matrix:
                if item["selected"]:
                    ctx.emit("stage",f"  {item['name']}: {class_result_status(item)} · {item['reason']}")
        ctx.emit("stage",f"Test plan: {len(ctx.test_plan)} methodology-backed plan(s); up to {reserved} request(s) reserved")
        return ctx


class ControlledTestingStage(Stage):
    name, title = "controlled-test", "Controlled test execution"
    async def run(self,ctx):
        if ctx.authorization.stopped:
            ctx.emit("stage","Controlled testing skipped: network stop is active")
        else:
            from .verification import execute_authorization_tests
            from .cors_verification import execute_cors_tests
            from .open_redirect_verification import execute_open_redirect_tests
            from .sql_injection_verification import execute_sql_injection_tests
            await execute_authorization_tests(ctx)
            await execute_cors_tests(ctx)
            await execute_open_redirect_tests(ctx)
            await execute_sql_injection_tests(ctx)
            from .workflow_execution import execute_read_only_workflows
            from .browser_workflow import execute_browser_workflows
            await execute_read_only_workflows(ctx)
            await execute_browser_workflows(ctx)
        ctx.emit("stage",f"Controlled tests executed: {len(ctx.tests)}; no signal is promoted at this stage")
        return ctx


class VerificationStage(Stage):
    name, title = "verification", "Security-property verification"
    async def run(self,ctx):
        from .verification import verify_authorization_tests
        from .cors_verification import verify_cors_tests
        from .open_redirect_verification import verify_open_redirect_tests
        from .sql_injection_verification import verify_sql_injection_tests
        verify_authorization_tests(ctx)
        verify_cors_tests(ctx)
        verify_open_redirect_tests(ctx)
        verify_sql_injection_tests(ctx)
        from .vulnerability_registry import build_vulnerability_matrix
        ctx.vulnerability_matrix=build_vulnerability_matrix(ctx,getattr(ctx.config,"test_profile","full"))
        ctx.emit("stage",f"Verification: {sum(1 for f in ctx.findings if f.status=='VERIFIED')} proof-backed verified finding(s)")
        return ctx


class CorrelationStage(Stage):
    name, title = "correlation", "Conservative finding correlation"
    async def run(self,ctx):
        seen=set(); unique=[]
        for finding in ctx.findings:
            key=(finding.category.lower(),finding.endpoint,finding.parameter,finding.title.lower())
            if key in seen: continue
            seen.add(key); unique.append(finding)
        removed=len(ctx.findings)-len(unique); ctx.findings[:]=unique
        ctx.emit("stage",f"Correlation: {removed} exact duplicate finding(s) removed; no speculative chains")
        return ctx


class EvidenceValidationStage(Stage):
    name, title = "evidence-validation", "Evidence chain validation"
    async def run(self,ctx):
        tests={t.get("test_id"):t for t in ctx.tests if t.get("status")=="VERIFIED" and t.get("finding_id")}
        valid=[]
        for finding in ctx.findings:
            if finding.status!="VERIFIED":
                valid.append(finding); continue
            refs=[e.detail for e in finding.evidence]
            linked=any(d.get("test_id") in tests and tests[d["test_id"]].get("status")=="VERIFIED" for d in refs)
            if linked: valid.append(finding)
            else:
                finding.status="CANDIDATE"
                finding.state="CANDIDATE"
                finding.evidence=[]
        removed=len(ctx.findings)-len(valid); ctx.findings[:]=valid
        ctx.emit("stage",f"Evidence validation: {len(ctx.findings)} findings retained with required links; {removed} invalid record(s) removed")
        return ctx


class FindingFinalizationStage(Stage):
    name, title = "finding-finalization", "Verified finding finalization"
    async def run(self,ctx):
        from ..core.models import STATUS_VERIFIED
        verified_tests={t.get("test_id"):t for t in ctx.tests if t.get("status")=="VERIFIED" and t.get("finding_id")}
        verified=[]
        for finding in ctx.findings:
            if finding.status!=STATUS_VERIFIED:
                continue
            linked=any(e.detail.get("test_id") in verified_tests and
                       verified_tests[e.detail.get("test_id")].get("finding_id")==finding.id
                       for e in finding.evidence)
            if linked:
                finding.state="VERIFIED"; verified.append(finding)
            else:
                finding.status="CANDIDATE"; finding.state="CANDIDATE"
        ctx.verified_findings=verified
        ctx.emit("stage",f"Verified findings: {len(verified)}; only independently verified, linked findings are included")
        return ctx


class RiskAnalysisStage(Stage):
    name, title = "risk-analysis", "Coverage-aware risk summary"
    async def run(self,ctx):
        from .attack_paths import build_attack_paths
        from .workflow import build_workflow_model
        verified=getattr(ctx,"verified_findings",[])
        # Purely local transformations of already collected records; no requests are made.
        ctx.attack_paths=build_attack_paths(ctx)
        ctx.workflow_model=build_workflow_model(ctx)
        counts={s:sum(1 for f in verified if f.severity.lower()==s) for s in ("critical","high","medium","low","info")}
        ctx.risk_summary={"status":"LIMITED_EVIDENCE","verified_by_severity":counts,
            "verified_total":len(verified),"candidate_total":sum(1 for f in ctx.findings if f.status!="VERIFIED"),
            "attack_path_records":len(ctx.attack_paths),
            "verified_components":sum(1 for p in ctx.attack_paths if p.status=="VERIFIED_COMPONENT"),
            "hypothesis_paths":sum(1 for p in ctx.attack_paths if p.status=="HYPOTHESIS"),
            "workflow_views":len(ctx.workflow_model.get("states",[])),
            "workflow_transitions":len(ctx.workflow_model.get("transitions",[])),
            "workflow_transitions_executed":0,
            "coverage_areas":len(getattr(ctx,"coverage",[])),
            "warning":"Attack-path records are component-level leads, not proof of end-to-end exploitability. Absence of verified findings does not establish that the target is secure."}
        ctx.emit("stage",f"Risk/workflow summary: {len(verified)} verified finding(s), {len(ctx.attack_paths)} component/lead record(s), {len(ctx.workflow_model.get('states',[]))} static view(s); no links/forms executed and no end-to-end chain inferred")
        return ctx


class CoverageStage(Stage):
    name, title = "coverage", "Truthful coverage assessment"
    async def run(self,ctx):
        from ..core.coverage import build_coverage
        ctx.coverage=build_coverage(ctx)
        summary=ctx.intelligence.setdefault("coverage",{})
        summary.update({"hypotheses":len(ctx.hypotheses),"planned_tests":len(ctx.test_plan),
            "tests_performed":len(ctx.tests),"verified_findings":sum(1 for f in getattr(ctx,"verified_findings",[]) if f.status=="VERIFIED"),
            "asset_nodes":len(ctx.asset_nodes),"asset_edges":len(ctx.asset_edges)})
        ctx.emit("stage",f"Coverage: {len(ctx.coverage)} security areas labeled with explicit support/status")
        return ctx


class ReportPreparationStage(Stage):
    name, title = "report-preparation", "Reporting input preparation"
    async def run(self,ctx):
        ctx.report_manifest={
            "scan_id":ctx.scan_id,
            "verified_finding_ids":[f.id for f in ctx.verified_findings],
            "candidate_count":sum(1 for f in ctx.findings if f.status!="VERIFIED"),
            "coverage_categories":len(getattr(ctx,"coverage",[])),
            "evidence_persisted_by_caller":True,
            "artifact_rendering":"CLI/report API responsibility",
        }
        ctx.emit("stage",f"Reporting inputs ready: {len(ctx.verified_findings)} verified finding(s), "
                  f"{ctx.report_manifest['candidate_count']} candidates, {ctx.report_manifest['coverage_categories']} coverage areas")
        return ctx


class PassiveChecksStage(Stage):
    name, title = "passive-checks", "Passive security checks"
    async def run(self, ctx):
        from ..plugins.base import load_builtin_plugins
        new_findings=0
        for plugin in load_builtin_plugins():
            if not plugin.passive or ctx.stopped: continue
            try: findings=plugin.run(ctx)
            except Exception as exc:
                ctx.emit("error",f"plugin {plugin.id} failed: {exc}")
                continue
            for finding in findings: finding.source_plugin=finding.source_plugin or plugin.id
            ctx.findings.extend(findings); new_findings+=len(findings)
        ctx.emit("stage",f"Passive checks: {new_findings} observation(s); no weak signal is auto-confirmed")
        return ctx


# ---------------------------------------------------------------------------
STAGES: List[Stage] = [
    AuthGateStage(), HttpConfigureStage(), TargetServiceStage(), PassiveReconStage(),
    CrawlStage(), JsAnalysisStage(), FrontendIntelligenceStage(), InventoryStage(), ApiModelStage(),
    TechDetectStage(), PassiveChecksStage(), IntelligenceStage(), ApplicationModelStage(),
    SecurityModelStage(), HypothesisStage(), TestPlanningStage(), ControlledTestingStage(),
    VerificationStage(), CorrelationStage(), EvidenceValidationStage(), FindingFinalizationStage(),
    CoverageStage(), RiskAnalysisStage(), ReportPreparationStage(),
]

def _base(url: str) -> str:
    p = urlsplit(url if "://" in url else "http://" + url)
    return f"{p.scheme}://{p.netloc}"


async def _run_async(config: ScanConfig, authorization, event_fn: Optional[Callable] = None) -> ScanResult:
    from pathlib import Path
    from ..core.phases import PhaseTracker
    from ..http.client import ScanAborted
    ctx = ScanContext(scan_id=config.scan_id or ("vf-" + uuid.uuid4().hex[:12]), config=config, authorization=authorization)
    if event_fn: ctx.on_event(event_fn)
    tracker=PhaseTracker(); ctx.phases=tracker.phases
    result=ScanResult(context=ctx)
    active_stage=""
    network_stages={"services","recon","crawl","api-model"}
    try:
        for stage in STAGES:
            # Observe the stop-file before any out-of-band DNS lookup or network stage.
            if stage.name!="auth" and Path(".vulnforge-stop").exists() and not authorization.stopped:
                authorization.stop(".vulnforge-stop detected")
            if authorization.stopped and stage.name in network_stages:
                ctx.stop_reason=ctx.stop_reason or authorization.stop_reason or "network stop requested"
                tracker.skip_stage(stage.name,stopped=True)
                ctx.emit("stage",f"SKIPPED {stage.title}: network stop active ({ctx.stop_reason})")
                continue
            active_stage=stage.name
            tracker.start_stage(stage.name)
            ctx.emit("stage-start",stage.title,stage=stage.name)
            t0=time.monotonic()
            try:
                ctx=await stage.run(ctx)
            except ScanAborted as exc:
                reason=authorization.stop_reason or str(exc)
                ctx.stop_reason=ctx.stop_reason or reason
                result.aborted=("budget" not in reason.lower())
                tracker.fail_stage(stage.name,stopped=True)
                ctx.emit("stage",f"NETWORK STOP · {stage.title}: {reason}")
                active_stage=""
                continue
            result.stage_timings[stage.name]=round(time.monotonic()-t0,2)
            tracker.complete_stage(stage.name,ctx)
            phase=tracker._find(stage.name)
            ctx.emit("stage-done",stage.title,stage=stage.name,
                     seconds=result.stage_timings[stage.name],
                     phase_status=(phase.status if phase else ""))
            active_stage=""
    except BaseException as exc:
        # Cancellation is not silently swallowed. Preserve elapsed state and let
        # the caller decide whether this was an operator stop or a programming bug.
        if active_stage: tracker.fail_stage(active_stage,stopped=isinstance(exc,asyncio.CancelledError))
        if isinstance(exc,asyncio.CancelledError):
            result.aborted=True; ctx.stop_reason=ctx.stop_reason or "async task cancelled"
            authorization.stop(ctx.stop_reason)
            ctx.emit("stage", "Asynchronous cancellation recorded; preserving completed results.")
        else:
            raise
    finally:
        if authorization.stopped:
            reason=authorization.stop_reason or ctx.stop_reason or "network stopped"
            ctx.stop_reason=ctx.stop_reason or reason
            if "budget" not in reason.lower(): result.aborted=True
        tracker.finalize(stopped=result.aborted)
        ctx.stats.finished_at=time.time()
        if ctx.requester is not None:
            ctx.stats.requests_sent=ctx.requester.budget.sent
            await ctx.requester.close()
    return result


def run_scan(config: ScanConfig, authorization, event_fn: Optional[Callable] = None) -> ScanResult:
    """Synchronous entry point used by the CLI."""
    return asyncio.run(_run_async(config, authorization, event_fn))
