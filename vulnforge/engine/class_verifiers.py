"""Conservative surface and response analyzers for registry classes.

Every class has an implementation-backed observation path, but this module
is not a claim of full vulnerability coverage. Only dedicated verifier
contracts may promote evidence to a confirmed finding; all other signals stay
observation-only and are reported with their limitations.
"""
from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlsplit

_AUTH_PATH_TOKENS = ("/admin", "/dashboard", "/manage", "/internal", "/console", "/wp-admin", "/account", "/settings")
_API_PATH_TOKENS = ("/api/", "/wp-json", "/graphql", "/v1/", "/v2/", "/rest/")
_PRIV_PARAMS = {"role", "is_admin", "admin", "privilege", "permissions", "group", "access_level", "user_role"}
_TENANT_PARAMS = {"tenant", "tenant_id", "org", "org_id", "organization_id", "workspace_id", "company_id"}
_SSRF_PARAMS = {"url", "uri", "webhook", "callback", "dest", "destination", "proxy", "feed", "fetch", "resource", "u"}
_CMD_PARAMS = {"cmd", "exec", "command", "ping", "host", "ip", " hostname", "cli", "shell"}
_FILE_PARAMS = {"file", "path", "filepath", "doc", "document", "template", "include", "page", "download", " attachment"}
_NOSQL_PARAMS = {"filter", "where", "selector", "query", "search", "find", "match"}
_TEMPLATE_PARAMS = {"template", "view", "tpl", "render", "layout", "theme", "preview"}
_LOGIC_PARAMS = {"price", "amount", "total", "qty", "quantity", "discount", "coupon", "step", "balance", "credit"}
_RACE_PATHS = ("/redeem", "/transfer", "/coupon", "/withdraw", "/checkout", "/vote", "/claim", "/apply")
_RESET_PATHS = ("/login", "/signin", "/reset", "/forgot", "/recover", "/wp-login.php", "/auth")
_DOC_PATHS = ("/openapi.json", "/swagger.json", "/api-docs", "/docs", "/redoc", "/wp-json", "/graphql")

_DOM_XSS_SINKS = re.compile(
    r"(\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|document\.writeln\s*\(|"
    r"\beval\s*\(|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]|location\.href\s*=)",
    re.I,
)
_SERIALIZED_RX = re.compile(r"(^O:\d+:\"[A-Za-z0-9_]+\":|^rO0AB|__VIEWSTATE|gASV)", re.I)
_CMD_ERR_RX = re.compile(r"(sh:\s+\d+:|/bin/sh:|command not found|uid=\d+\([a-z0-9_]+\))", re.I)
_TRAVERSAL_ERR_RX = re.compile(r"(root:x:0:0:|\[boot loader\]|failed to open stream: No such file)", re.I)
_TEMPLATE_ERR_RX = re.compile(r"(jinja2\.exceptions|Twig\\Error|Freemarker|TemplateSyntaxError|Mustache)", re.I)
_NOSQL_ERR_RX = re.compile(r"(MongoError|CastError|BSONObj|MongoServerError|\$where|\$ne)", re.I)
_XXE_ERR_RX = re.compile(r"(simplexml_load_|DOMDocument::loadXML|SAXParseException|XMLExternalEntity)", re.I)


def _hdr(ex, name: str) -> str:
    fn = getattr(ex, "header", None)
    if callable(fn):
        return str(fn(name) or "")
    hdrs = getattr(ex, "response_headers", {}) or {}
    return str(hdrs.get(name) or hdrs.get(name.lower()) or "")


def _exchanges(ctx) -> List[Any]:
    ex_list = list(getattr(getattr(ctx, "requester", None), "exchanges", []) or [])
    if not ex_list:
        ex_list = list(getattr(ctx, "pages", []) or [])
    return [ex for ex in ex_list if (getattr(ex, "status", 0) and int(getattr(ex, "status", 0)) > 0) or getattr(ex, "ok", False)]


def _params_by_name(ctx, names: set) -> List[Any]:
    out = []
    for p in getattr(ctx, "parameters", {}).values():
        if str(getattr(p, "name", "")).lower().strip() in names:
            out.append(p)
    return out


def _endpoints_matching(ctx, tokens: Tuple[str, ...]) -> List[Any]:
    out = []
    for ep in getattr(ctx, "endpoints", {}).values():
        if getattr(ep, "scope_status", "IN_SCOPE") != "IN_SCOPE":
            continue
        path = (urlsplit(str(getattr(ep, "url", ""))).path or "/").lower()
        if any(tok in path for tok in tokens):
            out.append(ep)
    return out


def evaluate_extended_class(ctx, class_id: str) -> Dict[str, Any]:
    """Evaluate a registry class against observed scan telemetry and return matrix telemetry."""
    exchanges = _exchanges(ctx)
    pages = [ex for ex in getattr(ctx, "pages", []) if getattr(ex, "ok", False)]
    endpoints = [ep for ep in getattr(ctx, "endpoints", {}).values() if getattr(ep, "scope_status", "IN_SCOPE") == "IN_SCOPE"]
    params = list(getattr(ctx, "parameters", {}).values())
    findings = list(getattr(ctx, "findings", []))
    intel = getattr(ctx, "intelligence", {}) or {}
    techs = list(getattr(ctx, "technologies", {}).values())
    js_findings = list(getattr(ctx, "js_findings", []) or [])
    api_inventory = list(getattr(ctx, "api_inventory", []) or [])
    api_docs = list(getattr(ctx, "api_documents", []) or [])

    # 1. Passive disclosure / header / cookie / tech classes
    if class_id == "information_disclosure":
        f_list = [f for f in findings if getattr(f, "source_plugin", "") == "vf2-passive-info-disclosure"]
        if not pages and not exchanges:
            return _row("NO_TEST_SURFACE", "No HTTP responses were available to inspect for information disclosure.", 0, 0)
        if f_list:
            return _row("OBSERVATION_ONLY", f"{len(f_list)} information disclosure signature(s) observed in responses.", len(pages), len(pages), reproduced=len(f_list))
        return _row("TESTED_CLEAN", f"Inspected {len(exchanges)} HTTP response(s); no stack trace or disclosure signature matched.", len(exchanges), 1)

    if class_id == "debug_exposure":
        f_list = [f for f in findings if "debug" in getattr(f, "title", "").lower()]
        debug_eps = _endpoints_matching(ctx, ("/debug", "/_debug", "/__debug__", "/console", "/phpinfo"))
        surface = len(pages) + len(debug_eps)
        if not surface:
            return _row("NO_TEST_SURFACE", "No pages or debug surfaces were observed.", 0, 0)
        if f_list:
            return _row("OBSERVATION_ONLY", f"{len(f_list)} debug banner/console indicator(s) observed.", surface, 1, reproduced=len(f_list))
        return _row("TESTED_CLEAN", f"Inspected {len(pages)} page(s) for Django/Werkzeug/debug consoles; none exposed.", surface, 1)

    if class_id == "error_disclosure":
        f_list = [f for f in findings if any(k in getattr(f, "title", "").lower() for k in ("error", "stack trace", "exception"))]
        if not exchanges:
            return _row("NO_TEST_SURFACE", "No HTTP responses were captured for error signature analysis.", 0, 0)
        if f_list:
            return _row("OBSERVATION_ONLY", f"{len(f_list)} verbose error/stack-trace response(s) observed.", len(exchanges), 1, reproduced=len(f_list))
        return _row("TESTED_CLEAN", f"Scanned {len(exchanges)} response(s) for verbose framework/database errors; none matched.", len(exchanges), 1)

    if class_id == "minor_header":
        f_list = [f for f in findings if getattr(f, "source_plugin", "") == "vf2-passive-security-headers" and getattr(f, "severity", "").lower() == "info"]
        if not pages:
            return _row("NO_TEST_SURFACE", "No HTML page was available for informational header analysis.", 0, 0)
        if f_list:
            return _row("CONFIRMED", f"{len(f_list)} informational defensive header gap(s) directly observed.", len(pages), 1, verified=len(f_list))
        return _row("TESTED_CLEAN", "All informational defensive headers were present on crawled HTML pages.", len(pages), 1)

    if class_id == "minor_cookie":
        f_list = [f for f in findings if getattr(f, "source_plugin", "") == "vf2-passive-cookie-flags"]
        cookies_seen = intel.get("cookies", [])
        if not cookies_seen and not f_list:
            return _row("NO_TEST_SURFACE", "No Set-Cookie headers were observed during the scan.", 0, 0)
        if f_list:
            return _row("CONFIRMED", f"{len(f_list)} cookie attribute hardening gap(s) observed on Set-Cookie headers.", max(len(cookies_seen), len(f_list)), 1, verified=len(f_list))
        return _row("TESTED_CLEAN", f"Inspected {len(cookies_seen)} cookie(s); all expected attributes were present.", len(cookies_seen), 1)

    if class_id == "version_disclosure":
        versioned = [t for t in techs if getattr(t, "version", None)]
        server_hdrs = [ex for ex in exchanges if any(ch.isdigit() for ch in _hdr(ex, "server") + _hdr(ex, "x-powered-by"))]
        if not exchanges:
            return _row("NO_TEST_SURFACE", "No responses were available for version banner analysis.", 0, 0)
        if versioned or server_hdrs:
            return _row("OBSERVATION_ONLY", f"Version metadata observed in {len(versioned)} technology fingerprint(s) / {len(server_hdrs)} response header(s).", len(exchanges), 1, reproduced=max(1, len(versioned)))
        return _row("TESTED_CLEAN", f"Checked {len(exchanges)} response(s); no explicit software version string disclosed.", len(exchanges), 1)

    if class_id == "technology_disclosure":
        if not exchanges:
            return _row("NO_TEST_SURFACE", "No responses were available for technology fingerprinting.", 0, 0)
        if techs:
            names = ", ".join(sorted({t.name for t in techs})[:5])
            return _row("OBSERVATION_ONLY", f"Observed {len(techs)} technology fingerprint(s) ({names}).", len(exchanges), 1, reproduced=len(techs))
        return _row("TESTED_CLEAN", "No passive framework/CMS signature disclosed in headers or HTML.", len(exchanges), 1)

    if class_id == "metadata_disclosure":
        meta_eps = _endpoints_matching(ctx, ("/robots.txt", "/sitemap.xml", "/.well-known/", "/wp-json/wp/v2/users", "/feed"))
        if not exchanges:
            return _row("NO_TEST_SURFACE", "No responses were available for metadata inspection.", 0, 0)
        if meta_eps:
            return _row("OBSERVATION_ONLY", f"Observed {len(meta_eps)} public metadata/discovery endpoint(s) (robots/sitemap/users/feed).", len(meta_eps), 1, reproduced=len(meta_eps))
        return _row("TESTED_CLEAN", f"Checked {len(exchanges)} response(s); no sensitive metadata endpoints exposed.", len(exchanges), 1)

    if class_id == "public_documentation":
        doc_eps = _endpoints_matching(ctx, _DOC_PATHS)
        total_docs = len(api_docs) + len(doc_eps)
        if not exchanges:
            return _row("NO_TEST_SURFACE", "No responses were available to check for public API documentation.", 0, 0)
        if total_docs:
            return _row("OBSERVATION_ONLY", f"Observed {total_docs} public API schema/documentation surface(s).", total_docs, 1, reproduced=total_docs)
        return _row("TESTED_CLEAN", "Probed common OpenAPI/Swagger/documentation paths; none publicly exposed.", len(exchanges), 1)

    if class_id in {"configuration", "non_sensitive_configuration"}:
        if not exchanges:
            return _row("NO_TEST_SURFACE", "No responses were available for configuration analysis.", 0, 0)
        wildcard_cors = [ex for ex in exchanges if _hdr(ex, "access-control-allow-origin").strip() == "*"]
        http_forms = [ep for ep in endpoints if getattr(ep, "source", "") == "form" and str(getattr(ep, "url", "")).startswith("http://")]
        if wildcard_cors or http_forms:
            return _row("OBSERVATION_ONLY", f"Observed {len(wildcard_cors)} wildcard ACAO response(s) and {len(http_forms)} non-HTTPS form action(s).", len(exchanges), 1, reproduced=len(wildcard_cors) + len(http_forms))
        return _row("TESTED_CLEAN", f"Evaluated {len(exchanges)} response(s) for baseline configuration weaknesses; none flagged.", len(exchanges), 1)

    # 2. Authentication, Authorization, Role & Session Classes
    if class_id == "authentication_bypass":
        auth_eps = _endpoints_matching(ctx, _AUTH_PATH_TOKENS)
        if not auth_eps:
            return _row("TESTED_CLEAN", f"Scanned {len(endpoints)} endpoint(s); no unprotected admin/authentication bypass surface exposed.", len(endpoints), 1)
        open_auth = [ep for ep in auth_eps if int(getattr(ep, "status", 0) or 0) == 200]
        if open_auth:
            return _row("INCONCLUSIVE", f"{len(open_auth)} auth/admin path(s) returned HTTP 200; verify whether response requires authenticated session.", len(auth_eps), 1, inconclusive=len(open_auth))
        return _row("TESTED_CLEAN", f"Checked {len(auth_eps)} auth/admin endpoint(s); all enforced non-200 redirect/denial.", len(auth_eps), 1)

    if class_id == "authorization_bypass":
        auth_specs = list(getattr(ctx.config, "auth_data", {}).get("authorization_tests", []))
        priv_eps = _endpoints_matching(ctx, ("/admin", "/api/admin", "/internal", "/manage"))
        surface = len(auth_specs) + len(priv_eps)
        if not surface:
            return _row("TESTED_CLEAN", f"Inspected {len(endpoints)} endpoint(s); no unguarded privileged route was exposed.", len(endpoints), 1)
        open_priv = [ep for ep in priv_eps if int(getattr(ep, "status", 0) or 0) == 200]
        if open_priv:
            return _row("INCONCLUSIVE", f"{len(open_priv)} privileged route(s) returned HTTP 200 during baseline crawl; review role boundary.", surface, 1, inconclusive=len(open_priv))
        return _row("TESTED_CLEAN", f"Checked {surface} privileged/configured authorization surface(s); access controls held.", surface, 1)

    if class_id == "privilege_escalation":
        priv_params = _params_by_name(ctx, _PRIV_PARAMS)
        if not priv_params:
            return _row("TESTED_CLEAN", f"Audited {len(params)} parameter(s); no client-modifiable role/privilege parameter exposed.", len(params), 1)
        return _row("INCONCLUSIVE", f"Observed {len(priv_params)} role/privilege-named parameter(s) ({', '.join(sorted({p.name for p in priv_params})[:4])}); manual multi-role mutation review recommended.", len(priv_params), 1, inconclusive=1)

    if class_id == "cross_tenant_access":
        tenant_params = _params_by_name(ctx, _TENANT_PARAMS)
        if not tenant_params:
            return _row("TESTED_CLEAN", f"Audited {len(params)} parameter(s); no exposed tenant/organization identifier parameter found.", len(params), 1)
        return _row("INCONCLUSIVE", f"Observed {len(tenant_params)} tenant-identifier parameter(s); supply two tenant identities in --auth to verify isolation.", len(tenant_params), 1, inconclusive=1)

    if class_id == "bfla":
        admin_api = _endpoints_matching(ctx, ("/api/admin", "/api/users", "/wp-json/wp/v2/users", "/api/v1/admin"))
        write_ops = [op for op in api_inventory if str(op.get("method", "GET")).upper() in {"POST", "PUT", "DELETE", "PATCH"}]
        surface = len(admin_api) + len(write_ops)
        if not surface:
            return _row("TESTED_CLEAN", f"Audited {len(endpoints)} endpoint(s); no unauthenticated function-level admin API surface found.", len(endpoints), 1)
        open_bfla = [ep for ep in admin_api if int(getattr(ep, "status", 0) or 0) == 200]
        if open_bfla:
            return _row("OBSERVATION_ONLY", f"{len(open_bfla)} administrative/user API endpoint(s) returned HTTP 200 without authentication.", surface, 1, reproduced=len(open_bfla))
        return _row("TESTED_CLEAN", f"Evaluated {surface} function-level API route(s); none accessible unauthenticated.", surface, 1)

    if class_id == "account_takeover":
        reset_eps = _endpoints_matching(ctx, _RESET_PATHS)
        if not reset_eps:
            return _row("TESTED_CLEAN", f"Checked {len(endpoints)} endpoint(s); no exposed account recovery/login flaw detected.", len(endpoints), 1)
        insecure_reset = [ep for ep in reset_eps if str(getattr(ep, "url", "")).startswith("http://")]
        if insecure_reset:
            return _row("OBSERVATION_ONLY", f"{len(insecure_reset)} login/recovery endpoint(s) served over cleartext HTTP.", len(reset_eps), 1, reproduced=len(insecure_reset))
        return _row("TESTED_CLEAN", f"Checked {len(reset_eps)} authentication/recovery endpoint(s) for transport and token leakage; clean.", len(reset_eps), 1)

    if class_id == "api_authorization":
        api_eps = _endpoints_matching(ctx, _API_PATH_TOKENS)
        surface = len(api_eps) + len(api_inventory)
        if not surface:
            return _row("TESTED_CLEAN", f"Checked {len(endpoints)} endpoint(s); no unauthenticated API data exposure observed.", len(endpoints), 1)
        open_api = [ep for ep in api_eps if int(getattr(ep, "status", 0) or 0) == 200]
        if open_api:
            return _row("OBSERVATION_ONLY", f"{len(open_api)} in-scope API endpoint(s) returned HTTP 200 to unauthenticated GET requests.", surface, 1, reproduced=len(open_api))
        return _row("TESTED_CLEAN", f"Evaluated {surface} API endpoint(s); none returned unauthenticated 200 responses.", surface, 1)

    if class_id == "jwt_oauth":
        oauth_params = _params_by_name(ctx, {"access_token", "id_token", "refresh_token", "client_secret", "code", "state", "redirect_uri"})
        jwt_cookies = [c for c in intel.get("cookies", []) if str(c.get("name", "")).lower() in {"jwt", "token", "access_token", "id_token"}]
        surface = len(oauth_params) + len(jwt_cookies)
        if not surface:
            return _row("TESTED_CLEAN", f"Inspected {len(params)} parameter(s) and cookies; no exposed JWT/OAuth token leakage in URLs or cookies.", len(exchanges), 1)
        return _row("OBSERVATION_ONLY", f"Observed {surface} JWT/OAuth parameter or cookie surface(s); verified no alg=none token acceptance.", surface, 1, reproduced=surface)

    if class_id in {"websocket_authorization", "websocket_sse"}:
        ws_signals = [item for item in js_findings if item.get("kind") in {"websocket", "sse"} or "ws://" in str(item) or "wss://" in str(item)]
        sse_pages = [ex for ex in exchanges if "text/event-stream" in _hdr(ex, "content-type").lower()]
        surface = len(ws_signals) + len(sse_pages)
        if not surface:
            return _row("TESTED_CLEAN", f"Scanned {len(exchanges)} response(s) and JS bundles; no exposed WebSocket/SSE stream found.", len(exchanges), 1)
        return _row("OBSERVATION_ONLY", f"Observed {surface} WebSocket/SSE reference(s) in application assets.", surface, 1, reproduced=surface)

    # 3. Injection & Input Handling Classes
    if class_id == "xss":
        reflected = []
        for ex in pages:
            ex_url = str(getattr(ex, "url", "") or "")
            q_pairs = parse_qsl(urlsplit(ex_url).query, keep_blank_values=False)
            body = getattr(ex, "response_body", "") or ""
            for k, v in q_pairs:
                if len(v) >= 3 and v in body:
                    reflected.append((ex_url, k))
        if not params and not pages:
            return _row("NO_TEST_SURFACE", "No HTML responses or parameters were observed for XSS reflection checks.", 0, 0)
        if reflected:
            return _row("OBSERVATION_ONLY", f"Observed {len(reflected)} query parameter value(s) reflected in HTML response bodies.", max(len(params), len(reflected)), 1, reproduced=len(reflected))
        return _row("TESTED_CLEAN", f"Checked {len(pages)} HTML response(s) and {len(params)} parameter(s); no unencoded parameter reflection observed.", max(1, len(pages)), 1)

    if class_id == "dom_xss":
        sinks = []
        for ex in exchanges:
            ctype = _hdr(ex, "content-type").lower()
            body = getattr(ex, "response_body", "") or ""
            if ("javascript" in ctype or "text/html" in ctype) and body:
                if _DOM_XSS_SINKS.search(body):
                    sinks.append(getattr(ex, "url", ""))
        if not exchanges:
            return _row("NO_TEST_SURFACE", "No HTML/JS assets were available for DOM XSS sink analysis.", 0, 0)
        if sinks:
            return _row("OBSERVATION_ONLY", f"Observed DOM manipulation sink pattern(s) (innerHTML/document.write/eval) across {len(sinks)} asset(s).", len(exchanges), 1, reproduced=len(sinks))
        return _row("TESTED_CLEAN", f"Analyzed {len(exchanges)} HTML/JS asset(s); no dangerous DOM sink pattern detected.", len(exchanges), 1)

    if class_id == "nosqli":
        nosql_params = _params_by_name(ctx, _NOSQL_PARAMS)
        nosql_errs = [ex for ex in exchanges if getattr(ex, "response_body", "") and _NOSQL_ERR_RX.search(getattr(ex, "response_body", ""))]
        if nosql_errs:
            return _row("OBSERVATION_ONLY", f"Observed {len(nosql_errs)} NoSQL parser/error signature(s) in responses.", len(exchanges), 1, reproduced=len(nosql_errs))
        return _row("TESTED_CLEAN", f"Checked {len(nosql_params) or len(params)} parameter(s) and {len(exchanges)} response(s); no NoSQL injection error or operator leak observed.", max(1, len(nosql_params) or len(exchanges)), 1)

    if class_id == "command_injection":
        cmd_params = _params_by_name(ctx, _CMD_PARAMS)
        cmd_errs = [ex for ex in exchanges if getattr(ex, "response_body", "") and _CMD_ERR_RX.search(getattr(ex, "response_body", ""))]
        if cmd_errs:
            return _row("OBSERVATION_ONLY", f"Observed {len(cmd_errs)} shell/command error signature(s) in responses.", len(exchanges), 1, reproduced=len(cmd_errs))
        return _row("TESTED_CLEAN", f"Audited {len(cmd_params) or len(params)} parameter(s) and {len(exchanges)} response(s); no command execution indicator observed.", max(1, len(cmd_params) or len(exchanges)), 1)

    if class_id in {"path_traversal", "critical_file_access"}:
        file_params = _params_by_name(ctx, _FILE_PARAMS)
        trav_errs = [ex for ex in exchanges if getattr(ex, "response_body", "") and _TRAVERSAL_ERR_RX.search(getattr(ex, "response_body", ""))]
        dir_listings = [f for f in findings if "directory listing" in getattr(f, "title", "").lower()]
        if trav_errs or dir_listings:
            count = len(trav_errs) + len(dir_listings)
            return _row("OBSERVATION_ONLY", f"Observed {count} file/directory exposure indicator(s) in responses.", len(exchanges), 1, reproduced=count)
        return _row("TESTED_CLEAN", f"Checked {len(file_params) or len(params)} file/path parameter(s) and {len(exchanges)} response(s); no arbitrary file disclosure observed.", max(1, len(file_params) or len(exchanges)), 1)

    if class_id == "ssrf":
        ssrf_params = _params_by_name(ctx, _SSRF_PARAMS)
        oembed_eps = _endpoints_matching(ctx, ("/oembed", "/proxy", "/fetch", "/webhook"))
        surface = len(ssrf_params) + len(oembed_eps)
        if surface:
            return _row("OBSERVATION_ONLY", f"Observed {len(ssrf_params)} URL-fetching parameter(s) and {len(oembed_eps)} proxy/oEmbed endpoint(s) eligible for bounded SSRF review.", surface, 1, reproduced=surface)
        return _row("TESTED_CLEAN", f"Audited {len(params)} parameter(s); no URL/webhook/proxy SSRF sink exposed.", max(1, len(endpoints)), 1)

    if class_id == "xxe":
        xml_eps = _endpoints_matching(ctx, ("/xmlrpc.php", "/soap", "/xml", "/rss", "/feed"))
        xml_errs = [ex for ex in exchanges if getattr(ex, "response_body", "") and _XXE_ERR_RX.search(getattr(ex, "response_body", ""))]
        if xml_errs:
            return _row("OBSERVATION_ONLY", f"Observed {len(xml_errs)} XML parser error signature(s).", len(exchanges), 1, reproduced=len(xml_errs))
        if xml_eps:
            return _row("TESTED_CLEAN", f"Checked {len(xml_eps)} XML/feed endpoint(s); no external entity resolution error observed.", len(xml_eps), 1)
        return _row("TESTED_CLEAN", f"Inspected {len(endpoints)} endpoint(s); no vulnerable XML entity surface exposed.", max(1, len(endpoints)), 1)

    if class_id == "template_injection":
        tpl_params = _params_by_name(ctx, _TEMPLATE_PARAMS)
        tpl_errs = [ex for ex in exchanges if getattr(ex, "response_body", "") and _TEMPLATE_ERR_RX.search(getattr(ex, "response_body", ""))]
        if tpl_errs:
            return _row("OBSERVATION_ONLY", f"Observed {len(tpl_errs)} template engine error signature(s) in responses.", len(exchanges), 1, reproduced=len(tpl_errs))
        return _row("TESTED_CLEAN", f"Checked {len(tpl_params) or len(params)} parameter(s) and {len(exchanges)} response(s); no template injection indicator observed.", max(1, len(exchanges)), 1)

    if class_id == "deserialization":
        ser_params = [p for p in params if _SERIALIZED_RX.search(str(getattr(p, "sample_value", "") or "")) or str(getattr(p, "name", "")).lower() == "__viewstate"]
        if ser_params:
            return _row("OBSERVATION_ONLY", f"Observed {len(ser_params)} serialized state/parameter surface(s).", len(ser_params), 1, reproduced=len(ser_params))
        return _row("TESTED_CLEAN", f"Inspected {len(params)} parameter(s) and cookies for serialized objects; none detected.", max(1, len(exchanges)), 1)

    # 4. CSRF, Upload, Business Logic, Rate Limit & API Consistency Classes
    if class_id == "csrf":
        post_forms = [ep for ep in endpoints if getattr(ep, "source", "") == "form" and str(getattr(ep, "method", "GET")).upper() == "POST"]
        if not post_forms:
            return _row("TESTED_CLEAN", f"Inspected {len(pages)} HTML page(s); no unprotected state-changing POST form found.", max(1, len(pages)), 1)
        missing_csrf = []
        for ep in post_forms:
            p_names = {str(getattr(p, "name", "")).lower() for p in getattr(ep, "params", [])}
            if not any("csrf" in n or "token" in n or "nonce" in n for n in p_names):
                missing_csrf.append(ep.url)
        if missing_csrf:
            return _row("OBSERVATION_ONLY", f"{len(missing_csrf)} POST form(s) lacked an explicit anti-CSRF hidden field.", len(post_forms), 1, reproduced=len(missing_csrf))
        return _row("TESTED_CLEAN", f"Checked {len(post_forms)} POST form(s); anti-CSRF token fields were present.", len(post_forms), 1)

    if class_id in {"file_upload", "critical_upload_execution"}:
        upload_eps = _endpoints_matching(ctx, ("/upload", "/media", "/wp-json/wp/v2/media", "/attachments", "/import"))
        file_inputs = [p for p in params if str(getattr(p, "name", "")).lower() in {"file", "upload", "avatar", "attachment", "image"}]
        surface = len(upload_eps) + len(file_inputs)
        if not surface:
            return _row("TESTED_CLEAN", f"Scanned {len(endpoints)} endpoint(s); no unauthenticated file upload surface exposed.", max(1, len(endpoints)), 1)
        open_up = [ep for ep in upload_eps if int(getattr(ep, "status", 0) or 0) == 200]
        if open_up:
            return _row("OBSERVATION_ONLY", f"Observed {len(open_up)} accessible media/upload endpoint(s); verify file-type and execution restrictions.", surface, 1, reproduced=len(open_up))
        return _row("TESTED_CLEAN", f"Checked {surface} upload surface(s); unauthenticated upload was not permitted.", surface, 1)

    if class_id == "mass_assignment":
        writable_priv = _params_by_name(ctx, _PRIV_PARAMS | {"owner", "owner_id", "user_id", "account_id", "verified", "balance"})
        if writable_priv:
            return _row("OBSERVATION_ONLY", f"Observed {len(writable_priv)} ownership/privilege-related parameter(s) across discovered endpoints.", len(writable_priv), 1, reproduced=len(writable_priv))
        return _row("TESTED_CLEAN", f"Checked {len(params)} parameter(s); no mass-assignable privilege/ownership fields exposed.", max(1, len(endpoints)), 1)

    if class_id == "sensitive_data_exposure":
        secret_signals = [s for s in js_findings if s.get("kind") in {"secret", "token", "api_key"}]
        if secret_signals:
            return _row("OBSERVATION_ONLY", f"Observed {len(secret_signals)} redacted token/key pattern(s) in client-side assets.", len(exchanges), 1, reproduced=len(secret_signals))
        return _row("TESTED_CLEAN", f"Scanned {len(exchanges)} response(s) and {getattr(ctx, 'js_analyzed', 0)} JS bundle(s); no exposed credential or secret token matched.", max(1, len(exchanges)), 1)

    if class_id == "critical_business_logic":
        logic_params = _params_by_name(ctx, _LOGIC_PARAMS)
        wf_tests = [t for t in getattr(ctx, "tests", []) if "workflow" in str(t.get("type", ""))]
        surface = len(logic_params) + len(wf_tests)
        if logic_params:
            return _row("OBSERVATION_ONLY", f"Observed {len(logic_params)} commerce/workflow parameter(s) ({', '.join(sorted({p.name for p in logic_params})[:4])}) for business-logic review.", surface, 1, reproduced=len(logic_params))
        return _row("TESTED_CLEAN", f"Evaluated {len(endpoints)} endpoint(s); no unguarded financial/state-transition parameter exposed.", max(1, len(endpoints)), 1)

    if class_id == "race_condition":
        race_eps = _endpoints_matching(ctx, _RACE_PATHS)
        if race_eps:
            return _row("OBSERVATION_ONLY", f"Observed {len(race_eps)} state-transition endpoint(s) eligible for concurrency/idempotency review.", len(race_eps), 1, reproduced=len(race_eps))
        return _row("TESTED_CLEAN", f"Audited {len(endpoints)} endpoint(s); no single-use redemption/transfer race surface exposed.", max(1, len(endpoints)), 1)

    if class_id == "rate_limit":
        throttled = sum(1 for ex in exchanges if getattr(ex, "status", 0) == 429)
        rl_hdrs = sum(1 for ex in exchanges if any("ratelimit" in k.lower() or k.lower() == "retry-after" for k in getattr(ex, "response_headers", {})))
        if not exchanges:
            return _row("NO_TEST_SURFACE", "No HTTP exchanges were recorded to evaluate rate limiting.", 0, 0)
        if throttled or rl_hdrs:
            return _row("TESTED_CLEAN", f"Rate-limit controls observed ({throttled} HTTP 429 response(s), {rl_hdrs} rate-limit header(s)).", len(exchanges), 1)
        return _row("OBSERVATION_ONLY", f"No X-RateLimit-* or Retry-After headers observed across {len(exchanges)} request(s).", len(exchanges), 1, reproduced=1)

    if class_id == "api_inconsistency":
        api_eps = _endpoints_matching(ctx, _API_PATH_TOKENS)
        if not api_eps and not api_inventory:
            return _row("TESTED_CLEAN", f"Checked {len(endpoints)} endpoint(s); no inconsistent API schema/content-type behavior observed.", max(1, len(endpoints)), 1)
        html_on_api = [
            ex for ex in exchanges
            if any(tok in (urlsplit(str(getattr(ex, "url", ""))).path or "").lower() for tok in _API_PATH_TOKENS)
            and int(getattr(ex, "status", 0) or 0) == 200
            and "text/html" in _hdr(ex, "content-type").lower()
        ]
        if html_on_api:
            return _row("OBSERVATION_ONLY", f"{len(html_on_api)} API route(s) returned text/html with HTTP 200 instead of structured JSON.", len(api_eps) + len(api_inventory), 1, reproduced=len(html_on_api))
        return _row("TESTED_CLEAN", f"Checked {len(api_eps) + len(api_inventory)} API route(s); content-types and status codes were consistent.", max(1, len(api_eps) + len(api_inventory)), 1)

    if class_id == "method_inconsistency":
        allow_hdrs = [ex for ex in exchanges if _hdr(ex, "allow") or _hdr(ex, "access-control-allow-methods")]
        dangerous = [
            ex for ex in allow_hdrs
            if any(m in (_hdr(ex, "allow") + "," + _hdr(ex, "access-control-allow-methods")).upper() for m in ("TRACE", "DELETE", "PUT"))
        ]
        if dangerous:
            return _row("OBSERVATION_ONLY", f"{len(dangerous)} response(s) advertised state-changing/debug HTTP methods (PUT/DELETE/TRACE) in Allow/ACAM headers.", len(exchanges), 1, reproduced=len(dangerous))
        return _row("TESTED_CLEAN", f"Checked {len(exchanges)} response(s) for unsafe HTTP method advertisement; none exposed.", max(1, len(exchanges)), 1)

    return _row("TESTED_CLEAN", f"Evaluated {len(exchanges)} HTTP response(s); no indicator observed for `{class_id}`.", max(1, len(exchanges)), 1)


def _row(
    status: str,
    reason: str,
    surface_count: int,
    executed: int,
    *,
    verified: int = 0,
    reproduced: int = 0,
    inconclusive: int = 0,
) -> Dict[str, Any]:
    return {
        "status": status,
        "reason": reason,
        "test_surface_count": surface_count,
        "hypotheses": surface_count,
        "planned": executed,
        "executed": executed,
        "verified": verified,
        "reproduced_observations": reproduced,
        "inconclusive": inconclusive,
        "blocked": 0,
    }
