"""Evidence-backed passive intelligence extracted from actual scan observations.

No active payloads or inferred product/version claims are made here. Missing
coverage is represented as NOT DETERMINED rather than as a negative finding.
"""
from __future__ import annotations

import re
import socket
import time
from collections import defaultdict
from typing import Any, Dict, List
from urllib.parse import urlsplit

SECURITY_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-embedder-policy": "COEP",
    "cross-origin-resource-policy": "CORP",
}
MFA_TERMS = re.compile(r"\b(mfa|2fa|otp|totp|webauthn|passkey|authenticator|security key|recovery codes?)\b", re.I)
AUTH_TERMS = re.compile(r"\b(login|log in|sign in|register|password reset|forgot password|oauth|openid|oidc|saml|bearer)\b", re.I)
API_PATTERNS = {
    "GraphQL": re.compile(r"graphql", re.I),
    "OpenAPI/Swagger": re.compile(r"openapi|swagger", re.I),
    "JSON-RPC": re.compile(r"json-rpc", re.I),
    "WebSocket": re.compile(r"(?:wss?|websocket)", re.I),
    "SSE": re.compile(r"text/event-stream|eventsource", re.I),
}


def _safe_cookie(value: str) -> Dict[str, Any]:
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True)
             for p in parts[1:]}
    low_name = name.lower()
    return {
        "name": name[:100], "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": attrs.get("samesite", "NOT SET"),
        "domain": attrs.get("domain", ""), "path": attrs.get("path", ""),
        "expires": attrs.get("expires", ""), "max_age": attrs.get("max-age", ""),
        "prefix": "__Host-" if name.startswith("__Host-") else ("__Secure-" if name.startswith("__Secure-") else ""),
        "session_like": any(x in low_name for x in ("session", "sid", "auth", "token")),
    }


def collect_intelligence(ctx) -> Dict[str, Any]:
    """Create truthful scan-level intelligence from pages and local DNS lookup."""
    target = ctx.config.target
    host = urlsplit(target).hostname or ""
    if hasattr(ctx,"observed_ips"):
        ips=list(ctx.observed_ips)
    elif getattr(ctx.authorization,"stopped",False):
        ips=[]
    else:
        try:
            ips = sorted({row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
        except (OSError, UnicodeError):
            ips = []
    dns = {"hostname": host, "A": [], "AAAA": [], "observed_addresses": ips,
           "additional_records": "NOT DETERMINED (no DNS record resolver configured)"}
    for ip in ips:
        (dns["AAAA"] if ":" in ip else dns["A"]).append(ip)

    tls: Dict[str, Any] = {"status": "NOT DETERMINED", "reason": "TLS certificate details are not exposed by the current HTTP transport"}
    services = {}
    redirects = []
    cookies = {}
    header_observations = defaultdict(lambda: {"observed": 0, "missing": 0, "examples": []})
    auth_signals, mfa_signals, api_signals = set(), set(), set()
    all_body = "\n".join((x.response_body or "")[:300000] for x in ctx.pages)
    for ex in ctx.pages:
        p = urlsplit(ex.url)
        key = f"{p.scheme}://{p.netloc}"
        services[key] = {"url": key, "host": p.hostname, "port": p.port or (443 if p.scheme == "https" else 80),
                         "protocol": p.scheme.upper(), "status": ex.status,
                         "content_type": ex.header("content-type"), "server": ex.header("server", "UNKNOWN")}
        if getattr(ex, "redirect_chain", None):
            redirects.extend(ex.redirect_chain)
        if ex.status in (301, 302, 303, 307, 308) and ex.header("location"):
            dest = ex.header("location")
            redirects.append({"source": ex.url, "destination": dest, "status_code": ex.status,
                              "host_change": (urlsplit(dest).hostname or p.hostname) != p.hostname,
                              "scheme_change": urlsplit(dest).scheme not in ("", p.scheme),
                              "redirect_type": "HTTPS UPGRADE" if p.scheme == "http" and dest.startswith("https:") else "REDIRECT"})
        body = ex.response_body or ""
        if AUTH_TERMS.search(body) or re.search(r"/(?:login|signin|oauth|authorize)(?:[/?#]|$)", p.path, re.I):
            auth_signals.add("authentication workflow or route text observed")
        if MFA_TERMS.search(body):
            mfa_signals.update(set(m.group(0).lower() for m in MFA_TERMS.finditer(body)))
        for label, rx in API_PATTERNS.items():
            if rx.search(body) or (label == "WebSocket" and rx.search(ex.url)):
                api_signals.add(label)
        for name, label in SECURITY_HEADERS.items():
            observation = header_observations[label]
            observation["observed"] += 1
            if not ex.header(name):
                observation["missing"] += 1
            elif len(observation["examples"]) < 3:
                observation["examples"].append({"url": ex.url, "value": ex.header(name)[:300]})
        for k, v in ex.response_headers.items():
            if k.lower() == "set-cookie":
                cookie = _safe_cookie(v)
                cookies[cookie["name"]] = cookie

    # Include non-HTML service probes (e.g. same-host HTTP/HTTPS HEAD checks).
    for ex in getattr(ctx.requester, "exchanges", []):
        p = urlsplit(ex.url)
        key = f"{p.scheme}://{p.netloc}"
        services.setdefault(key, {"url": key, "host": p.hostname,
            "port": p.port or (443 if p.scheme == "https" else 80),
            "protocol": p.scheme.upper(), "status": ex.status,
            "content_type": ex.header("content-type"), "server": ex.header("server", "UNKNOWN")})
        redirects.extend(getattr(ex, "redirect_chain", []))
    # Preserve order while removing identical hop records observed through multiple pages.
    redirects = list({(r.get("source"), r.get("destination"), r.get("status_code")): r for r in redirects}.values())
    final_url = target
    for hop in redirects:
        if hop.get("source") == target and hop.get("scope_status", "IN-SCOPE") == "IN-SCOPE":
            final_url = hop.get("destination", final_url)

    # API declarations are evidence only when present in actual observed pages/assets.
    api_count = defaultdict(int)
    for ep in ctx.endpoints.values():
        path = urlsplit(ep.url).path.lower()
        if "/api/" in path or path.startswith("/api"):
            api_count["REST"] += 1
        if "graphql" in path:
            api_count["GraphQL"] += 1
        if "ws://" in ep.url or "wss://" in ep.url:
            api_count["WebSocket"] += 1
    for a in api_signals:
        api_count.setdefault(a, 0)

    ctx.intelligence = {
        "target": {"original_input": getattr(ctx.config, "original_target", target),
                   "canonical_url": target, "final_url": final_url,
                   "hostname": host, "scheme": urlsplit(target).scheme,
                   "port": urlsplit(target).port or (443 if urlsplit(target).scheme=="https" else 80),
                   "resolved_ips": ips},
        "dns": dns, "services": list(services.values()), "redirects": redirects,
        "tls": tls, "security_headers": dict(header_observations), "cookies": list(cookies.values()),
        "authentication": {"status": "DETECTED" if auth_signals else "NOT DETERMINED",
                            "signals": sorted(auth_signals)},
        "mfa": {"status": "DETECTED" if mfa_signals else "NOT DETERMINED",
                "methods_or_terms": sorted(mfa_signals),
                "reason": "No authenticated account workflow was supplied" if not mfa_signals else "Terms observed in fetched content; workflow not verified"},
        "api": {"types_observed": sorted(api_count), "inventory_counts": dict(api_count)},
        "coverage": {"pages_crawled": len(ctx.pages), "endpoints_discovered": len(ctx.endpoints),
                     "parameters_discovered": len(ctx.parameters),
                     "javascript_discovered": len(getattr(getattr(ctx, "_crawl_result", None), "js_assets", [])),
                     "javascript_analyzed": getattr(ctx, "js_analyzed", 0),
                     "hypotheses": len(getattr(ctx, "hypotheses", [])),
                     "verified_findings": sum(1 for f in getattr(ctx,"verified_findings",[]) if f.status == "VERIFIED")},
        "generated_at": time.time(),
    }
    return ctx.intelligence
