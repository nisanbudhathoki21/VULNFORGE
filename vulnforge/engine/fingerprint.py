"""
VulnForge — technology fingerprinting (spec §12).

Multi-signal detection: headers, cookies, HTML, JS. No exclusive probing in
passive mode — analysis runs over pages the pipeline already fetched, so
detection is free of extra requests. Each observation carries a confidence
(HIGH/MEDIUM/LOW) with the signals that support it.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlsplit

from ..core.models import HttpExchange, ScanContext

# (name, category, confidence, header-name, value-regex-or-None)
HEADER_RULES = [
    ("Cloudflare", "cdn", "HIGH", "cf-ray", None),
    ("Cloudflare", "cdn", "HIGH", "server", r"cloudflare"),
    ("nginx", "server", "HIGH", "server", r"nginx"),
    ("Apache", "server", "HIGH", "server", r"apache"),
    ("Microsoft-IIS", "server", "HIGH", "server", r"microsoft-iis"),
    ("LiteSpeed", "server", "HIGH", "server", r"litespeed"),
    ("ASP.NET", "framework", "HIGH", "x-powered-by", r"asp\.net"),
    ("ASP.NET", "framework", "MEDIUM", "x-aspnet-version", None),
    ("Express", "framework", "HIGH", "x-powered-by", r"express"),
    ("PHP", "language", "HIGH", "x-powered-by", r"php"),
    ("Next.js", "framework", "HIGH", "x-powered-by", r"next\.js"),
    ("Vercel", "cdn", "HIGH", "x-vercel-id", None),
    ("Netlify", "cdn", "HIGH", "x-nf-request-id", None),
    ("AWS CloudFront", "cdn", "HIGH", "x-amz-cf-id", None),
    ("Akamai", "cdn", "MEDIUM", "x-akamai-transformed", None),
    ("Fastly", "cdn", "HIGH", "x-served-by", r"cache-"),
    ("Imperva", "waf", "HIGH", "x-iinfo", None),
    ("Imperva", "waf", "MEDIUM", "x-cdn", r"Imperva"),
    ("AWS CloudFront", "cdn", "HIGH", "via", r"cloudfront"),
    ("AWS WAF", "waf", "MEDIUM", "x-amzn-waf-action", None),
    ("Azure Front Door", "cdn", "HIGH", "x-azure-ref", None),
    ("F5", "waf", "MEDIUM", "x-wa-info", None),
]

COOKIE_RULES = [
    ("PHP", "language", "HIGH", r"\bPHPSESSID="),
    ("Java Servlet", "framework", "HIGH", r"\bJSESSIONID="),
    ("ASP.NET", "framework", "HIGH", r"\bASP\.NET_SessionId="),
    ("Django", "framework", "MEDIUM", r"\bcsrftoken="),
    ("Laravel", "framework", "HIGH", r"\blaravel_session="),
    ("WordPress", "cms", "HIGH", r"\bwp-settings"),
    ("Rails", "framework", "MEDIUM", r"\b_session_id="),
]

HTML_RULES = [
    ("WordPress", "cms", "MEDIUM", r"wp-content/(?:themes|plugins)/[^\"'\\s]+|wp-includes/(?:js|css)/[^\"'\\s]+"),
    ("Drupal", "cms", "HIGH", r"Drupal\.settings|/sites/default/files"),
    ("Joomla", "cms", "HIGH", r"/media/jui/|content=\"Joomla!"),
    ("React", "js-framework", "MEDIUM", r"data-reactroot|__REACT|react-dom(?:\\.production)?\\.min\\.js"),
    ("Next.js", "framework", "HIGH", r"__NEXT_DATA__|/_next/static"),
    ("Vue", "js-framework", "MEDIUM", r"data-v-[0-9a-f]{8}|id=\"app\"[^>]*data-server-rendered|\bnew Vue\("),
    ("Nuxt", "framework", "HIGH", r"__NUXT__|/_nuxt/"),
    ("Angular", "js-framework", "MEDIUM", r"\bng-app=|\bng-version=|_ngcontent-"),
    ("Svelte", "js-framework", "LOW", r"\bsvelte-"),
    ("jQuery", "js-framework", "MEDIUM", r"jquery[-.min]*\.js|\$\(document\)\.ready"),
    ("Bootstrap", "js-framework", "LOW", r"bootstrap[-.min]*\.(css|js)"),
    ("Swagger UI", "api", "MEDIUM", r"swagger-ui|swagger-initializer\.js"),
    ("Tailwind CSS", "frontend", "MEDIUM", r"tailwindcss|--tw-"),
    ("Vite", "build-tool", "MEDIUM", r"/@vite/client|vite\.svg"),
    ("Webpack", "build-tool", "MEDIUM", r"webpackJsonp|webpackChunk|webpack://"),
    ("Shopify", "cms", "HIGH", r"cdn\.shopify\.com|Shopify\.theme"),
    ("Magento", "cms", "HIGH", r"/static/version[0-9]+/frontend|Mage\.Cookies"),
]

GENERATOR_RULES = [
    ("WordPress", "cms", "High", r"wordpress"),
    ("Drupal", "cms", "HIGH", r"drupal"),
    ("Joomla", "cms", "HIGH", r"joomla"),
    ("Hugo", "framework", "MEDIUM", r"hugo"),
    ("Ghost", "cms", "MEDIUM", r"ghost"),
]


def _page_location(url: str) -> str:
    try:
        parts=urlsplit(url)
        return f"{parts.hostname or 'observed host'}{parts.path or '/'}"[:160]
    except Exception:
        return "observed page"


def fingerprint_pages(ctx: ScanContext, pages: Iterable[Tuple[HttpExchange, Any]]) -> None:
    for ex, parser in pages:
        if not ex.ok:
            continue
        # --- headers ---------------------------------------------------
        headers = {k.lower(): v for k, v in ex.response_headers.items()}
        for name, cat, conf, hname, rx in HEADER_RULES:
            val = headers.get(hname)
            if val is None:
                continue
            if rx is None or re.search(rx, val, re.I):
                ctx.add_technology(name, cat, conf, f"header marker: {hname} on {_page_location(ex.url)}")
        server = headers.get("server", "")
        if server and not any(t.name == server for t in ctx.technologies.values()):
            ctx.add_technology(server.split("/")[0], "server", "MEDIUM", f"server header on {_page_location(ex.url)}")

        # --- cookies ----------------------------------------------------
        for ck, vals in (("set-cookie", [v for k, v in ex.response_headers.items() if k.lower() == "set-cookie"]),):
            for v in vals:
                for name, cat, conf, rx in COOKIE_RULES:
                    if re.search(rx, v):
                        cookie_name=v.split("=",1)[0].strip()
                        ctx.add_technology(name, cat, conf, f"cookie name: {cookie_name} on {_page_location(ex.url)}")

        # --- html --------------------------------------------------------
        body = ex.response_body or ""
        for name, cat, conf, rx in HTML_RULES:
            if re.search(rx, body, re.I):
                ctx.add_technology(name, cat, conf, f"HTML signature: {name} on {_page_location(ex.url)}")
        gen = getattr(parser, "generator", "") if parser is not None else ""
        if gen:
            for name, cat, conf, rx in GENERATOR_RULES:
                if re.search(rx, gen, re.I):
                    ctx.add_technology(name, cat, conf.upper(), f"meta generator: {gen[:80]}")
