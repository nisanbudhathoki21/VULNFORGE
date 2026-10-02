"""
Passive plugin — HTTP security header & cookie-flag analysis (spec §35).

These are CONFIGURATION observations, never 'critical vulnerabilities':
missing-header findings are capped at low/info severity with a clear
misconfiguration label (audit requirement: misconfig ≠ exploit).
"""
from __future__ import annotations

from typing import Dict, List

from ...core.models import Finding, EvidenceItem, ScanContext, STATUS_LIKELY
from ..base import DetectorPlugin, register

# Header/cookie-flag presence is read directly off a response VulnForge already
# captured — there is no ambiguity to resolve and nothing to reproduce, so
# (unlike a signature match that could be a false positive) this clears the
# project's VERIFIED bar on the first observation. Severity stays capped at
# low/info regardless: a missing header is a hardening gap, never proof of
# exploitability, and VERIFIED here only means "the absence is real," not
# "this is a confirmed exploitable vulnerability."

_HEADERS = [
    ("Content-Security-Policy", "low", "Helps prevent XSS and data-injection by constraining where content can load from."),
    ("Strict-Transport-Security", "low", "Forces HTTPS on subsequent visits; missing on HTTPS sites enables downgrade attacks."),
    ("X-Content-Type-Options", "info", "Prevents MIME-sniffing of responses into executable content."),
    ("X-Frame-Options", "low", "Protects against clickjacking (or use CSP frame-ancestors)."),
    ("Referrer-Policy", "info", "Controls how much URL data leaks to third parties via the Referer header."),
    ("Permissions-Policy", "info", "Restricts powerful browser features (camera, mic, geolocation)."),
]

_IMPORTANT_PATH_HINT = ("/login", "/auth", "/account", "/checkout", "/payment", "/admin")


@register
class SecurityHeadersPlugin(DetectorPlugin):
    id = "vf2-passive-security-headers"
    name = "Missing HTTP Security Headers"
    category = "misconfiguration"
    severity = "low"
    confidence_base = 0.9
    cwe = "CWE-693"
    owasp = "A05:2021-Security Misconfiguration"
    description = ("Detects responses missing well-established defensive headers. "
                   "These are hardening gaps (misconfigurations), not directly "
                   "exploitable vulnerabilities.")
    remediation = ("Set the recommended headers at the application or reverse-proxy "
                   "layer. Prioritize Content-Security-Policy and "
                   "Strict-Transport-Security on authentication and payment surfaces.")
    references = ["https://owasp.org/www-project-secure-headers/"]
    passive = True

    def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        seen_pages = 0
        # representative sample: analyze every crawled page, report per header
        # aggregated across pages to avoid finding-spam (spec §40).
        missing_counter: Dict[str, Dict[str, int]] = {}
        examples: Dict[str, str] = {}
        for ex in ctx.pages:
            if not ex.ok or "text/html" not in (ex.header("content-type") or "").lower():
                continue
            seen_pages += 1
            for header, _sev, _why in _HEADERS:
                if not ex.header(header):
                    bucket = missing_counter.setdefault(header, {"missing": 0, "total": 0})
                    bucket["missing"] += 1
                    examples.setdefault(header, ex.url)
                bucket = missing_counter.setdefault(header, {"missing": 0, "total": 0})
                bucket["total"] += 1
        if not seen_pages:
            return findings
        for header, sev, why in _HEADERS:
            c = missing_counter.get(header)
            if not c or c["missing"] == 0:
                continue
            coverage = f"{c['missing']}/{c['total']} HTML pages"
            important = any(h in examples.get(header, "") for h in _IMPORTANT_PATH_HINT)
            sev_eff = sev if not important else ("low" if sev == "info" else sev)
            findings.append(Finding(
                title=f"Security header not set: {header}",
                category="Security Misconfiguration (header hardening)",
                severity=sev_eff,
                description=(f"The HTTP header {header} was absent on {coverage} crawled. "
                             f"{why} This is a defense-in-depth gap, not a directly "
                             f"exploitable vulnerability."),
                endpoint=examples.get(header, ""),
                confidence=self.confidence_base,
                status=STATUS_LIKELY,
                evidence=[EvidenceItem(
                    description=f"{header} absent on {coverage} of crawled HTML pages",
                    response_summary=f"example: GET {examples.get(header, '?')} — header not present")],
                remediation=self.remediation,
                references=self.references, cwe=self.cwe, owasp=self.owasp,
                source_plugin=self.id,
                simple_summary=f"The site does not send the '{header}' protection header.",
                why_it_matters=("Browsers get less guidance on how to safely handle the site, "
                                "which makes some other attacks easier to perform."),
                manual_verification=("Re-request the listed URL and confirm the header is absent "
                                     "from the live response headers."),
            ))
        return findings


@register
class CookieFlagsPlugin(DetectorPlugin):
    id = "vf2-passive-cookie-flags"
    name = "Cookie Security Attribute Analysis"
    category = "misconfiguration"
    severity = "low"
    confidence_base = 0.9
    cwe = "CWE-1004"
    owasp = "A05:2021-Security Misconfiguration"
    description = ("Checks Set-Cookie attributes (Secure, HttpOnly, SameSite) on "
                   "cookies observed during the crawl.")
    remediation = ("Mark session cookies Secure + HttpOnly + SameSite=Lax/Strict. "
                   "Only omit HttpOnly for cookies JavaScript genuinely needs.")
    passive = True

    def run(self, ctx: ScanContext) -> List[Finding]:
        issues: Dict[str, set] = {}
        for ex in ctx.pages:
            for k, v in ex.response_headers.items():
                if k.lower() != "set-cookie":
                    continue
                name = v.split("=", 1)[0].strip()[:40]
                low = v.lower()
                entry = issues.setdefault(name, set())
                if "secure" not in low and ex.url.startswith("https://"):
                    entry.add("missing Secure")
                if "httponly" not in low:
                    entry.add("missing HttpOnly")
                if "samesite" not in low:
                    entry.add("no SameSite attribute")
        findings: List[Finding] = []
        for name, problems in sorted(issues.items()):
            if not problems:
                continue
            findings.append(Finding(
                title=f"Cookie '{name}' lacks security attributes",
                category="Security Misconfiguration (cookie hardening)",
                severity="low",
                description=(f"The cookie '{name}' was set with: {', '.join(sorted(problems))}. "
                             f"Cookies are redacted from findings; only the name is shown."),
                confidence=self.confidence_base,
                status=STATUS_LIKELY,
                evidence=[EvidenceItem(description=f"Set-Cookie {name}=… ({', '.join(sorted(problems))})")],
                remediation=self.remediation, cwe="CWE-614", owasp=self.owasp,
                source_plugin=self.id,
                simple_summary=f"A cookie named '{name}' is missing protective flags.",
                why_it_matters=("Without these flags the cookie is easier to steal through "
                                "script injection or to send in unwanted cross-site contexts."),
                manual_verification=("Inspect the Set-Cookie header for this cookie in your browser's "
                                     "dev tools or a fresh request and confirm the listed flag(s) are absent."),
            ))
        return findings
