"""
Passive plugin — information disclosure in already-fetched content (spec §36).

Detects stack traces, framework error pages, directory listings, and debug
banners in pages the pipeline already downloaded. No new requests are sent —
that keeps this strictly passive. Values are masked; only context is shown.
"""
from __future__ import annotations

import re
from typing import List

from ...core.models import Finding, EvidenceItem, ScanContext, STATUS_CANDIDATE
from ...core.redaction import redact_text
from ..base import DetectorPlugin, register

_SIGNATURES = [
    ("stack_trace", re.compile(r"(Traceback \(most recent call last\)|NullPointerException|"
                               r"at [\w.$]+\([\w.]+:\d+\)|System\.Exception:|stack trace[: ]|"
                               r"File \"[^\"]+\.py\", line \d+)", re.I),
     "Application stack trace in response", "medium",
     "Error messages reveal internal code paths, file names and framework details."),
    ("django_debug", re.compile(r"You're seeing this error because you have DEBUG = True", re.I),
     "Django DEBUG mode enabled", "high",
     "DEBUG pages can disclose settings, environment, and code."),
    ("flask_debugger", re.compile(r"Werkzeug Debugger|The debugger caught an exception", re.I),
     "Werkzeug/Flask debugger exposed", "critical",
     "An exposed interactive debugger may allow arbitrary code execution."),
    ("dir_listing", re.compile(r"Index of /|Parent Directory</a>|Directory listing for /", re.I),
     "Directory listing enabled", "low",
     "Directory listings expose file names that help an attacker map the server."),
    ("php_error", re.compile(r"(Warning|Fatal error|Parse error): .{0,120} on line \d+", re.I),
     "PHP error message in response", "medium",
     "PHP errors disclose server paths and code details."),
    ("sql_error", re.compile(r"(SQL syntax.*MySQL|Warning.*\bmysqli?\b|PostgreSQL.*ERROR|"
                             r"ORA-\d{5}|SQLite3::|unclosed quotation mark)", re.I),
     "Database error message in response", "high",
     "Database errors prove input reaches the SQL layer and disclose engine details."),
]


@register
class InfoDisclosurePlugin(DetectorPlugin):
    id = "vf2-passive-info-disclosure"
    name = "Information Disclosure in Responses"
    category = "information-disclosure"
    severity = "medium"
    confidence_base = 0.8
    cwe = "CWE-209"
    owasp = "A05:2021-Security Misconfiguration / A09:2021-Logging Failures"
    description = ("Detects stack traces, debug consoles, directory listings and "
                   "engine error messages in passively collected responses.")
    remediation = ("Disable debug modes in production, route errors to generic pages, "
                   "and turn off directory indexes. Treat any exposed debugger as "
                   "an incident until proven otherwise.")
    passive = True

    def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()
        for ex in ctx.pages:
            if not ex.ok or not ex.response_body:
                continue
            for kind, rx, title, sev, impact in _SIGNATURES:
                m = rx.search(ex.response_body)
                if not m:
                    continue
                key = (kind, ex.url.split("?")[0])
                if key in seen:
                    continue
                seen.add(key)
                snippet = redact_text(
                    ex.response_body[max(0, m.start() - 60): m.end() + 60]).replace("\n", " ")[:220]
                # Passive signature matching is only a candidate; no security boundary
                # violation has been verified by this observation alone.
                status = STATUS_CANDIDATE
                findings.append(Finding(
                    title=title,
                    category="Information Disclosure",
                    severity=sev,
                    description=(f"A {kind.replace('_', ' ')} signature was matched in the response of "
                                 f"{ex.url}. Matched text (masked): “{snippet}”"),
                    endpoint=ex.url,
                    confidence=0.7,
                    status=status,
                    evidence=[EvidenceItem(
                        description=f"signature '{m.group(0)[:80]}' matched in body",
                        request_summary=f"GET {ex.url}",
                        response_summary=f"HTTP {ex.status}, {ex.body_length} bytes, masked snippet shown above")],
                    remediation=self.remediation, cwe=self.cwe, owasp=self.owasp,
                    references=self.references, source_plugin=self.id,
                    impact=impact,
                    simple_summary=f"The page at {ex.url} shows internal technical error details.",
                    why_it_matters=impact,
                    manual_verification=("Confirm the signature appears on freshly fetched pages and is "
                                         "not part of static documentation content."),
                ))
        return findings
