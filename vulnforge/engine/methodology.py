"""Auditable test cards: concise rationale and reproducible method, not private chain-of-thought."""
from __future__ import annotations
from copy import deepcopy
from typing import Any, Dict

METHOD_CARDS: Dict[str, Dict[str, Any]] = {
    "browser-read-only-workflow": {
        "methodology_id": "VF-METHOD-BROWSER-1",
        "title": "Scope-routed read-only browser workflow observation",
        "objective": "Observe a researcher-defined browser navigation sequence with every HTTP request delegated to Requester.",
        "rationale": "Browser rendering can reveal application routes and UI states, but requests and side effects must remain behind VulnForge's central controls.",
        "preconditions": ["Optional Playwright and Chromium are installed", "Active request explicitly enabled", "Every configured navigation URL is in scope", "Optional storage state is supplied owner-only and remains ephemeral"],
        "steps": ["Launch an ephemeral isolated browser context", "Route HTTP through Requester and re-check scope, rate, budget, cancellation, and stop state", "Block non-safe methods, external requests, downloads, binary assets, and WebSockets", "Run only navigate, selector, and URL assertions", "Do not persist browser state, session headers, or exchange bodies"],
        "negative_controls": ["Out-of-scope URLs are aborted before any target request", "POST/PUT/PATCH/DELETE and unsupported network protocols are blocked"],
        "expected_evidence": ["Exchange IDs, status codes, selector/URL assertion outcomes, and redacted blocked-action notes"],
        "stop_conditions": ["Scope denial", "Per-workflow/global request budget", "Emergency stop/cancellation", "Browser dependency or capability unavailable"],
        "permitted_methods": ["GET", "HEAD", "OPTIONS"], "request_cost": "configured request cap", "risk": "LOW_READ_ONLY",
        "limitations": ["Not a security vulnerability verifier", "No form submission, browser JavaScript assertion code, or state-changing workflow execution"],
    },
    "configured-read-only-workflow": {
        "methodology_id": "VF-METHOD-WORKFLOW-1",
        "title": "Configured read-only HTTP workflow sequence",
        "objective": "Observe an explicitly configured, bounded sequence of in-scope HTTP steps.",
        "rationale": "Multi-step routes can be reviewed without interpreting ordinary status behavior as a vulnerability.",
        "preconditions": ["Researcher-supplied workflow JSON", "Explicit active request and active-capable safety profile", "Every step passes the existing scope and method checks"],
        "steps": ["Execute only the listed GET, HEAD, or OPTIONS steps through Requester", "Do not submit bodies, payloads, scripts, or per-step headers", "Do not follow redirects", "Record status and exchange evidence IDs only"],
        "negative_controls": ["Scope-denied steps are blocked before sending", "Status mismatch remains an observation and does not create a finding"],
        "expected_evidence": ["One exchange ID per executed step", "HTTP status, content type, and expected-status comparison"],
        "stop_conditions": ["Scope denial", "Request budget exhaustion", "Emergency stop or cancellation", "First mismatch by default"],
        "permitted_methods": ["GET", "HEAD", "OPTIONS"], "request_cost": "one per step", "risk": "LOW_READ_ONLY",
        "limitations": ["No browser JavaScript, state-changing request, or vulnerability-specific verifier", "Expected HTTP status does not prove business success or a security property"],
    },
    "cross-account-object-authorization": {
        "methodology_id": "VF-METHOD-BOLA-1",
        "title": "Read-only cross-account object authorization comparison",
        "objective": "Check a researcher-declared owner boundary using two distinct supplied identities.",
        "rationale": "An object identifier is a review lead only; the declared owner invariant and identity assertions are required before execution.",
        "preconditions": ["Two distinct researcher-supplied identities", "Same-origin object URL", "Owner field/value and sensitive fields declared", "SAFE_ACTIVE, CONTROLLED_ACTIVE, or loopback LAB"],
        "steps": ["GET as the declared owner", "GET as the declared non-owner", "Repeat the non-owner GET", "Compare identity assertions, owner field, sensitive fields, and response stability"],
        "negative_controls": ["Identity assertion must distinguish owner from non-owner", "Invalid or non-JSON responses do not verify the hypothesis"],
        "expected_evidence": ["Three linked exchange IDs", "HTTP statuses", "Identity assertion results", "Owner/sensitive-field assertions", "Response digests"],
        "stop_conditions": ["Authorization scope denial", "Request budget exhaustion", "Cancellation", "Invalid/missing identity configuration"],
        "permitted_methods": ["GET"], "request_cost": 3, "risk": "LOW_READ_ONLY",
        "limitations": ["Does not infer identity roles or object ownership", "Only the explicitly configured URL and fields are assessed"],
    },
    "sql-injection-validation": {
        "methodology_id": "VF-METHOD-SQLI-1",
        "title": "Conservative SQL parser-error control check",
        "objective": "Assess whether a single quote in one observed GET query value reproducibly causes a database parser error.",
        "rationale": "An observed parameter is only a lead. The check uses the original value and a plain alphanumeric suffix as controls, then repeats one quote mutation; it never attempts query extraction or a state change.",
        "preconditions": ["Observed in-scope successful GET endpoint", "One non-sensitive query parameter with one short observed value", "Explicit active request and active-capable profile", "GET allowed by the saved scope"],
        "steps": ["Repeat the observed request unchanged", "Append a short alphanumeric suffix as a benign control", "Append one single quote and repeat that exact GET once", "Require a high-confidence database parser-error signature on both quote probes and neither control"],
        "negative_controls": ["Original request and benign-suffix response must lack database error signatures", "A single/non-repeatable error, generic 500, WAF block, or transport failure does not verify"],
        "expected_evidence": ["Four linked exchange IDs", "HTTP statuses", "Database error family labels only; response text and query values are not retained in the finding"],
        "stop_conditions": ["Scope/method denial", "Request budget exhaustion", "Emergency stop/cancellation", "Any transport error"],
        "permitted_methods": ["GET"], "request_cost": 4, "risk": "LOW_READ_ONLY",
        "limitations": ["No boolean, timing, stacked-query, extraction, write, or out-of-band technique", "Verifies repeatable parser-error behavior only; arbitrary SQL execution, data access, and impact are not established"],
    },
    "open-redirect-validation": {
        "methodology_id": "VF-METHOD-REDIRECT-1",
        "title": "Read-only open-redirect parameter validation",
        "objective": "Check whether a researcher-observed redirect-like query parameter controls an external Location response.",
        "rationale": "A parameter name alone is not a vulnerability. A paired external marker and same-origin control check whether the supplied parameter actually controls the redirect destination.",
        "preconditions": ["Observed in-scope GET URL with a redirect-like query parameter", "Explicit authorization and active-capable safety mode", "GET permitted by the existing scope"],
        "steps": ["Replace only the observed parameter with https://vf-redirect.invalid/vf-validation", "Send one scoped GET without following redirects", "Repeat with /vf-internal-validation as a same-origin control", "Verify the first Location targets only the reserved marker host and the control remains on the original origin"],
        "negative_controls": ["A fixed internal redirect does not satisfy the external-marker check", "A missing Location, non-redirect status, scope denial, or incomplete pair does not verify"],
        "expected_evidence": ["Two linked GET exchange IDs", "Tested parameter name", "Response status and Location for each request", "Target origin and marker comparison"],
        "stop_conditions": ["Authorization scope denial", "Request budget exhaustion", "Cancellation", "Malformed URL or missing query parameter"],
        "permitted_methods": ["GET"], "request_cost": 2, "risk": "LOW_READ_ONLY",
        "limitations": ["Does not follow the redirect or visit the reserved marker host", "Does not prove phishing success, credential theft, or business impact"],
    },
    "cors-origin-reflection": {
        "methodology_id": "VF-METHOD-CORS-1",
        "title": "Read-only credentialed CORS origin-reflection check",
        "objective": "Verify whether an in-scope GET response reflects multiple unrelated test origins while allowing credentials.",
        "rationale": "A single ACAO header can be an intentional allowlist; identical reflection behavior for three distinct reserved .invalid origins is stronger evidence of a broad reflection policy.",
        "preconditions": ["An observed in-scope GET endpoint", "Explicit authorization and active-capable safety mode", "GET allowed by the saved request policy"],
        "steps": ["Send one GET with Origin https://vf-a.invalid", "Repeat with https://vf-b.invalid and https://vf-c.invalid", "Record ACAO, ACAC, Vary, status, and exchange provenance", "Independently require exact origin reflection and ACAC=true on all three 2xx responses"],
        "negative_controls": ["A fixed allowlisted origin does not satisfy reflection for all three test origins", "Wildcard ACAO without ACAC=true is not reported as credentialed reflection", "Errors, redirects, scope denials, and partial runs do not verify"],
        "expected_evidence": ["Three linked GET exchange IDs", "Each request Origin", "ACAO and ACAC response headers", "Status and Vary header"],
        "stop_conditions": ["Authorization scope denial", "Request budget exhaustion", "Cancellation", "Non-2xx response"],
        "permitted_methods": ["GET"], "request_cost": 3, "risk": "LOW_READ_ONLY",
        "limitations": ["Verifies response policy headers only; does not prove browser execution, sensitive-data access, cookie delivery, or user impact"],
    },
}


def build_test_methodology(test_type: str, endpoint: str = "") -> Dict[str, Any]:
    """Return an isolated, JSON-safe methodology card attached to a planned test."""
    card=deepcopy(METHOD_CARDS.get(test_type, {}))
    if not card:
        return {"methodology_id":"VF-METHOD-UNSUPPORTED","test_type":test_type,
                "status":"UNSUPPORTED","reason":"No auditable test methodology is registered."}
    card["test_type"]=test_type
    card["endpoint"]=str(endpoint)
    card["status"]="DEFINED"
    return card
