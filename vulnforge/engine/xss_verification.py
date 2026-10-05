from __future__ import annotations

import html
import re
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .verification import VerificationDecision


MARKER_PREFIX = "VF_XSS_"


def _replace_query_parameter(url: str, parameter: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    output = []

    for key, old_value in pairs:
        if key == parameter and not replaced:
            output.append((key, value))
            replaced = True
        else:
            output.append((key, old_value))

    if not replaced:
        output.append((parameter, value))

    return urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path,
        urlencode(output),
        parts.fragment,
    ))


def _context(body: str, marker: str) -> str:
    pos = body.find(marker)
    if pos < 0:
        return "NOT_REFLECTED"

    window = body[max(0, pos - 120):pos + len(marker) + 120]

    if re.search(r"<script[^>]*>.*" + re.escape(marker), window, re.I | re.S):
        return "SCRIPT"

    if re.search(r"<[^>]+=[\"'][^\"']*" + re.escape(marker), window, re.I):
        return "ATTRIBUTE"

    if re.search(r"<[^>]*" + re.escape(marker), window, re.I):
        return "HTML"

    return "TEXT"


async def _browser_execution(body: str, marker: str) -> bool:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return False

    proof = f"VF_PROOF_{uuid.uuid4().hex[:12]}"

    # The lab proof is intentionally harmless: the page title is changed.
    # No alert, network callback, cookie access, or data extraction is used.
    safe_marker = html.escape(proof, quote=True)

    payload = (
        f"<script>document.title='{safe_marker}'</script>"
    )

    rendered = body.replace(marker, payload)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.set_content(rendered, wait_until="domcontentloaded")
            return await page.title() == proof
        finally:
            await browser.close()


async def execute_xss_tests(ctx) -> None:
    specs = list(getattr(ctx, "_xss_test_specs", []) or [])

    for spec in specs:
        test_id = spec["test_id"]
        hypothesis_id = spec["hypothesis_id"]
        url = spec["url"]
        parameter = spec["parameter"]

        marker = MARKER_PREFIX + uuid.uuid4().hex[:12]

        observations = []
        try:
            baseline = await ctx.requester.send(
                "GET",
                _replace_query_parameter(url, parameter, "hello"),
                module="xss",
                follow_redirects=False,
            )

            probe = await ctx.requester.send(
                "GET",
                _replace_query_parameter(url, parameter, marker),
                module="xss",
                follow_redirects=False,
            )

            control_value = html.escape(f"<{marker}>", quote=True)
            control = await ctx.requester.send(
                "GET",
                _replace_query_parameter(url, parameter, control_value),
                module="xss",
                follow_redirects=False,
            )

            observations.extend([baseline, probe, control])

            body = probe.response_body or ""
            reflected = marker in body
            context = _context(body, marker)

            execution = False
            if reflected and context in {"HTML", "SCRIPT", "ATTRIBUTE"}:
                execution = await _browser_execution(body, marker)

            repeat = await ctx.requester.send(
                "GET",
                _replace_query_parameter(url, parameter, marker),
                module="xss",
                follow_redirects=False,
            )

            repeated = marker in (repeat.response_body or "")

            if execution and repeated:
                status = "VERIFIED"
                confidence = 1.0
                reason = "Reflected input reached an executable browser context and reproduced."
            elif reflected and context in {"HTML", "SCRIPT", "ATTRIBUTE"}:
                status = "CANDIDATE"
                confidence = 0.75
                reason = "Unsafe-looking reflection was observed, but browser execution was not reproduced."
            elif reflected:
                status = "CANDIDATE"
                confidence = 0.55
                reason = "Input was reflected, but an executable browser context was not established."
            elif control_value in body:
                status = "KILLED"
                confidence = 0.0
                reason = "Input was encoded rather than reflected as executable markup."
            else:
                status = "KILLED"
                confidence = 0.0
                reason = "No usable reflected XSS behavior was observed."

            ctx.tests.append({
                "test_id": test_id,
                "hypothesis_id": hypothesis_id,
                "type": "xss-reflection-validation",
                "status": status,
                "endpoint": url,
                "parameter": parameter,
                "method": "GET",
                "observations": {
                    "marker": marker,
                    "reflected": reflected,
                    "context": context,
                    "browser_execution": execution,
                    "repeat_reflection": repeated,
                    "baseline_status": baseline.status,
                    "probe_status": probe.status,
                    "control_status": control.status,
                    "repeat_status": repeat.status,
                },
                "reason": reason,
                "confidence": confidence,
            })

            if status == "VERIFIED":
                ctx.findings.append({
                    "title": "Reflected cross-site scripting",
                    "category": "xss",
                    "severity": "HIGH",
                    "endpoint": url,
                    "parameter": parameter,
                    "method": "GET",
                    "confidence": 1.0,
                    "status": "VERIFIED",
                    "state": "VERIFIED",
                    "impact": "Attacker-controlled input executes in the browser context.",
                    "source_plugin": "xss_reflection_validation",
                    "evidence": [{
                        "kind": "xss-browser-execution",
                        "detail": reason,
                    }],
                })

        except Exception as exc:
            ctx.tests.append({
                "test_id": test_id,
                "hypothesis_id": hypothesis_id,
                "type": "xss-reflection-validation",
                "status": "UNTESTABLE",
                "endpoint": url,
                "parameter": parameter,
                "method": "GET",
                "reason": f"XSS verification could not complete: {exc}",
                "confidence": 0.0,
            })


def verify_xss_tests(ctx) -> None:
    for test in getattr(ctx, "tests", []):
        if test.get("type") != "xss-reflection-validation":
            continue

        if test.get("status") == "VERIFIED":
            continue

        test["final_status"] = test.get("status", "UNTESTABLE")
