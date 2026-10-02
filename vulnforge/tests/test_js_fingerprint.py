"""JS analysis + technology fingerprint tests."""
from vulnforge.core.redaction import REDACTED
from vulnforge.engine.jsanalysis import analyze_js
from vulnforge.engine.fingerprint import fingerprint_pages
from vulnforge.core.models import ScanContext, HttpExchange, ScanStats
from vulnforge.engine.crawler import PageParser


def test_js_extracts_fetch_and_graphql():
    code = "fetch('/api/v1/orders?id=3'); axios.post('/graphql', q);"
    signals, cands = analyze_js("app.js", code, "http://t.example/")
    urls = "\n".join(sorted(cands))
    assert "http://t.example/api/v1/orders?id=3" in urls
    assert any(s.kind == "graphql_hint" for s in signals)


def test_js_secret_signal_is_redacted():
    code = '{"api_key": "AKIAIOSFODNN7EXAMPLE"}'
    signals, _ = analyze_js("conf.js", code, "http://t.example/")
    secret_signals = [s for s in signals if s.kind == "secret_like"]
    assert secret_signals, "expected a secret_like signal"
    assert "AKIAIOSFODNN7EXAMPLE" not in str(secret_signals[0].detail)
    assert REDACTED in secret_signals[0].detail


def test_js_websocket_and_sourcemap():
    code = 'new WebSocket("wss://x/socket"); //# sourceMappingURL=a.js.map'
    signals, _ = analyze_js("a.js", code, "http://t.example/")
    kinds = {s.kind for s in signals}
    assert "websocket_hint" in kinds and "source_map" in kinds


def test_js_strings_are_signals_not_findings():
    code = 'const p = "/admin/delete-everything";'
    signals, _ = analyze_js("x.js", code, "http://t.example/")
    # discovery signals only — never findings/vulnerabilities
    assert all(s.severity_hint in ("info", "low", "medium", "high") for s in signals)


def test_fingerprint_from_headers_and_html():
    ctx = ScanContext(scan_id="t", config=None, authorization=None)
    ex = HttpExchange(
        method="GET", url="http://t.example/", status=200,
        response_headers={"Server": "nginx/1.25", "X-Powered-By": "Express",
                          "Set-Cookie": "laravel_session=abc; HttpOnly"},
        response_body='<html><head></head><body><div id="__NEXT_DATA__"></div></body></html>',
    )
    parser = PageParser(ex.url)
    parser.feed(ex.response_body)
    fingerprint_pages(ctx, [(ex, parser)])
    names = {t.name for t in ctx.technologies.values()}
    assert "nginx" in names or "Express" in names
    assert "Laravel" in names and "Next.js" in names
    confs = {t.name: t.confidence for t in ctx.technologies.values()}
    assert confs.get("Express") == "HIGH"


def test_js_spa_routes_graphql_ops_and_parameter_mining():
    from vulnforge.engine.jsanalysis import extract_js_parameters

    code = """
    <Route path="/account/:id/billing" element={<Billing />} />
    router.push('/workspace/settings');
    const q = `query GetTenantBilling { billing { id } }`;
    const p = searchParams.get('tenant_id');
    axios.get('/api/v2/invoices', { params: { invoice_id: 10, currency: 'USD' } });
    """
    signals, cands = analyze_js("spa.js", code, "http://t.example/")
    kinds = {s.kind for s in signals}
    assert "spa_route" in kinds
    assert "graphql_operation" in kinds
    assert "js_parameter" in kinds
    assert "http://t.example/account/1/billing" in cands
    assert "http://t.example/workspace/settings" in cands
    mined = extract_js_parameters(code)
    assert {"tenant_id", "invoice_id", "currency"}.issubset(mined)

