from io import StringIO
from types import SimpleNamespace

from vulnforge import cli
from vulnforge.cli import build_parser
from vulnforge.cli_ui import LiveScanDashboard, banner_lines, run_results_workbench


def test_banner_uses_wordmark_and_narrow_terminal_fallback():
    assert "VULNFORGE" in "\n".join(banner_lines(60))
    wide = banner_lines(100)
    assert wide[0].startswith("██╗")
    assert "RED TEAM SECURITY ENGINE" not in "\n".join(wide)
    assert max(map(len, banner_lines(79))) <= 30


def test_live_dashboard_uses_actual_exchange_and_hides_query_values():
    output = StringIO()
    clock = iter([10.0, 12.0, 12.0, 12.0, 12.0])
    dashboard = LiveScanDashboard(
        "http://127.0.0.1:8765/?session=target-secret", stream=output, tty=True, color=False,
        clock=lambda: next(clock),
    )
    dashboard("http-exchange", "GET /private?token=do-not-print", {
        "method": "GET", "url": "http://127.0.0.1:8765/private?token=do-not-print",
        "status": 200, "response_chars": 37, "duration_ms": 14.2,
    })
    assert dashboard.requests == 1
    rendered = output.getvalue()
    assert "/private" in rendered
    assert "do-not-print" not in rendered
    assert "target-secret" not in rendered
    dashboard("stage-start", "Inspect \u001b]0;evil-title\u0007 https://example.test/path?x=private", {})
    rendered = output.getvalue()
    assert "?x=private" not in rendered
    assert "\x1b]0;evil-title" not in rendered
    assert "200" in rendered and "37 ch" in rendered
    assert "RED TEAM SECURITY ENGINE" not in rendered
    assert "No HTTP exchange has been recorded" not in rendered
    assert max(map(len, dashboard.lines(40))) <= 40


def test_scan_output_options_and_results_alias_parse_without_changing_scan_url_form():
    parser = build_parser()
    args = parser.parse_args(["scan", "url", "http://127.0.0.1:8765", "--all", "--lab", "--interactive"])
    assert args.target == "url" and args.target_extra == "http://127.0.0.1:8765"
    assert args.severity_profile == "full" and args.interactive
    assert parser.parse_args(["scan", "example.test", "--quiet"]).quiet
    assert parser.parse_args(["scan", "example.test", "--json"]).json_output
    assert parser.parse_args(["results"]).command == "results"


def test_verbose_event_renderer_redacts_urls_and_terminal_controls(capsys):
    emit = cli._emit(verbose=True)
    emit("stage", "Inspect https://example.test/private?x=sensitive\u001b]0;bad\u0007", {})
    output = capsys.readouterr().out
    assert "?x=sensitive" not in output
    assert "\x1b]0;bad" not in output


def test_interactive_workbench_falls_back_when_not_attached_to_a_tty(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", StringIO(""))
    assert run_results_workbench(None, None, {}) is False
    assert "requires a TTY" in capsys.readouterr().out


def test_quiet_summary_is_limited_to_outcome_findings_and_report_location(capsys, tmp_path):
    context = SimpleNamespace(
        intelligence={"target": {"final_url": "https://example.test/?token=hidden"}},
        config=SimpleNamespace(target="https://example.test/?token=hidden"),
        technologies={}, findings=[], verified_findings=[], stop_reason="", scan_id="scan-test",
    )
    cli._summary(SimpleNamespace(context=context, aborted=False),
                 {"html": str(tmp_path / "report.html"), "json": str(tmp_path / "report.json")}, quiet=True)
    output = capsys.readouterr().out
    assert "SCAN COMPLETE" in output and "Confirmed   0" in output
    assert "scan-test" in output
    assert str(tmp_path) not in output
    assert "hidden" not in output
    assert "HTTP requests" not in output and "Testing:" not in output


def test_compact_summary_surfaces_observed_fingerprints_and_rate_controls(capsys):
    context=SimpleNamespace(
        intelligence={"target":{"final_url":"http://127.0.0.1:8765/","hostname":"127.0.0.1"},
                      "dns":{"observed_addresses":["127.0.0.1"]}},
        config=SimpleNamespace(target="http://127.0.0.1:8765/",request_rate=2.0,request_budget=100),
        technologies={"nginx":SimpleNamespace(name="nginx",category="server"),
                      "React":SimpleNamespace(name="React",category="js-framework")},
        findings=[],verified_findings=[],stop_reason="",scan_id="vf-abc123def456",
        stats=SimpleNamespace(requests_sent=4),endpoints={},parameters={},tests=[],hypotheses=[],
        vulnerability_matrix=[],requester=SimpleNamespace(budget=SimpleNamespace(max_requests=100),exchanges=[]),
    )
    cli._summary(SimpleNamespace(context=context,aborted=False),{"json":"reports/report.json"})
    output=capsys.readouterr().out
    for label in ("FINGERPRINTS", "WAF", "Frontend", "Backend", "Scan ID"):
        assert label in output
    assert "React" in output and "nginx" in output and "vf-abc123def456" in output


def test_report_accepts_target_and_uses_latest_matching_scan(monkeypatch, tmp_path):
    class FakeStore:
        def get_report(self, scan_ref):
            return {"scan": {"scan_id": scan_ref}} if scan_ref == "scan-latest" else None

        def list_scans(self):
            return [
                {"scan_id": "scan-latest", "target": "https://example.test/path"},
                {"scan_id": "scan-older", "target": "https://example.test/old"},
                {"scan_id": "other", "target": "https://other.test/"},
            ]

    generated = []
    monkeypatch.setattr(cli, "write_json_report", lambda data, path: generated.append((data, path)) or path)
    args = SimpleNamespace(scan_id="example.test", out=str(tmp_path), format="json")
    assert cli.cmd_report(args, FakeStore()) == 0
    assert generated[0][0]["scan"]["scan_id"] == "scan-latest"
    assert generated[0][1].endswith("scan-latest.json")
