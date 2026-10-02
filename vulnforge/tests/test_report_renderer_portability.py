from vulnforge.report.renderers import write_pdf_report


def test_pdf_report_writer_is_dependency_free(tmp_path):
    report = {
        "scan": {
            "scan_id": "vf-pdf-smoke",
            "target": "https://example.test/",
            "started_at": 1.0,
            "duration_s": 0.0,
            "status": "completed",
            "test_profile": "passive",
        },
        "statistics": {
            "requests_sent": 0,
            "endpoints_discovered": 0,
            "parameters_discovered": 0,
        },
        "findings": [],
        "candidates": [],
        "technologies": [],
        "endpoints": [],
        "parameters": [],
        "vulnerability_matrix": [],
        "tests": [],
        "hypotheses": [],
        "phases": [],
        "coverage": [],
    }
    path = tmp_path / "report.pdf"
    write_pdf_report(report, str(path))
    assert path.read_bytes().startswith(b"%PDF-1.4")
