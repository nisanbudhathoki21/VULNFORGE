from vulnforge.core.outcomes import (
    RESULT_STATES,
    class_result_status,
    finding_result_status,
    outcome_counts,
    test_result_status as result_status,
)
from vulnforge.report.json_report import build_report_dict


def test_test_record_states_are_conservative_and_publicly_named():
    assert result_status({"status": "VERIFIED"}) == "CONFIRMED"
    assert result_status({"status": "CANDIDATE"}) == "UNCONFIRMED"
    assert result_status({"status": "KILLED"}) == "KILLED"
    assert result_status({"status": "INCOMPLETE"}) == "UNTESTABLE"
    assert result_status({"status": "BLOCKED"}) == "SKIPPED"
    assert result_status({"status": "NOT_RUN"}) == "SKIPPED"
    assert result_status({"status": "UNSUPPORTED"}) == "UNSUPPORTED"
    assert result_status({"status": "new-unknown-state"}) == "UNTESTABLE"


def test_hardening_observation_is_not_misrepresented_as_unconfirmed_vulnerability():
    assert finding_result_status({
        "status": "REPRODUCED",
        "category": "Security Misconfiguration (header hardening)",
    }) == "INFORMATIONAL"
    assert finding_result_status({
        "status": "CANDIDATE",
        "category": "Cross-site scripting",
    }) == "UNCONFIRMED"


def test_class_states_distinguish_unsupported_skipped_and_untestable():
    assert class_result_status({"supported": False, "status": "UNSUPPORTED"}) == "UNSUPPORTED"
    assert class_result_status({"supported": True, "status": "NOT_SELECTED"}) == "SKIPPED"
    assert class_result_status({"supported": True, "status": "NO_TEST_SURFACE"}) == "UNTESTABLE"
    assert class_result_status({"supported": True, "status": "CONFIRMED", "verified": 1}) == "CONFIRMED"
    assert class_result_status({"supported": True, "status": "INCONCLUSIVE"}) == "UNCONFIRMED"
    assert class_result_status({"supported": True, "status": "OBSERVATION_ONLY", "inconclusive": 1, "reproduced_observations": 1}) == "UNCONFIRMED"


def test_legacy_engine_states_are_additive_in_json_report():
    doc = build_report_dict({
        "findings": [{"title": "proof", "status": "VERIFIED"},
                     {"title": "lead", "status": "CANDIDATE"}],
        "tests": [{"test_id": "t1", "status": "VERIFIED"},
                  {"test_id": "t2", "status": "CANDIDATE"},
                  {"test_id": "t3", "status": "BLOCKED"}],
        "vulnerability_matrix": [
            {"class_id": "sqli", "supported": True, "status": "CONFIRMED", "verified": 1},
            {"class_id": "ssrf", "supported": False, "status": "UNSUPPORTED"},
            {"class_id": "xss", "supported": True, "status": "NO_TEST_SURFACE"},
        ],
        "statistics": {},
    })
    assert [f["result_status"] for f in doc["findings"]] == ["CONFIRMED"]
    assert [f["result_status"] for f in doc["candidates"]] == ["UNCONFIRMED"]
    assert [t["result_status"] for t in doc["tests"]] == ["CONFIRMED", "UNCONFIRMED", "SKIPPED"]
    assert [r["result_status"] for r in doc["vulnerability_matrix"]] == [
        "CONFIRMED", "UNSUPPORTED", "UNTESTABLE"
    ]
    assert tuple(doc["result_summary"]["tests"]) == RESULT_STATES
    assert doc["result_summary"]["tests"]["SKIPPED"] == 1
    assert doc["result_summary"]["classes"]["UNSUPPORTED"] == 1
