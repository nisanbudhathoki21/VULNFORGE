import json

from vulnforge.core.models import ScanContext
from vulnforge.core.store import Store


def test_technology_observations_are_counted_with_bounded_samples():
    context = ScanContext("scan-tech", None, None)
    for index in range(50):
        context.add_technology("Example CMS", "cms", "MEDIUM", f"marker on host/page-{index}")

    technology = context.technologies["Example CMS"]
    assert technology.observations_count == 50
    assert len(technology.signals) == 6
    assert technology.signals[0] == "marker on host/page-0"
    assert technology.to_dict()["observations_count"] == 50


def test_technology_listing_reads_old_lists_and_new_bounded_envelopes(tmp_path):
    store = Store(str(tmp_path / "technology-history.db"))
    store.start_scan_record("scan-tech", "https://example.test/", "standard", 1.0)
    with store._conn() as con:
        con.execute(
            "INSERT INTO technologies(scan_id,name,category,confidence,signals) VALUES(?,?,?,?,?)",
            ("scan-tech", "Old record", "server", "LOW", json.dumps([f"legacy signal {index}" for index in range(12)])),
        )
        con.execute(
            "INSERT INTO technologies(scan_id,name,category,confidence,signals) VALUES(?,?,?,?,?)",
            ("scan-tech", "New record", "cms", "MEDIUM", json.dumps({"items": ["sample"], "observations_count": 17})),
        )

    rows = {row["name"]: row for row in store.list_technologies()}
    assert len(rows["Old record"]["signals"]) == 8
    assert rows["Old record"]["signals"][0] == "legacy signal 0"
    assert rows["Old record"]["observations_count"] == 12
    assert rows["Old record"]["evidence_samples_omitted"] == 4
    assert rows["New record"]["signals"] == ["sample"]
    assert rows["New record"]["observations_count"] == 17
