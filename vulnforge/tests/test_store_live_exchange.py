import json

from vulnforge.core.store import Store


def test_exchange_is_visible_during_scan_and_secret_values_are_redacted(tmp_path):
    store = Store(str(tmp_path / "scan-history.db"))
    store.start_scan_record("scan-live", "https://safe.example/", "standard", 1.0)
    store.record_exchange("scan-live", {
        "exchange_id": "exchange-live",
        "method": "GET",
        "url": "https://safe.example/items?token=top-secret",
        "request_headers": {
            "Authorization": "Bearer header-secret",
            "X-Research-Key": "custom-secret",
        },
        "request_body": "",
        "status": 200,
        "response_headers": {"content-type": "application/json"},
        "response_body": json.dumps({"api_key": "body-secret", "ok": True}),
        "duration_ms": 3.2,
        "module": "crawler",
        "error": None,
        "redirect_chain": [],
    }, sensitive_headers={"X-Research-Key"})

    page = store.list_exchanges(scan_id="scan-live", limit=20)
    assert [item["exchange_id"] for item in page] == ["exchange-live"]
    detail = store.get_exchange("exchange-live")
    assert detail["request_headers"]["Authorization"] == "[REDACTED]"
    assert detail["request_headers"]["X-Research-Key"] == "[REDACTED]"
    serialized = json.dumps(detail)
    for secret in ("top-secret", "header-secret", "custom-secret", "body-secret"):
        assert secret not in serialized
