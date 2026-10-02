import json

import pytest

from vulnforge.core.store import Store
from vulnforge.engine.research import compare_response_bodies, parse_raw_http_request


def test_json_diff_reports_pointer_changes_and_non_verdict():
    result = compare_response_bodies(
        '{"user":{"id":1,"name":"A"},"items":["x"]}',
        '{"user":{"id":2,"role":"member"},"items":["x","y"]}',
    )
    assert result["format"] == "json"
    assert result["different"] is True
    assert {item["path"] for item in result["changes"]} == {
        "/user/id", "/user/name", "/user/role", "/items/1"
    }
    assert result["truncated"] is False


def test_json_diff_escapes_json_pointer_tokens_and_bounds_changes():
    result = compare_response_bodies('{"a/b~c":1}', '{"a/b~c":2}')
    assert result["changes"][0]["path"] == "/a~1b~0c"
    many_a = json.dumps({str(i): i for i in range(5)})
    many_b = json.dumps({str(i): i + 1 for i in range(5)})
    bounded = compare_response_bodies(many_a, many_b, max_items=2)
    assert len(bounded["changes"]) == 2
    assert bounded["truncated"] is True


def test_non_json_comparison_uses_capped_text_diff():
    result = compare_response_bodies("hello\nworld", "hello\nearth")
    assert result["format"] == "text"
    assert result["different"] is True
    assert any("world" in line or "earth" in line for line in result["unified_diff"])


def test_raw_request_parser_accepts_simple_origin_form():
    method, target, headers, body = parse_raw_http_request(
        "POST /items?q=one HTTP/1.1\r\nHost: lab.example\r\nContent-Type: application/json\r\n\r\n{\"x\":1}"
    )
    assert (method, target, body) == ("POST", "/items?q=one", '{"x":1}')
    assert headers["Host"] == "lab.example"


@pytest.mark.parametrize("raw", [
    "GET https://example.test/ HTTP/1.1\nHost: example.test\n\n",
    "GET //evil.test/ HTTP/1.1\nHost: example.test\n\n",
    "GET / HTTP/1.1\nHost: example.test\nhost: example.test\n\n",
    "POST / HTTP/1.1\nHost: example.test\nContent-Length: 1\n\nx",
    "GET / HTTP/1.1\n folded: yes\n\n",
])
def test_raw_request_parser_rejects_ambiguous_or_transport_managed_input(raw):
    with pytest.raises(ValueError):
        parse_raw_http_request(raw)


def test_exchange_request_and_response_ids_are_distinct_and_provenance_filters_work(tmp_path):
    store = Store(str(tmp_path / "history.db"))
    store.start_scan_record("scan", "http://127.0.0.1/", "lab", 1.0)
    store.record_exchange("scan", {
        "exchange_id": "source", "method": "GET", "url": "http://127.0.0.1/",
        "status": 200, "module": "crawl", "request_body": "", "response_body": "{}",
    })
    store.record_exchange("scan", {
        "exchange_id": "follow-up", "method": "GET", "url": "http://127.0.0.1/about",
        "status": 200, "module": "repeater", "request_body": "", "response_body": "{}",
        "parent_exchange_id": "source",
    })
    source = store.get_exchange("source")
    assert source["request_id"] != source["response_id"]
    assert source["request_id"] == "source:request"
    rows = store.list_exchanges(scan_id="scan", module="repeater", parent_exchange_id="source")
    assert [row["exchange_id"] for row in rows] == ["follow-up"]
    assert rows[0]["request_id"] == "follow-up:request"
    assert store.list_exchanges(scan_id="scan", module="crawl")[0]["response_id"] == "source:response"
