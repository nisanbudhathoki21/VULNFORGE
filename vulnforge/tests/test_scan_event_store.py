import json

from vulnforge.core.store import Store


def test_events_are_scan_scoped_redacted_and_replayable_after_reopen(tmp_path):
    path=tmp_path/"events.db"
    store=Store(str(path))
    store.start_scan_record("vf-event-123456","https://demo.example/","passive",10.0)
    first=store.record_event("vf-event-123456",{
        "kind":"http-exchange","message":"GET exchange token=message-secret",
        "timestamp":11.0,"data":{"url":"https://demo.example/items?q=private&token=query-secret",
                            "headers":{"Authorization":"Bearer header-secret"},
                            "request_body":{"api_key":"json-secret"}},
    })
    second=store.record_event("vf-event-123456",{
        "kind":"stage-done","message":"Discovery completed","timestamp":12.0,
        "data":{"stage":"recon","observed_hosts":2},
    })

    assert first["event_id"] < second["event_id"]
    assert first["data"]["url"]=="https://demo.example/items?q=%5BREDACTED%5D&token=[REDACTED]"
    serialized=json.dumps(first)
    for secret in ("message-secret","query-secret","header-secret","json-secret"):
        assert secret not in serialized

    reopened=Store(str(path))
    assert reopened.list_scan_events("vf-event-123456")==[first,second]
    assert reopened.list_scan_events("vf-event-123456",after_event_id=first["event_id"])==[second]
    assert reopened.list_scan_events("different-scan")==[]
    bundle=reopened.get_scan_bundle("vf-event-123456")
    assert [event["event_id"] for event in bundle["events"]]==[first["event_id"],second["event_id"]]


def test_oversized_event_payload_is_bounded_without_persisting_body(tmp_path):
    store=Store(str(tmp_path/"bounded-events.db"))
    store.start_scan_record("vf-bounded-123456","https://demo.example/","passive",1.0)
    event=store.record_event("vf-bounded-123456",{
        "kind":"large-observation","message":"bounded","timestamp":2.0,
        "data":{"content":"x"*(300*1024)},
    })
    assert event["data"]=={"truncated":True,"original_bytes":300*1024+14}
    rows=store.list_scan_events("vf-bounded-123456")
    assert rows[0]["data"]==event["data"]
