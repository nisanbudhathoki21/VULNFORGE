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

def test_p31f_exchange_authentication_context_persists_to_requests(tmp_path):
    """P3.1f: exchange authentication context survives DB materialization."""

    import sqlite3

    from vulnforge.core.models import HttpExchange
    from vulnforge.core.store import Store

    database = tmp_path / "p31f.db"

    # Store() is the application's real database bootstrap path.
    store = Store(str(database))

    exchange = HttpExchange(
        method="GET",
        url="https://example.test/api/records/123",
        request_headers={
            "X-Test-Identity": "owner",
        },
        status=200,
        response_headers={
            "Content-Type": "application/json",
        },
        response_body='{"id":"123","name":"test"}',
        module="p31f-test",
        authentication_context_id="auth-context-owner",
    )

    doc = exchange.to_dict()

    assert doc["authentication_context_id"] == "auth-context-owner"

    # Use the same normalized relational persistence function used by
    # production storage, but through the application's real Store-created DB.
    with sqlite3.connect(store.path) as con:
        from vulnforge.core import relational

        relational.materialize_exchange(
            con,
            "p31f-scan",
            doc,
            project_id="project-default",
            target_id="",
        )

        con.commit()

        row = con.execute(
            """
            SELECT authentication_context_id
            FROM requests
            WHERE request_id = ?
            """,
            (exchange.request_id,),
        ).fetchone()

    assert row is not None, (
        "P3.1f failed: materialize_exchange() did not create "
        "the normalized requests record"
    )

    assert row[0] == "auth-context-owner", (
        "P3.1f failed: authentication context was not preserved. "
        f"Expected 'auth-context-owner', got {row[0]!r}"
    )


def test_p31g_identity_authentication_context_session_consistency(tmp_path):
    """P3.1g: identity, authentication context, and session IDs remain consistent."""

    import sqlite3

    from vulnforge.auth.manager import IdentityManager
    from vulnforge.auth.models import Identity
    from vulnforge.core.store import Store

    database = tmp_path / "p31g.db"
    store = Store(str(database))

    identity_id = "owner"
    authentication_context_id = "auth-context-owner"
    session_id = "session-owner"

    identity = Identity(
        identity_id=identity_id,
        label="owner",
        actor="alice",
        role="owner",
        authentication_context_id=authentication_context_id,
        session_id=session_id,
        authenticated=True,
        state="authenticated",
        headers={
            "X-Test-Identity": "owner",
        },
    )

    manager = IdentityManager()
    manager.register(identity)

    registered = manager.get(identity_id)

    assert registered.authentication_context_id == authentication_context_id
    assert registered.session_id == session_id
    assert registered.authenticated is True
    assert registered.state == "authenticated"

    # Materialize the same identity context into the application's
    # normalized authentication/session tables.
    with sqlite3.connect(store.path) as con:
        con.execute(
            """
            INSERT INTO authentication_contexts(
                authentication_context_id,
                scan_id,
                label,
                actor,
                redacted_headers_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                authentication_context_id,
                "p31g-scan",
                registered.label,
                registered.actor or registered.label,
                "{}",
                0.0,
            ),
        )

        con.execute(
            """
            INSERT INTO sessions(
                session_id,
                authentication_context_id,
                label,
                state,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session_id,
                authentication_context_id,
                registered.label,
                registered.state,
                0.0,
            ),
        )

        con.commit()

        context_row = con.execute(
            """
            SELECT authentication_context_id, label, actor
            FROM authentication_contexts
            WHERE authentication_context_id = ?
            """,
            (authentication_context_id,),
        ).fetchone()

        session_row = con.execute(
            """
            SELECT session_id, authentication_context_id, label, state
            FROM sessions
            WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()

    assert context_row is not None, (
        "P3.1g failed: authentication context was not persisted"
    )

    assert context_row == (
        authentication_context_id,
        "owner",
        "alice",
    )

    assert session_row is not None, (
        "P3.1g failed: session was not persisted"
    )

    assert session_row == (
        session_id,
        authentication_context_id,
        "owner",
        "authenticated",
    )

    # Most important invariant:
    # Identity -> authentication context -> session must describe
    # one consistent authentication boundary.
    assert registered.authentication_context_id == session_row[1]
    assert registered.session_id == session_row[0]

