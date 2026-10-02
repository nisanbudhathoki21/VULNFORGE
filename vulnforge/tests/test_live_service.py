import pytest

from vulnforge.engine.live import classify_live_state
from vulnforge.core.authorization import AuthorizationContext
from vulnforge.engine.orchestrator import ScanConfig, run_scan


@pytest.mark.parametrize(("status", "expected"), [
    (200, "LIVE"), (404, "LIVE"), (405, "LIVE"),
    (401, "LIVE_AUTH_REQUIRED"), (403, "LIVE_FORBIDDEN"),
    (429, "LIVE_RATE_LIMITED"), (500, "LIVE_SERVER_ERROR"),
    (599, "LIVE_SERVER_ERROR"), (302, "REDIRECT"), (204, "LIVE"),
])
def test_http_response_states_are_classified_as_live_evidence(status, expected):
    assert classify_live_state(status) == expected


def test_transport_failures_do_not_become_false_endpoint_facts():
    assert classify_live_state(0, "ReadTimeout: request timed out") == "TIMEOUT"
    assert classify_live_state(0, "ConnectError: [Errno 111] Connection refused") == "DEAD"
    assert classify_live_state(0, "RemoteProtocolError: malformed reply") == "UNKNOWN"
    assert classify_live_state(0, "crawl task cancelled") == "UNKNOWN"


def test_followed_redirect_is_still_classified_as_redirect():
    hops = [{"status_code": 302, "destination": "https://example.test/new"}]
    assert classify_live_state(200, redirect_chain=hops) == "REDIRECT"


def test_scan_reports_401_as_live_auth_required(mock_server):
    target=f"{mock_server}/auth-required"
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="passive",allow_private=True,confirmed=True)
    config=ScanConfig(target=target,profile_name="passive",allowed_hosts=["127.0.0.1"],
                      allow_private=True,authorization_confirmed=True)
    result=run_scan(config,auth)
    observation=next(item for item in result.context.live_observations if item["url"].endswith("/auth-required"))
    assert observation["status"]==401
    assert observation["live_state"]=="LIVE_AUTH_REQUIRED"
