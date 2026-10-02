"""Scope gate tests — the most safety-critical module (spec §3)."""
import pytest
from vulnforge.core.authorization import AuthorizationContext


def make(**kw):
    import ipaddress
    kw.setdefault("allowed_hosts", ["example.com"])
    kw.setdefault("confirmed", True)
    auth=AuthorizationContext(**kw)
    real_resolve=auth._resolve
    def deterministic_resolve(host):
        if host.endswith("example.com"):
            return [ipaddress.ip_address("93.184.216.34")]
        return real_resolve(host)
    auth._resolve=deterministic_resolve
    return auth


def test_exact_host_allowed():
    ok, _ = make().check("https://example.com/page")
    assert ok


def test_idna_host_rules_are_canonicalized(monkeypatch):
    import ipaddress
    auth=make(allowed_hosts=["bücher.example"])
    monkeypatch.setattr(auth,"_resolve",lambda _host:[ipaddress.ip_address("93.184.216.34")])
    assert auth.describe()["allowed_hosts"]==["xn--bcher-kva.example"]
    assert auth.check("https://bücher.example/")[0]


def test_subdomain_denied_without_wildcard():
    ok, reason = make().check("https://api.example.com/")
    assert not ok and "outside allowed_hosts" in reason


def test_wildcard_covers_subdomain_and_parent(monkeypatch):
    import ipaddress
    auth = make(allowed_hosts=["*.example.com"])
    monkeypatch.setattr(auth,"_resolve",lambda _host:[ipaddress.ip_address("93.184.216.34")])
    assert auth.check("https://api.example.com/x")[0]
    assert auth.check("https://example.com/x")[0]


def test_other_host_denied():
    ok, _ = make().check("https://evil.com/")
    assert not ok


def test_scheme_rejected():
    ok, reason = make().check("file:///etc/passwd")
    assert not ok


def test_excluded_path_blocks():
    auth = make(excluded_paths=[r"/logout", r"/admin/delete.*"])
    assert not auth.check("https://example.com/logout")[0]
    assert not auth.check("https://example.com/admin/delete/1")[0]
    assert auth.check("https://example.com/admin/view")[0]


def test_excluded_params():
    auth = make(excluded_params=["csrf_token"])
    assert auth.param_excluded("CSRF_TOKEN")
    assert not auth.param_excluded("q")


def test_port_restrictions():
    auth = make(allowed_ports=[443])
    assert not auth.check("http://example.com:8080/x")[0]
    assert not auth.check("http://example.com:0/x")[0]
    assert auth.check("https://example.com/x")[0]


def test_prefix_restrictions():
    auth = make(allowed_prefixes=["https://example.com/api"])
    assert auth.check("https://example.com/api")[0]
    assert auth.check("https://example.com/api/users")[0]
    assert not auth.check("https://example.com/api-evil")[0]
    assert not auth.check("http://example.com/api/users")[0]
    assert not auth.check("https://example.com:8443/api/users")[0]
    assert not auth.check("https://example.com/admin")[0]


def test_redirect_destination_validated():
    auth = make()
    assert auth.check_redirect("https://example.com/r", "https://example.com/ok")[0]
    ok, _ = auth.check_redirect("https://example.com/r", "https://evil.com/")
    assert not ok


def test_private_target_requires_opt_in(mock_server):
    host_url = mock_server
    auth = make(allowed_hosts=["127.0.0.1"], allow_private=False, profile_name="standard")
    assert not auth.check(host_url + "/")[0]
    auth2 = make(allowed_hosts=["127.0.0.1"], allow_private=True, profile_name="standard")
    assert auth2.check(host_url + "/")[0]
    auth3 = make(allowed_hosts=["127.0.0.1"], profile_name="lab")
    assert auth3.check(host_url + "/")[0]


def test_lab_mode_is_loopback_only_at_the_central_gate():
    auth=make(allowed_hosts=["example.com"],profile_name="lab",allow_private=True)
    allowed,reason=auth.check("https://example.com/")
    assert not allowed and "loopback targets" in reason


def test_lab_localhost_alias_must_resolve_only_to_loopback(monkeypatch):
    import ipaddress
    auth=make(allowed_hosts=["localhost"],profile_name="lab",allow_private=True)
    monkeypatch.setattr(auth,"_resolve",lambda _host:[ipaddress.ip_address("127.0.0.1"),ipaddress.ip_address("93.184.216.34")])
    allowed,reason=auth.check("http://localhost/")
    assert not allowed and "loopback targets" in reason


def test_discovered_hosts_never_auto_in_scope():
    auth = make()
    assert not auth.check("https://subdomain-i-just-found.example.org/")[0]


def test_audit_log_records_denials():
    auth = make()
    auth.check("https://evil.com/")
    auth.check("https://example.com/")
    actions = [e["action"] for e in auth.audit_dump()]
    assert "scope_deny" in actions
    assert auth.stats["denied"] == 1 and auth.stats["allowed"] == 1


def test_confirmation_required():
    auth = AuthorizationContext(allowed_hosts=["example.com"], confirmed=False)
    with pytest.raises(PermissionError):
        auth.require_confirmation()


def test_stop_event():
    auth = make()
    assert not auth.stopped
    auth.stop("unit test")
    assert auth.stopped


def test_scope_rejects_embedded_credentials_and_unsafe_default_methods():
    auth = make()
    ok, reason = auth.check("https://user:secret@example.com/private")
    assert not ok and "credentials" in reason
    ok, reason = auth.check("https://example.com/", method="POST")
    assert not ok and "allowed_methods" in reason
    assert auth.check("https://example.com/", method="GET")[0]


def test_explicit_method_allowlist_and_expiry_are_enforced():
    import time
    auth = make(allowed_methods=["GET", "POST"], profile_name="controlled-active", expires_at=time.time() + 60)
    assert auth.check("https://example.com/", method="POST")[0]
    assert not auth.check("https://example.com/", method="DELETE")[0]
    expired = make(expires_at=time.time() - 1)
    assert not expired.check("https://example.com/")[0]
    future = make(not_before=time.time() + 60)
    assert not future.check("https://example.com/")[0]


def test_excluded_hosts_and_invalid_scope_rules_fail_closed(monkeypatch):
    import ipaddress
    auth = make(allowed_hosts=["*.example.com"], excluded_hosts=["admin.example.com"])
    monkeypatch.setattr(auth,"_resolve",lambda _host:[ipaddress.ip_address("93.184.216.34")])
    assert not auth.check("https://admin.example.com/")[0]
    assert auth.check("https://api.example.com/")[0]
    with pytest.raises(ValueError, match="too broad"):
        make(allowed_hosts=["*.com"])
    with pytest.raises(ValueError, match="between 1 and 65535"):
        make(allowed_ports=[70000])
    with pytest.raises(ValueError, match="timezone-aware"):
        make(not_before="2026-09-30T10:00:00")
    with pytest.raises(ValueError, match="state-changing methods require"):
        make(allowed_methods=["GET", "POST"])


def test_mixed_public_private_dns_answer_is_treated_as_private(monkeypatch):
    import ipaddress
    auth = make(allowed_hosts=["mixed.example"])
    monkeypatch.setattr(auth, "_resolve", lambda _host: [
        ipaddress.ip_address("93.184.216.34"), ipaddress.ip_address("10.1.2.3")])
    assert auth.is_private_target("mixed.example")


def test_unresolvable_host_fails_closed(monkeypatch):
    auth = make(allowed_hosts=["unresolved.example"])
    monkeypatch.setattr(auth, "_resolve", lambda _host: [])
    allowed,reason=auth.check("https://unresolved.example/")
    assert not allowed and "cannot be established" in reason


def test_allowed_scope_decisions_are_audited():
    auth = make()
    assert auth.check("https://example.com/")[0]
    assert any(entry["action"] == "scope_allow" for entry in auth.audit_dump())
