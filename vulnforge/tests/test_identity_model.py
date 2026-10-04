from vulnforge.auth.models import Identity


def test_identity_defaults_to_configured():
    identity = Identity(
        identity_id="user-a",
        label="User A",
    )

    assert identity.state == "configured"
    assert identity.authenticated is False
    assert identity.is_active is False


def test_identity_can_be_authenticated():
    identity = Identity(
        identity_id="user-a",
        label="User A",
        role="user",
    )

    identity.mark_authenticated(
        authentication_context_id="auth-123",
        session_id="session-123",
    )

    assert identity.authenticated is True
    assert identity.state == "authenticated"
    assert identity.is_active is True
    assert identity.authentication_context_id == "auth-123"
    assert identity.session_id == "session-123"


def test_identity_public_dict_redacts_headers():
    identity = Identity(
        identity_id="user-a",
        label="User A",
        headers={
            "Authorization": "Bearer secret-value",
            "Cookie": "session=secret-value",
            "X-Test": "safe",
        },
    )

    public = identity.public_dict()

    assert "secret-value" not in str(public)
    assert public["headers"]["X-Test"] == "safe"


def test_identity_state_transitions():
    identity = Identity(
        identity_id="user-a",
        label="User A",
    )

    identity.mark_authenticated()
    assert identity.is_active

    identity.mark_expired()
    assert not identity.is_active

    identity.mark_failed()
    assert identity.state == "failed"

    identity.disable()
    assert identity.state == "disabled"
