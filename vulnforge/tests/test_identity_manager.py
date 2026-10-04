from vulnforge.auth.manager import IdentityManager, IdentityManagerError
from vulnforge.auth.models import Identity


def test_manager_registers_and_retrieves_identity():
    manager = IdentityManager()

    identity = Identity(
        identity_id="user-a",
        label="User A",
        role="user",
    )

    manager.register(identity)

    assert len(manager) == 1
    assert manager.get("user-a") is identity
    assert manager.labels() == ("User A",)


def test_manager_rejects_duplicate_identity():
    manager = IdentityManager()

    manager.register(
        Identity(identity_id="user-a", label="User A")
    )

    try:
        manager.register(
            Identity(identity_id="user-a", label="User A duplicate")
        )
        assert False, "duplicate identity should be rejected"
    except IdentityManagerError:
        pass


def test_manager_tracks_authenticated_identities():
    manager = IdentityManager(
        [
            Identity(identity_id="user-a", label="User A", role="user"),
            Identity(identity_id="admin", label="Admin", role="admin"),
        ]
    )

    manager.mark_authenticated("user-a")

    assert len(manager.authenticated()) == 1
    assert manager.authenticated()[0].identity_id == "user-a"


def test_manager_filters_by_role():
    manager = IdentityManager(
        [
            Identity(identity_id="user-a", label="User A", role="user"),
            Identity(identity_id="user-b", label="User B", role="user"),
            Identity(identity_id="admin", label="Admin", role="admin"),
        ]
    )

    users = manager.by_role("user")
    admins = manager.by_role("admin")

    assert {identity.identity_id for identity in users} == {
        "user-a",
        "user-b",
    }
    assert [identity.identity_id for identity in admins] == ["admin"]


def test_manager_returns_copy_of_headers():
    identity = Identity(
        identity_id="user-a",
        label="User A",
        headers={"Authorization": "Bearer secret"},
    )

    manager = IdentityManager([identity])

    headers = manager.headers_for("user-a")
    headers["Authorization"] = "changed"

    assert identity.headers["Authorization"] == "Bearer secret"


def test_manager_public_dict_redacts_identity_headers():
    identity = Identity(
        identity_id="user-a",
        label="User A",
        headers={
            "Authorization": "Bearer secret-value",
            "X-Test": "safe",
        },
    )

    manager = IdentityManager([identity])

    public = manager.public_dict()

    assert "secret-value" not in str(public)
    assert public["user-a"]["headers"]["X-Test"] == "safe"
