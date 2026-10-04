from dataclasses import dataclass

import pytest

from vulnforge.auth.manager import IdentityManager
from vulnforge.auth.models import Identity
from vulnforge.auth.runtime import IdentityRuntime, IdentityRuntimeError


@dataclass
class FakeScanConfig:
    extra_headers: dict
    identity_headers: dict


def make_manager():
    return IdentityManager(
        [
            Identity(
                identity_id="user-a",
                label="User A",
                role="user",
                headers={
                    "Authorization": "Bearer user-a-token",
                    "X-Test-Identity": "user-a",
                },
            ),
            Identity(
                identity_id="admin",
                label="Admin",
                role="admin",
                headers={
                    "Authorization": "Bearer admin-token",
                    "X-Test-Identity": "admin",
                },
            ),
        ]
    )


def test_select_identity():
    runtime = IdentityRuntime(make_manager())

    identity = runtime.select("user-a")

    assert identity.identity_id == "user-a"
    assert runtime.selected_identity_id == "user-a"


def test_unknown_identity_fails_closed():
    runtime = IdentityRuntime(make_manager())

    with pytest.raises(IdentityRuntimeError):
        runtime.select("does-not-exist")


def test_headers_are_defensive_copy():
    runtime = IdentityRuntime(make_manager())
    runtime.select("user-a")

    headers = runtime.headers()
    headers["Authorization"] = "modified"

    assert runtime.headers()["Authorization"] == "Bearer user-a-token"


def test_no_identity_selected_fails():
    runtime = IdentityRuntime(make_manager())

    with pytest.raises(IdentityRuntimeError):
        runtime.headers()


def test_apply_to_config_does_not_mutate_original():
    runtime = IdentityRuntime(make_manager())
    runtime.select("admin")

    config = FakeScanConfig(
        extra_headers={
            "X-Global": "keep-me",
        },
        identity_headers={
            "X-Old-Identity": "old",
        },
    )

    updated = runtime.apply_to_config(config)

    assert config.identity_headers == {
        "X-Old-Identity": "old",
    }

    assert updated.identity_headers == {
        "Authorization": "Bearer admin-token",
        "X-Test-Identity": "admin",
    }

    assert updated.extra_headers == {
        "X-Global": "keep-me",
    }

    assert updated is not config
