"""
VulnForge — Phase 3 identity runtime bridge.

Connects a selected Identity to runtime request configuration without
performing authentication or bypassing authorization controls.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Optional

from .manager import IdentityManager, IdentityManagerError
from .models import Identity


class IdentityRuntimeError(RuntimeError):
    """Raised when an identity cannot be applied to runtime configuration."""


class IdentityRuntime:
    """
    Runtime selector for authenticated security-testing identities.

    Responsibilities:
    - select a registered identity
    - expose a defensive copy of its headers
    - apply those headers to ScanConfig.identity_headers

    Non-responsibilities:
    - authentication/login
    - authorization/scope decisions
    - HTTP requests
    - persistence
    """

    def __init__(self, manager: IdentityManager) -> None:
        if not isinstance(manager, IdentityManager):
            raise TypeError("manager must be an IdentityManager")

        self.manager = manager
        self._selected_identity_id: Optional[str] = None

    @property
    def selected_identity_id(self) -> Optional[str]:
        return self._selected_identity_id

    def select(self, identity_id: str) -> Identity:
        try:
            identity = self.manager.get(identity_id)
        except IdentityManagerError as exc:
            raise IdentityRuntimeError(str(exc)) from exc

        self._selected_identity_id = identity.identity_id
        return identity

    def selected(self) -> Identity:
        if self._selected_identity_id is None:
            raise IdentityRuntimeError("no identity selected")

        try:
            return self.manager.get(self._selected_identity_id)
        except IdentityManagerError as exc:
            raise IdentityRuntimeError(str(exc)) from exc

    def headers(self) -> dict[str, str]:
        """
        Return a defensive copy of the selected identity's headers.
        """
        return dict(self.selected().headers)

    def apply_to_config(self, config):
        """
        Return a copy of ScanConfig using the selected identity.

        The original config is never mutated.

        Global extra_headers remain untouched. Identity-specific headers are
        placed exclusively in config.identity_headers.
        """
        identity_headers = self.headers()

        try:
            return replace(
                config,
                identity_headers=identity_headers,
            )
        except TypeError as exc:
            raise IdentityRuntimeError(
                "config must be a dataclass compatible with dataclasses.replace"
            ) from exc
