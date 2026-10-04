"""
VulnForge — Phase 3 identity manager.

IdentityManager owns the runtime identity matrix used by active security
testing. It does not implement authentication itself.

Authentication remains delegated to the existing login_flow module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional

from .models import Identity


class IdentityManagerError(RuntimeError):
    """Raised when identity management cannot complete safely."""


@dataclass(frozen=True)
class IdentitySpec:
    """
    Configuration for one testing identity.

    Secrets are intentionally kept outside the Identity model's public
    serialization path.
    """

    identity_id: str
    label: str
    actor: Optional[str] = None
    role: Optional[str] = None
    authentication_context_id: Optional[str] = None
    session_id: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, object]] = None


class IdentityManager:
    """
    Runtime registry for security-testing identities.

    The manager deliberately does not perform login. Login is owned by the
    existing engine.login_flow implementation.
    """

    def __init__(self, identities: Optional[Iterable[Identity]] = None) -> None:
        self._identities: Dict[str, Identity] = {}

        for identity in identities or ():
            self.register(identity)

    def register(self, identity: Identity) -> Identity:
        if not isinstance(identity, Identity):
            raise TypeError("identity must be an Identity instance")

        if identity.identity_id in self._identities:
            raise IdentityManagerError(
                f"identity already registered: {identity.identity_id}"
            )

        self._identities[identity.identity_id] = identity
        return identity

    def upsert(self, identity: Identity) -> Identity:
        if not isinstance(identity, Identity):
            raise TypeError("identity must be an Identity instance")

        self._identities[identity.identity_id] = identity
        return identity

    def get(self, identity_id: str) -> Identity:
        key = str(identity_id).strip()

        if not key:
            raise IdentityManagerError("identity_id is required")

        try:
            return self._identities[key]
        except KeyError as exc:
            raise IdentityManagerError(
                f"unknown identity: {key}"
            ) from exc

    def get_optional(self, identity_id: str) -> Optional[Identity]:
        key = str(identity_id).strip()

        if not key:
            return None

        return self._identities.get(key)

    def remove(self, identity_id: str) -> None:
        key = str(identity_id).strip()

        if key:
            self._identities.pop(key, None)

    def all(self) -> tuple[Identity, ...]:
        return tuple(self._identities.values())

    def authenticated(self) -> tuple[Identity, ...]:
        return tuple(
            identity
            for identity in self._identities.values()
            if identity.is_active
        )

    def by_role(self, role: str) -> tuple[Identity, ...]:
        wanted = str(role).strip().lower()

        return tuple(
            identity
            for identity in self._identities.values()
            if str(identity.role or "").strip().lower() == wanted
        )

    def headers_for(self, identity_id: str) -> Dict[str, str]:
        """
        Return a copy of the runtime headers for an identity.

        Never return the manager's internal dictionary directly.
        """

        identity = self.get(identity_id)
        return dict(identity.headers)

    def set_headers(
        self,
        identity_id: str,
        headers: Dict[str, str],
    ) -> Identity:
        identity = self.get(identity_id)

        if not isinstance(headers, dict):
            raise TypeError("headers must be a dictionary")

        identity.headers = {
            str(key): str(value)
            for key, value in headers.items()
        }

        return identity

    def mark_authenticated(
        self,
        identity_id: str,
        *,
        authentication_context_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Identity:
        identity = self.get(identity_id)

        identity.mark_authenticated(
            authentication_context_id=authentication_context_id,
            session_id=session_id,
        )

        return identity

    def mark_failed(self, identity_id: str) -> Identity:
        identity = self.get(identity_id)
        identity.mark_failed()
        return identity

    def mark_expired(self, identity_id: str) -> Identity:
        identity = self.get(identity_id)
        identity.mark_expired()
        return identity

    def disable(self, identity_id: str) -> Identity:
        identity = self.get(identity_id)
        identity.disable()
        return identity

    def public_dict(self) -> Dict[str, object]:
        return {
            identity.identity_id: identity.public_dict()
            for identity in self._identities.values()
        }

    def labels(self) -> tuple[str, ...]:
        return tuple(
            identity.label
            for identity in self._identities.values()
        )

    def __len__(self) -> int:
        return len(self._identities)
