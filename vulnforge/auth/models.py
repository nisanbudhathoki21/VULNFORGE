"""
VulnForge — Phase 3 identity models.

An Identity represents a security-testing actor, not merely a set of HTTP
headers. Examples:

    anonymous
    user-a
    user-b
    administrator

Credentials/secrets must never be included in the serialized public form.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


VALID_STATES = {
    "configured",
    "authenticated",
    "expired",
    "failed",
    "disabled",
}


@dataclass
class Identity:
    """
    A first-class security-testing identity.

    The identity is deliberately independent from a particular endpoint.
    This allows the same actor/session to be used across many tests.
    """

    identity_id: str
    label: str
    actor: Optional[str] = None
    role: Optional[str] = None

    authentication_context_id: Optional[str] = None
    session_id: Optional[str] = None

    authenticated: bool = False
    state: str = "configured"

    # Runtime-only request material. Never serialize raw secrets.
    headers: Dict[str, str] = field(default_factory=dict)

    metadata: Dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.identity_id = str(self.identity_id).strip()
        self.label = str(self.label).strip()

        if not self.identity_id:
            raise ValueError("identity_id is required")

        if not self.label:
            raise ValueError("identity label is required")

        self.state = str(self.state).lower().strip()

        if self.state not in VALID_STATES:
            raise ValueError(
                f"invalid identity state: {self.state!r}"
            )

        if self.authenticated and self.state == "configured":
            self.state = "authenticated"

    @property
    def is_active(self) -> bool:
        return (
            self.state == "authenticated"
            and self.authenticated
        )

    def redacted_headers(self) -> Dict[str, str]:
        """
        Return headers suitable for logs/reports.

        The actual redaction implementation remains centralized in the
        existing redaction module.
        """
        from ..core.redaction import redact_headers

        return redact_headers(self.headers)

    def public_dict(self) -> Dict[str, object]:
        """
        Safe representation for dashboards, reports and persistence.
        """
        return {
            "identity_id": self.identity_id,
            "label": self.label,
            "actor": self.actor,
            "role": self.role,
            "authentication_context_id": self.authentication_context_id,
            "session_id": self.session_id,
            "authenticated": self.authenticated,
            "state": self.state,
            "headers": self.redacted_headers(),
            "metadata": dict(self.metadata),
        }

    def mark_authenticated(
        self,
        *,
        authentication_context_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> None:
        if authentication_context_id is not None:
            self.authentication_context_id = authentication_context_id

        if session_id is not None:
            self.session_id = session_id

        self.authenticated = True
        self.state = "authenticated"

    def mark_failed(self) -> None:
        self.authenticated = False
        self.state = "failed"

    def mark_expired(self) -> None:
        self.authenticated = False
        self.state = "expired"

    def disable(self) -> None:
        self.authenticated = False
        self.state = "disabled"
