"""
VulnForge — plugin framework (spec §51).

Every detector is a plugin implementing DetectorPlugin. Plugins are
auto-discovered from vulnforge.plugins.* and never modify the core engine.

Design rules:
• passive plugins analyze already-collected data; they send NO requests
• active plugins declare check_class; they only run when the scan profile
  lists that class (ARCHITECTURE §10) and must use the scoped Requester
• a plugin producing a VERIFIED finding must also fill evidence +
  manual_verification (else the orchestrator downgrades it to 'likely')
• plugins receive a read-only view of scope — they cannot widen it
"""
from __future__ import annotations

import abc
from typing import Any, Dict, List

from ..core.models import Finding, ScanContext


class DetectorPlugin(abc.ABC):
    # --- metadata (spec §51) -------------------------------------------
    id: str = "vf2-unnamed"
    name: str = "Unnamed detector"
    category: str = "misc"
    severity: str = "info"          # ceiling suggestion; risk engine may lower
    confidence_base: float = 0.5
    cwe: str = ""
    owasp: str = ""
    description: str = ""
    remediation: str = ""
    references: List[str] = []
    passive: bool = True            # passive == no new requests
    check_class: str = ""           # for active plugins: profile gate key
    prerequisites: List[str] = []   # e.g. ["endpoints>=1"], advisory

    # --- behavior -------------------------------------------------------
    @abc.abstractmethod
    def run(self, ctx: ScanContext) -> List[Finding]:
        """Analyze the scan context and return findings (may be empty)."""
        raise NotImplementedError


_REGISTRY: List[type] = []


def register(cls: type) -> type:
    if cls not in _REGISTRY:
        _REGISTRY.append(cls)
    return cls


def registered_plugins() -> List[DetectorPlugin]:
    return [cls() for cls in _REGISTRY]


def load_builtin_plugins() -> List[DetectorPlugin]:
    """Import all bundled plugin modules so their @register decorators run."""
    import importlib
    import pkgutil
    from .. import plugins as pkg

    for finder, name, ispkg in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
        if name.rsplit(".", 1)[-1].startswith("_"):
            continue
        try:
            importlib.import_module(name)
        except Exception:
            # A broken optional plugin must not break the platform.
            continue
    return registered_plugins()
