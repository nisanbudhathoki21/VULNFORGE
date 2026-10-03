"""Central attack-strategy registry for VulnForge.

Strategies describe HOW an authorized security property may be tested.
They do not execute requests and they never create findings.

Execution remains owned by the existing orchestrator/requester/verifier
pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple


@dataclass(frozen=True)
class AttackStrategy:
    strategy_id: str
    name: str
    vulnerability_classes: Tuple[str, ...]
    surfaces: Tuple[str, ...] = ()
    prerequisites: Tuple[str, ...] = ()
    mutation_types: Tuple[str, ...] = ()
    control_requirements: Tuple[str, ...] = ()
    verification_contract: Tuple[str, ...] = ()
    reproduction_required: bool = True
    impact_required: bool = True
    active: bool = True
    risk: str = "SAFE_ACTIVE"
    request_cost: int = 1
    description: str = ""

    def applies_to(
        self,
        *,
        vulnerability_class: str,
        surface: str | None = None,
        observed_capabilities: Iterable[str] = (),
        active_requested: bool = False,
    ) -> bool:
        if vulnerability_class not in self.vulnerability_classes:
            return False

        if surface and self.surfaces and surface not in self.surfaces:
            return False

        if self.active and not active_requested:
            return False

        available = {str(x).lower() for x in observed_capabilities}
        required = {str(x).lower() for x in self.prerequisites}

        return required.issubset(available)


_STRATEGIES: Tuple[AttackStrategy, ...] = (
    AttackStrategy(
        strategy_id="authz.object_boundary",
        name="Object authorization boundary",
        vulnerability_classes=("bola", "authorization_bypass", "cross_tenant_access"),
        surfaces=("rest", "web", "api"),
        prerequisites=(
            "two researcher-supplied identities",
            "owner invariant",
            "sensitive fields",
        ),
        mutation_types=("object_identity", "resource_identifier"),
        control_requirements=(
            "owner baseline",
            "non-owner control",
            "repeat reproduction",
        ),
        verification_contract=(
            "owner identity separation",
            "resource ownership",
            "sensitive field comparison",
            "authorization decision",
        ),
        risk="SAFE_ACTIVE",
        request_cost=3,
        description="Compare owner and non-owner access to an object-bound resource.",
    ),
    AttackStrategy(
        strategy_id="authz.function_boundary",
        name="Function authorization boundary",
        vulnerability_classes=("bfla", "privilege_escalation"),
        surfaces=("rest", "web", "api"),
        prerequisites=("two researcher-supplied identities", "known protected function"),
        mutation_types=("identity", "method", "route"),
        control_requirements=("authorized-role baseline", "lower-role control"),
        verification_contract=("function access decision", "role separation"),
        risk="SAFE_ACTIVE",
        request_cost=3,
        description="Compare access to a protected function across authorized roles.",
    ),
    AttackStrategy(
        strategy_id="authz.tenant_boundary",
        name="Tenant isolation boundary",
        vulnerability_classes=("cross_tenant_access",),
        surfaces=("rest", "api"),
        prerequisites=("two researcher-supplied tenant identities", "tenant-bound object"),
        mutation_types=("tenant_identifier", "object_identifier", "identity"),
        control_requirements=("tenant-A baseline", "tenant-B control"),
        verification_contract=("tenant separation", "resource ownership"),
        risk="SAFE_ACTIVE",
        request_cost=4,
        description="Test whether a tenant-bound resource crosses an identity/tenant boundary.",
    ),
    AttackStrategy(
        strategy_id="api.parameter_boundary",
        name="API parameter authorization",
        vulnerability_classes=("api_authorization", "mass_assignment"),
        surfaces=("api", "rest"),
        prerequisites=("observed API endpoint", "observed request parameters"),
        mutation_types=("parameter", "property", "method"),
        control_requirements=("original request", "benign control"),
        verification_contract=("security-property differential",),
        risk="SAFE_ACTIVE",
        request_cost=4,
        description="Bounded mutation of API parameters or writable properties.",
    ),
    AttackStrategy(
        strategy_id="injection.sql_differential",
        name="SQL injection differential",
        vulnerability_classes=("sqli",),
        surfaces=("rest", "web", "api"),
        prerequisites=("observed non-sensitive query value",),
        mutation_types=("query_parameter",),
        control_requirements=("benign control", "repeatable baseline"),
        verification_contract=("repeatable database-error signature",),
        risk="SAFE_ACTIVE",
        request_cost=4,
        description="Use bounded differential input testing against an eligible parameter.",
    ),
    AttackStrategy(
        strategy_id="injection.nosql_differential",
        name="NoSQL injection differential",
        vulnerability_classes=("nosqli",),
        surfaces=("rest", "api"),
        prerequisites=("observed structured input",),
        mutation_types=("json_parameter", "query_parameter"),
        control_requirements=("benign control", "baseline response"),
        verification_contract=("repeatable semantic differential",),
        risk="SAFE_ACTIVE",
        request_cost=4,
        description="Bounded differential testing of structured query inputs.",
    ),
    AttackStrategy(
        strategy_id="injection.command_boundary",
        name="Command injection boundary",
        vulnerability_classes=("command_injection",),
        surfaces=("rest", "web", "api"),
        prerequisites=("authorized command-processing surface",),
        mutation_types=("parameter",),
        control_requirements=("benign control", "non-destructive marker"),
        verification_contract=("controlled execution marker",),
        risk="HIGH_ACTIVE",
        request_cost=5,
        description="Controlled proof of command interpretation without destructive commands.",
    ),
    AttackStrategy(
        strategy_id="server.ssrF_boundary",
        name="SSRF boundary",
        vulnerability_classes=("ssrf",),
        surfaces=("rest", "web", "api"),
        prerequisites=("observed server-side URL consumer",),
        mutation_types=("url", "host", "redirect"),
        control_requirements=("same-origin control", "reserved test destination"),
        verification_contract=("server-side request evidence",),
        risk="HIGH_ACTIVE",
        request_cost=5,
        description="Bounded testing of server-side URL fetching using an authorized test destination.",
    ),
    AttackStrategy(
        strategy_id="web.xss_reflection",
        name="Reflected XSS differential",
        vulnerability_classes=("xss",),
        surfaces=("web", "rest"),
        prerequisites=("observed reflected input"),
        mutation_types=("query_parameter", "form_parameter"),
        control_requirements=("benign marker", "encoded control"),
        verification_contract=("context-aware reflection", "browser execution proof"),
        risk="SAFE_ACTIVE",
        request_cost=4,
        description="Determine whether attacker-controlled input reaches an executable browser context.",
    ),
    AttackStrategy(
        strategy_id="web.cors_boundary",
        name="CORS trust-boundary verification",
        vulnerability_classes=("cors",),
        surfaces=("web", "api"),
        prerequisites=("observed in-scope GET endpoint",),
        mutation_types=("origin_header",),
        control_requirements=("same-origin control", "untrusted-origin control"),
        verification_contract=("ACAO reflection", "credential policy", "sensitive response"),
        risk="SAFE_ACTIVE",
        request_cost=3,
        description="Test cross-origin trust policy without assuming reflection is exploitable.",
    ),
    AttackStrategy(
        strategy_id="web.redirect_boundary",
        name="Open redirect boundary",
        vulnerability_classes=("open_redirect",),
        surfaces=("web", "rest"),
        prerequisites=("observed redirect-like parameter",),
        mutation_types=("redirect_destination",),
        control_requirements=("same-origin negative control",),
        verification_contract=("external destination accepted",),
        risk="SAFE_ACTIVE",
        request_cost=2,
        description="Verify user-controlled redirect destinations without following external redirects.",
    ),
    AttackStrategy(
        strategy_id="files.path_boundary",
        name="Path traversal boundary",
        vulnerability_classes=("path_traversal", "critical_file_access"),
        surfaces=("web", "rest", "api"),
        prerequisites=("observed file/path parameter",),
        mutation_types=("path",),
        control_requirements=("known-safe file control",),
        verification_contract=("authorized file-boundary proof",),
        risk="HIGH_ACTIVE",
        request_cost=4,
        description="Bounded file-boundary testing using non-sensitive authorized fixtures.",
    ),
    AttackStrategy(
        strategy_id="files.upload_boundary",
        name="File upload boundary",
        vulnerability_classes=("file_upload", "critical_upload_execution"),
        surfaces=("web", "rest", "api"),
        prerequisites=("observed upload endpoint",),
        mutation_types=("filename", "content_type", "file_content"),
        control_requirements=("benign file", "safe marker"),
        verification_contract=("storage/execution boundary",),
        risk="HIGH_ACTIVE",
        request_cost=4,
        description="Test upload validation using harmless controlled files.",
    ),
    AttackStrategy(
        strategy_id="auth.session_boundary",
        name="Session boundary",
        vulnerability_classes=("cookie_session", "authentication_bypass"),
        surfaces=("web", "api"),
        prerequisites=("authenticated session",),
        mutation_types=("session", "cookie", "authentication_state"),
        control_requirements=("fresh session baseline", "logout/invalidation control"),
        verification_contract=("session state transition",),
        risk="SAFE_ACTIVE",
        request_cost=4,
        description="Test authentication-state and session-boundary behavior.",
    ),
    AttackStrategy(
        strategy_id="logic.workflow_replay",
        name="Workflow state-machine testing",
        vulnerability_classes=("critical_business_logic", "race_condition"),
        surfaces=("web", "rest", "api"),
        prerequisites=("observed multi-step workflow",),
        mutation_types=("sequence", "replay", "state", "identity"),
        control_requirements=("valid workflow baseline", "state transition control"),
        verification_contract=("state invariant", "business-property violation"),
        risk="HIGH_ACTIVE",
        request_cost=6,
        description="Test bounded workflow sequence changes and replay behavior.",
    ),
)


STRATEGIES: Dict[str, AttackStrategy] = {
    strategy.strategy_id: strategy for strategy in _STRATEGIES
}


def get_strategy(strategy_id: str) -> AttackStrategy | None:
    return STRATEGIES.get(str(strategy_id or ""))


def strategies_for_class(vulnerability_class: str) -> List[AttackStrategy]:
    return [
        strategy
        for strategy in STRATEGIES.values()
        if vulnerability_class in strategy.vulnerability_classes
    ]


def select_strategies(
    vulnerability_class: str,
    *,
    surface: str | None = None,
    observed_capabilities: Iterable[str] = (),
    active_requested: bool = False,
) -> List[AttackStrategy]:
    """Return applicable strategies without executing anything."""

    return [
        strategy
        for strategy in strategies_for_class(vulnerability_class)
        if strategy.applies_to(
            vulnerability_class=vulnerability_class,
            surface=surface,
            observed_capabilities=observed_capabilities,
            active_requested=active_requested,
        )
    ]


def strategy_public_dict(strategy: AttackStrategy) -> Dict[str, Any]:
    return {
        "strategy_id": strategy.strategy_id,
        "name": strategy.name,
        "vulnerability_classes": list(strategy.vulnerability_classes),
        "surfaces": list(strategy.surfaces),
        "prerequisites": list(strategy.prerequisites),
        "mutation_types": list(strategy.mutation_types),
        "control_requirements": list(strategy.control_requirements),
        "verification_contract": list(strategy.verification_contract),
        "reproduction_required": strategy.reproduction_required,
        "impact_required": strategy.impact_required,
        "active": strategy.active,
        "risk": strategy.risk,
        "request_cost": strategy.request_cost,
        "description": strategy.description,
    }
