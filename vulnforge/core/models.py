"""
VulnForge — core data models.

Every pipeline stage consumes and produces these structures. They are
plain dataclasses with to_dict() so any stage can be serialized into the
store and feeds reporting without translation glue.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Finding lifecycle statuses (spec §37, §43)
# ---------------------------------------------------------------------------
STATUS_CANDIDATE = "CANDIDATE"
STATUS_NEEDS_VERIFICATION = "CANDIDATE"
STATUS_LIKELY = "REPRODUCED"
STATUS_VERIFIED = "VERIFIED"
# Compatibility alias; the canonical confirmed state is VERIFIED.
STATUS_CONFIRMED = STATUS_VERIFIED
STATUS_FALSE_POSITIVE = "KILLED"
FINDING_STATES = ("OBSERVED", "SIGNAL", "CANDIDATE", "REPRODUCED", "VERIFIED", "KILLED")

SEVERITIES = ("critical", "high", "medium", "low", "info")


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"

# Typed reasoning and evidence-backed model entities.
@dataclass
class AssetNode:
    asset_id: str
    asset_type: str
    value: str
    source: str
    confidence: float = 1.0
    scope_status: str = "UNKNOWN"
    observed_at: float = field(default_factory=time.time)
    evidence_ids: List[str] = field(default_factory=list)
    def to_dict(self): return asdict(self)

@dataclass
class AssetEdge:
    source_id: str
    target_id: str
    relation: str
    source: str
    confidence: float = 1.0
    observed_at: float = field(default_factory=time.time)
    evidence_ids: List[str] = field(default_factory=list)
    def to_dict(self): return asdict(self)

@dataclass
class Actor:
    actor_id: str
    label: str
    role: str = "UNKNOWN"
    tenant: str = "UNKNOWN"
    source: str = "researcher-config"
    authenticated: str = "UNKNOWN"
    def to_dict(self): return asdict(self)

@dataclass
class Resource:
    resource_id: str
    resource_type: str
    endpoint: str
    declared_owner: str = "UNKNOWN"
    source: str = "researcher-config"
    def to_dict(self): return asdict(self)

@dataclass
class ApplicationModel:
    application_id: str
    target: str
    service_urls: List[str] = field(default_factory=list)
    endpoint_ids: List[str] = field(default_factory=list)
    parameter_ids: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    relationships: List[Dict[str, str]] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    completeness: str = "PARTIAL"
    observed_page_ids: List[str] = field(default_factory=list)
    javascript_asset_ids: List[str] = field(default_factory=list)
    api_document_ids: List[str] = field(default_factory=list)
    declared_operation_ids: List[str] = field(default_factory=list)
    out_of_scope_endpoint_ids: List[str] = field(default_factory=list)
    def to_dict(self): return asdict(self)

@dataclass
class SecurityProperty:
    property_id: str
    name: str
    actor_id: str
    resource_id: str
    operation: str
    expected: str
    source: str = "researcher-config"
    def to_dict(self): return asdict(self)

@dataclass
class HypothesisRecord:
    hypothesis_id: str
    category: str
    status: str
    endpoint: str = ""
    parameter: str = ""
    actor_id: str = ""
    resource_id: str = ""
    operation: str = ""
    security_property: str = ""
    reason: str = ""
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0
    test_strategy: str = ""
    request_cost: int = 0
    risk: str = "PASSIVE"
    def to_dict(self): return asdict(self)
    def __getitem__(self, key): return self.to_dict()[key]
    def get(self, key, default=None): return self.to_dict().get(key, default)

@dataclass
class PlannedTest:
    test_id: str
    hypothesis_id: str
    test_type: str
    endpoint: str
    method: str = "GET"
    request_cost: int = 3
    risk: str = "LOW"
    authorization_required: bool = True
    status: str = "PLANNED"
    methodology: Dict[str, Any] = field(default_factory=dict)
    def to_dict(self): return asdict(self)

@dataclass
class AttackPathRecord:
    """Evidence-linked attack-path component; never implies end-to-end exploitability."""
    path_id: str
    status: str
    title: str
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    hypothesis_ids: List[str] = field(default_factory=list)
    finding_id: str = ""
    rationale: str = ""
    missing_evidence: List[str] = field(default_factory=list)
    safe_next_steps: List[str] = field(default_factory=list)
    end_to_end_verified: bool = False
    impact_proven: bool = False
    source: str = "evidence-linked-model"
    def to_dict(self): return asdict(self)

# ---------------------------------------------------------------------------
# HTTP exchange (immutable record of one request/response pair)
# ---------------------------------------------------------------------------
@dataclass
class HttpExchange:
    method: str
    url: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_header_items: List[List[str]] = field(default_factory=list)
    request_version: str = "HTTP/1.1"
    request_body: str = ""
    status: int = 0
    reason_phrase: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_header_items: List[List[str]] = field(default_factory=list)
    response_version: str = "HTTP/1.1"
    response_body: str = ""
    duration_ms: float = 0.0
    error: Optional[str] = None
    module: str = ""
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    exchange_id: str = field(default_factory=lambda: _uid("exchange"))
    request_id: str = field(default_factory=lambda: _uid("request"))
    response_id: str = field(default_factory=lambda: _uid("response"))
    parent_exchange_id: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None and self.status > 0
    @property
    def body_length(self) -> int:
        return len(self.response_body or "")
    def header(self, name: str, default: str = "") -> str:
        lname = name.lower()
        for k, v in self.response_headers.items():
            if k.lower() == lname: return v
        return default
    def to_dict(self) -> Dict[str, Any]: return asdict(self)

# ---------------------------------------------------------------------------
# Parameter intelligence (spec §13)
# ---------------------------------------------------------------------------
@dataclass
class Parameter:
    name: str
    location: str
    endpoint_url: str
    method: str = "GET"
    content_type: str = ""
    example: str = ""
    type_hint: str = ""
    classifications: List[str] = field(default_factory=list)
    source: str = "html"
    confidence: float = 0.7
    def key(self) -> str: return f"{self.method}:{self.endpoint_url}:{self.location}:{self.name}"
    def to_dict(self) -> Dict[str, Any]: return asdict(self)

# ---------------------------------------------------------------------------
# Endpoint inventory (spec §14)
# ---------------------------------------------------------------------------
@dataclass
class Endpoint:
    url: str
    normalized: str
    method: str = "GET"
    path: str = ""
    params: List[Parameter] = field(default_factory=list)
    content_type: str = ""
    source: str = "crawl"
    depth: int = 0
    status: int = 0
    title: str = ""
    response_hash: str = ""
    response_length: int = 0
    state_changing: bool = False
    auth_hint: str = ""
    technologies: List[str] = field(default_factory=list)
    discovered_at: float = field(default_factory=time.time)
    scope_status: str = "UNKNOWN"
    scope_reason: str = ""
    state: str = "DISCOVERED"
    state_reason: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    def key(self) -> str: return f"{self.method}:{self.normalized}"
    def to_dict(self) -> Dict[str, Any]: return asdict(self)

# ---------------------------------------------------------------------------
# Technology observation (spec §12)
# ---------------------------------------------------------------------------
@dataclass
class Technology:
    name: str
    category: str
    confidence: str
    signals: List[str] = field(default_factory=list)
    observations_count: int = 0
    version: str = "UNKNOWN"
    detection_method: str = "passive-response"
    source: str = "HTTP response"
    def to_dict(self) -> Dict[str, Any]: return asdict(self)

# ---------------------------------------------------------------------------
# Discovery signal — NOT a finding
# ---------------------------------------------------------------------------
@dataclass
class Signal:
    kind: str
    detail: str
    source: str
    url: str = ""
    severity_hint: str = "info"
    def to_dict(self) -> Dict[str, Any]: return asdict(self)

# ---------------------------------------------------------------------------
# Finding + Evidence
# ---------------------------------------------------------------------------
@dataclass
class EvidenceItem:
    description: str
    request_summary: str = ""
    response_summary: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    def to_dict(self) -> Dict[str, Any]: return asdict(self)

@dataclass
class Finding:
    title: str
    category: str
    severity: str
    description: str
    endpoint: str = ""
    parameter: str = ""
    method: str = "GET"
    confidence: float = 0.5
    status: str = STATUS_CANDIDATE
    state: str = ""
    evidence: List[EvidenceItem] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cwe: str = ""
    owasp: str = ""
    source_plugin: str = ""
    manual_verification: str = ""
    impact: str = ""
    id: str = field(default_factory=lambda: _uid("VF2"))
    created_at: float = field(default_factory=time.time)
    simple_summary: str = ""
    why_it_matters: str = ""
    def __post_init__(self):
        legacy={"candidate":"CANDIDATE","needs_verification":"CANDIDATE",
                "likely":"REPRODUCED","false_positive":"KILLED",
                "confirmed":"CANDIDATE"}
        self.status=legacy.get(self.status,self.status)
        if not self.state:
            self.state={STATUS_CANDIDATE:"CANDIDATE",STATUS_NEEDS_VERIFICATION:"CANDIDATE",
                        STATUS_LIKELY:"REPRODUCED",STATUS_VERIFIED:"VERIFIED",
                        STATUS_FALSE_POSITIVE:"KILLED"}.get(self.status,"CANDIDATE")
    def to_dict(self) -> Dict[str, Any]: return asdict(self)

@dataclass
class ScanStats:
    requests_sent: int = 0
    requests_refused_scope: int = 0
    pages_crawled: int = 0
    endpoints_discovered: int = 0
    parameters_discovered: int = 0
    signals: int = 0
    crawl_errors: int = 0
    crawl_cancelled: int = 0
    crawl_timeouts: int = 0
    crawl_scope_rejected: int = 0
    crawl_budget_rejected: int = 0
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    def to_dict(self) -> Dict[str, Any]: return asdict(self)

@dataclass
class ScanContext:
    scan_id: str
    config: Any
    authorization: Any
    endpoints: Dict[str, Endpoint] = field(default_factory=dict)
    parameters: Dict[str, Parameter] = field(default_factory=dict)
    technologies: Dict[str, Technology] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    signals: List[Signal] = field(default_factory=list)
    exchanges: List[HttpExchange] = field(default_factory=list)
    pages: List[HttpExchange] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    requester: Any = None
    stop_reason: str = ""
    intelligence: Dict[str, Any] = field(default_factory=dict)
    application_model: Optional[ApplicationModel] = None
    hypotheses: List[HypothesisRecord] = field(default_factory=list)
    tests: List[Dict[str, Any]] = field(default_factory=list)
    verified_findings: List[Finding] = field(default_factory=list)
    risk_summary: Dict[str, Any] = field(default_factory=dict)
    test_plan: List[PlannedTest] = field(default_factory=list)
    attack_paths: List[AttackPathRecord] = field(default_factory=list)
    workflow_model: Dict[str, Any] = field(default_factory=dict)
    workflow_plan_errors: List[str] = field(default_factory=list)
    asset_nodes: List[AssetNode] = field(default_factory=list)
    asset_edges: List[AssetEdge] = field(default_factory=list)
    actors: List[Actor] = field(default_factory=list)
    resources: List[Resource] = field(default_factory=list)
    security_properties: List[SecurityProperty] = field(default_factory=list)
    phases: List[Any] = field(default_factory=list)
    js_analyzed: int = 0
    _listeners: List[Any] = field(default_factory=list, repr=False)
    def on_event(self, fn) -> None: self._listeners.append(fn)
    def emit(self, kind: str, message: str, **data) -> None:
        for fn in list(self._listeners):
            try: fn(kind, message, data)
            except Exception: pass
    def add_endpoint(self, ep: Endpoint) -> bool:
        k=ep.key()
        if k in self.endpoints:
            existing=self.endpoints[k]; known={p.name+p.location for p in existing.params}
            for p in ep.params:
                if p.name+p.location not in known:
                    existing.params.append(p); self.parameters.setdefault(p.key(),p)
            existing.evidence_ids=sorted(set(existing.evidence_ids+ep.evidence_ids))
            if existing.scope_status=="UNKNOWN" and ep.scope_status!="UNKNOWN":
                existing.scope_status,existing.scope_reason=ep.scope_status,ep.scope_reason
            return False
        self.endpoints[k]=ep
        for p in ep.params: self.parameters.setdefault(p.key(),p)
        return True
    def add_technology(self, name: str, category: str, confidence: str, signal: str) -> None:
        """Aggregate detections while retaining a bounded set of evidence samples."""
        order={"LOW":0,"MEDIUM":1,"HIGH":2}
        max_samples=6
        if name in self.technologies:
            t=self.technologies[name]
            if order.get(confidence,0)>order.get(t.confidence,0): t.confidence=confidence
            t.observations_count+=1
            if signal and signal not in t.signals and len(t.signals)<max_samples: t.signals.append(signal)
        else:
            self.technologies[name]=Technology(name,category,confidence,[signal] if signal else [],observations_count=1)
    @property
    def stopped(self) -> bool: return bool(self.stop_reason)
