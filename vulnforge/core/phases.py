"""Canonical 15-phase lifecycle used by the real orchestrator and all outputs."""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import List

PHASE_STATES = ("START", "RUNNING", "COMPLETE", "PARTIAL", "SKIPPED", "BLOCKED", "FAILED")

@dataclass(frozen=True)
class PhaseSpec:
    phase_id: str
    name: str
    stages: List[str]
    completion_status: str
    note: str

PHASE_SPECS = [
    PhaseSpec("phase-01", "AUTHORIZATION & TARGET NORMALIZATION", ["auth", "http"], "COMPLETE", "Authorization and normalization initialize the centralized request controls."),
    PhaseSpec("phase-02", "ASSET & INFRASTRUCTURE DISCOVERY", ["services", "recon"], "PARTIAL", "Observed target DNS and authorized HTTP only; no broad port or subdomain discovery."),
    PhaseSpec("phase-03", "APPLICATION DISCOVERY", ["crawl"], "PARTIAL", "Bounded static HTTP crawl; no browser-rendered application execution."),
    PhaseSpec("phase-04", "FRONTEND INTELLIGENCE", ["js", "frontend-intel"], "PARTIAL", "Fetched JavaScript is statically analyzed; no DOM/browser execution."),
    PhaseSpec("phase-05", "BACKEND & API INTELLIGENCE", ["inventory", "api-model", "tech", "passive-checks", "intelligence"], "PARTIAL", "Observed routes, response fingerprints, and passive signals; no complete API contract or backend validation."),
    PhaseSpec("phase-06", "APPLICATION MODELING", ["application-model"], "PARTIAL", "Application relationships are built from observed endpoints, parameters, services, and technology evidence."),
    PhaseSpec("phase-07", "SECURITY MODELING", ["security-model"], "PARTIAL", "Observed assets and explicitly declared actors, resources, and security properties only."),
    PhaseSpec("phase-08", "HYPOTHESIS GENERATION", ["hypotheses"], "COMPLETE", "Hypotheses are evidence-linked research leads, never findings by themselves."),
    PhaseSpec("phase-09", "TEST PLANNING", ["test-plan"], "COMPLETE", "Only supported, bounded tests are planned; blocked reasons are retained."),
    PhaseSpec("phase-10", "CONTROLLED SECURITY TESTING", ["controlled-test"], "PARTIAL", "Only explicit, read-only cross-account comparison is implemented."),
    PhaseSpec("phase-11", "VERIFICATION", ["verification"], "PARTIAL", "Promotion requires repeated identity-bound observations and a demonstrated security-property violation."),
    PhaseSpec("phase-12", "CORRELATION", ["correlation"], "COMPLETE", "Exact duplicate findings are correlated conservatively; no speculative chains."),
    PhaseSpec("phase-13", "EVIDENCE & FINDINGS", ["evidence-validation", "finding-finalization"], "COMPLETE", "Only independently verified findings with a valid evidence link enter the verified findings set."),
    PhaseSpec("phase-14", "COVERAGE & RISK ANALYSIS", ["coverage", "risk-analysis"], "COMPLETE", "Coverage is implementation-backed; risk summaries do not imply security from absent findings."),
    PhaseSpec("phase-15", "REPORTING", ["report-preparation"], "PARTIAL", "Orchestration prepares actual structured report inputs; CLI/API renderer writes final artifacts."),
]

@dataclass
class ScanPhase:
    phase_id: str
    name: str
    status: str = "START"
    stages: List[str] = field(default_factory=list)
    completed_stages: List[str] = field(default_factory=list)
    skipped_stages: List[str] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    note: str = ""
    def to_dict(self):
        return {"phase_id":self.phase_id,"name":self.name,"status":self.status,
                "stages":list(self.stages),"completed_stages":list(self.completed_stages),
                "skipped_stages":list(self.skipped_stages),"started_at":self.started_at,
                "finished_at":self.finished_at,"note":self.note}

class PhaseTracker:
    def __init__(self):
        self.phases=[ScanPhase(s.phase_id,s.name,stages=list(s.stages),note=s.note) for s in PHASE_SPECS]
        self._specs={s.phase_id:s for s in PHASE_SPECS}
        self._by_stage={stage:s.phase_id for s in PHASE_SPECS for stage in s.stages}
    def start_stage(self, stage: str):
        phase=self._find(stage)
        if phase and phase.status=="START":
            phase.status="RUNNING"; phase.started_at=time.time()
    def complete_stage(self, stage: str, context):
        phase=self._find(stage)
        if not phase: return
        if stage not in phase.completed_stages: phase.completed_stages.append(stage)
        if set(phase.stages).issubset(phase.completed_stages):
            phase.status=self._completion_for(phase,context)
            phase.finished_at=time.time()
    def _completion_for(self, phase, context):
        if phase.phase_id=="phase-10":
            return "PARTIAL" if any(t.get("status") not in ("NOT_RUN", "BLOCKED") for t in context.tests) else "SKIPPED"
        if phase.phase_id=="phase-11":
            return "PARTIAL" if any(t.get("status")=="VERIFIED" for t in context.tests) else "SKIPPED"
        if phase.phase_id=="phase-07":
            return "PARTIAL" if (getattr(context,"asset_nodes",[]) or getattr(context,"actors",[])) else "SKIPPED"
        return self._specs[phase.phase_id].completion_status
    def skip_stage(self, stage: str, stopped=False, blocked=False):
        phase=self._find(stage)
        if not phase: return
        if stage not in phase.completed_stages: phase.completed_stages.append(stage)
        if stage not in phase.skipped_stages: phase.skipped_stages.append(stage)
        if set(phase.stages).issubset(phase.completed_stages):
            completed=[x for x in phase.completed_stages if x not in phase.skipped_stages]
            phase.status=("PARTIAL" if completed else ("BLOCKED" if blocked else "SKIPPED"))
            phase.finished_at=time.time()
    def fail_stage(self, stage: str, stopped=False, blocked=False):
        phase=self._find(stage)
        if phase and phase.status=="RUNNING":
            phase.status="BLOCKED" if blocked else "FAILED"; phase.finished_at=time.time()
    def start_reporting(self): self._start_manual("phase-15")
    def finish_reporting(self): self._finish_manual("phase-15","COMPLETE")
    def _start_manual(self, phase_id):
        p=next(x for x in self.phases if x.phase_id==phase_id)
        p.status="RUNNING"; p.started_at=p.started_at or time.time()
    def _finish_manual(self, phase_id,status):
        p=next(x for x in self.phases if x.phase_id==phase_id)
        p.status=status; p.started_at=p.started_at or time.time(); p.finished_at=time.time()
    def finalize(self, stopped=False):
        for p in self.phases:
            if p.status=="RUNNING": p.status="FAILED"; p.finished_at=time.time()
            elif p.status=="START":
                p.status="SKIPPED"; p.note=p.note or "Phase not reached."
    def _find(self,stage):
        phase_id=self._by_stage.get(stage)
        return next((p for p in self.phases if p.phase_id==phase_id),None)
