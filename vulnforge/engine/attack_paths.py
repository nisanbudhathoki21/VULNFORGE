"""Offline, evidence-linked attack-path leads; this module never issues network requests."""
from __future__ import annotations
import hashlib
from typing import Any, Dict, Iterable, List, Set

from ..core.models import AttackPathRecord


def _collect_exchange_ids(value: Any) -> Set[str]:
    found=set()
    if isinstance(value,dict):
        for key,item in value.items():
            if isinstance(item,str) and ("exchange_id" in str(key).lower()) and item:
                found.add(item)
            else:
                found.update(_collect_exchange_ids(item))
    elif isinstance(value,(list,tuple)):
        for item in value: found.update(_collect_exchange_ids(item))
    return found


def _path_id(kind: str, identity: str) -> str:
    return "path-"+hashlib.sha256((kind+"\0"+identity).encode("utf-8","replace")).hexdigest()[:12]


def build_attack_paths(ctx, *, max_paths: int = 100) -> List[AttackPathRecord]:
    """Create reviewable leads and verified components without joining unsupported edges.

    Hypothesis paths remain hypotheses. Verified findings contribute a `VERIFIED_COMPONENT`
    record, never an end-to-end exploitability claim. Multi-step chaining is intentionally
    deferred until a workflow/state model can justify every transition.
    """
    endpoints={str(ep.url):ep for ep in getattr(ctx,"endpoints",{}).values()}
    all_exchanges=list(getattr(ctx,"exchanges",[]) or [])
    all_exchanges.extend(getattr(getattr(ctx,"requester",None),"exchanges",[]) or [])
    exchange_ids={ex.exchange_id for ex in all_exchanges if getattr(ex,"exchange_id",None)}
    output=[]; seen=set()
    for hypothesis in getattr(ctx,"hypotheses",[]):
        if len(output)>=max_paths: break
        if str(getattr(hypothesis,"status","")).upper()=="VERIFIED":
            continue
        endpoint=str(getattr(hypothesis,"endpoint","") or "")
        if not endpoint: continue
        ep=endpoints.get(endpoint)
        evidence=set(getattr(hypothesis,"evidence",[]) or [])
        if ep: evidence.update(getattr(ep,"evidence_ids",[]) or [])
        evidence={item for item in evidence if item in exchange_ids}
        key=("hypothesis",getattr(hypothesis,"hypothesis_id",""),endpoint)
        if key in seen: continue
        seen.add(key)
        actor_value=(getattr(hypothesis,"actor_id","") or "Actor/identity not inferred")
        actor_source="researcher-config" if getattr(hypothesis,"actor_id","") else "NOT_INFERRED"
        prop=str(getattr(hypothesis,"security_property","") or getattr(hypothesis,"category","review lead"))
        status="IN_SCOPE_OBSERVED" if ep and getattr(ep,"scope_status","")=="IN_SCOPE" else "DECLARED_OR_UNVALIDATED"
        output.append(AttackPathRecord(
            path_id=_path_id("hypothesis",str(key)),status="HYPOTHESIS",
            title=f"Review lead: {getattr(hypothesis,'category','security hypothesis')}",
            nodes=[{"node_id":"actor","node_type":"ACTOR_ORIGIN","value":actor_value,"provenance":actor_source},
                   {"node_id":"entry","node_type":"ENDPOINT","value":endpoint,"provenance":status,
                    "evidence_ids":sorted(evidence)},
                   {"node_id":"property","node_type":"UNVERIFIED_PROPERTY","value":prop,"provenance":"HYPOTHESIS"}],
            edges=[{"from":"actor","to":"entry","relation":"possible-entry","status":"HYPOTHESIS",
                    "evidence_ids":sorted(evidence)},
                   {"from":"entry","to":"property","relation":"review-lead","status":"HYPOTHESIS",
                    "evidence_ids":sorted(evidence)}],
            evidence_ids=sorted(evidence),hypothesis_ids=[str(getattr(hypothesis,"hypothesis_id",""))],
            rationale=str(getattr(hypothesis,"reason","") or "No rationale recorded."),
            missing_evidence=["Independent test evidence for each transition", "A supported verifier for the stated security property"],
            safe_next_steps=[str(getattr(hypothesis,"test_strategy","") or "Manual authorized review; no automated method mapped.")],
            end_to_end_verified=False,impact_proven=False))

    for finding in getattr(ctx,"verified_findings",[]):
        if len(output)>=max_paths: break
        if str(getattr(finding,"status","")).upper()!="VERIFIED": continue
        details=[]
        for item in getattr(finding,"evidence",[]) or []:
            detail=getattr(item,"detail",{})
            if isinstance(detail,dict): details.append(detail)
        evidence=set()
        hypothesis_ids=set()
        for detail in details:
            evidence.update(_collect_exchange_ids(detail))
            if detail.get("hypothesis_id"): hypothesis_ids.add(str(detail["hypothesis_id"]))
        evidence &= exchange_ids
        key=("verified-component",str(getattr(finding,"id","")))
        if key in seen: continue
        seen.add(key)
        category=str(getattr(finding,"category",""))
        if "bola" in category.lower():
            actor="Configured non-owner identity"; property_value="Configured owner-bound fields were returned to the non-owner identity"
            impact=True; missing=["Additional workflow transitions outside this configured object test"]
        elif "cors" in category.lower():
            actor="Synthetic untrusted Origin"; property_value="Credentialed CORS origin-reflection headers were verified"
            impact=False; missing=["Browser credential behavior", "Sensitive data exposure and real-user impact"]
        elif "redirect" in category.lower():
            actor="User-controlled redirect parameter"; property_value="External redirect destination control was verified without following it"
            impact=False; missing=["Phishing success or downstream user impact"]
        else:
            actor="Test actor not inferred"; property_value=str(getattr(finding,"title","Verified component"))
            impact=False; missing=["End-to-end impact and remaining chain transitions"]
        endpoint=str(getattr(finding,"endpoint","") or "")
        output.append(AttackPathRecord(
            path_id=_path_id("verified-component",str(getattr(finding,"id",""))),
            status="VERIFIED_COMPONENT",title=f"Verified component: {getattr(finding,'title','security result')}",
            nodes=[{"node_id":"actor","node_type":"TEST_CONTEXT","value":actor,"provenance":"TEST_CONFIGURATION"},
                   {"node_id":"entry","node_type":"ENDPOINT","value":endpoint,"provenance":"OBSERVED",
                    "evidence_ids":sorted(evidence)},
                   {"node_id":"property","node_type":"VERIFIED_COMPONENT","value":property_value,
                    "provenance":"INDEPENDENT_VERIFIER","finding_id":finding.id}],
            edges=[{"from":"actor","to":"entry","relation":"tested-request","status":"SUPPORTED",
                    "evidence_ids":sorted(evidence)},
                   {"from":"entry","to":"property","relation":"verified-security-property","status":"SUPPORTED",
                    "evidence_ids":sorted(evidence)}],
            evidence_ids=sorted(evidence),hypothesis_ids=sorted(hypothesis_ids),finding_id=str(finding.id),
            rationale="This record summarizes one independently verified component only; no additional attack-chain transitions are inferred.",
            missing_evidence=missing,safe_next_steps=["Review the finding's evidence and verify the business context under explicit authorization."],
            end_to_end_verified=False,impact_proven=impact))
    return output[:max(0,int(max_paths))]
