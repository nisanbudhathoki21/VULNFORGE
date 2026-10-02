from types import SimpleNamespace

from vulnforge.core.models import (
    AttackPathRecord, Endpoint, EvidenceItem, Finding, HttpExchange, HypothesisRecord,
)
from vulnforge.engine.attack_paths import build_attack_paths


def _ctx():
    observed=HttpExchange(method="GET",url="http://127.0.0.1/item/7",status=200,module="test")
    declared=HttpExchange(method="GET",url="http://127.0.0.1/other",status=200,module="test")
    return SimpleNamespace(
        endpoints={"GET:/item/7":Endpoint(url=observed.url,normalized=observed.url,
            scope_status="IN_SCOPE",evidence_ids=[observed.exchange_id])},
        hypotheses=[
            HypothesisRecord("hyp-review","cors-policy-review","KEEP",endpoint=observed.url,
                security_property="Origin policy should be allowlisted",reason="Observed response surface",
                evidence=[observed.exchange_id],test_strategy="Review authorized policy"),
            HypothesisRecord("hyp-verified","open-redirect-review","VERIFIED",endpoint=declared.url),
        ],
        verified_findings=[Finding(title="Cross-account object authorization failure",
            category="authorization / BOLA",severity="medium",description="Tested access control",
            endpoint=observed.url,status="VERIFIED",id="finding-1",
            evidence=[EvidenceItem(description="Verified test",detail={"test_id":"test-1",
                "hypothesis_id":"hyp-verified","observations":[{"exchange_id":observed.exchange_id},
                {"exchange_id":declared.exchange_id}]})])],
        requester=SimpleNamespace(exchanges=[observed,declared]),
    )


def test_builder_keeps_hypotheses_separate_and_only_links_known_evidence():
    ctx=_ctx()
    records=build_attack_paths(ctx)
    assert len(records)==2
    hypothesis=next(item for item in records if item.status=="HYPOTHESIS")
    component=next(item for item in records if item.status=="VERIFIED_COMPONENT")
    assert hypothesis.hypothesis_ids==["hyp-review"]
    assert hypothesis.evidence_ids
    assert all(edge["status"]=="HYPOTHESIS" for edge in hypothesis.edges)
    assert component.finding_id=="finding-1"
    assert component.hypothesis_ids==["hyp-verified"]
    assert set(component.evidence_ids)=={ex.exchange_id for ex in ctx.requester.exchanges}
    assert component.impact_proven is True
    assert component.end_to_end_verified is False
    assert all(edge["status"]=="SUPPORTED" for edge in component.edges)


def test_builder_does_not_turn_a_verified_component_into_an_end_to_end_path():
    records=build_attack_paths(_ctx())
    assert all(not item.end_to_end_verified for item in records)
    assert all(item.status!="VERIFIED_PATH" for item in records)
    assert all(isinstance(item,AttackPathRecord) for item in records)


def test_risk_stage_and_report_expose_offline_component_records():
    import asyncio
    from vulnforge.core.authorization import AuthorizationContext
    from vulnforge.core.models import ScanContext
    from vulnforge.engine.orchestrator import RiskAnalysisStage, ScanConfig, ScanResult
    from vulnforge.report.json_report import build_report_dict

    observed=HttpExchange(method="GET",url="http://127.0.0.1/item/7",status=200,module="test")
    config=ScanConfig(target="http://127.0.0.1",profile_name="lab")
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],allowed_methods=["GET"],
        allow_private=True,confirmed=True,profile_name="lab")
    ctx=ScanContext("scan-path-report",config,auth)
    ctx.endpoints={"endpoint":Endpoint(url=observed.url,normalized=observed.url,
        scope_status="IN_SCOPE",evidence_ids=[observed.exchange_id])}
    ctx.hypotheses=[HypothesisRecord("hyp-1","open-redirect-review","KEEP",
        endpoint=observed.url,reason="Observed endpoint")]
    ctx.requester=SimpleNamespace(exchanges=[observed])
    asyncio.run(RiskAnalysisStage().run(ctx))
    report=build_report_dict(ScanResult(context=ctx))
    assert report["attack_paths"]
    assert report["attack_path_summary"]["hypothesis_paths"]==1
    assert report["attack_path_summary"]["end_to_end_verified"] is False
    assert report["workflow_model"]["status"]=="STATIC_OBSERVATIONS_ONLY"
    assert report["workflow_summary"]["executed_transitions"]==0
    assert ctx.risk_summary["attack_path_records"]==1
    assert ctx.risk_summary["workflow_transitions_executed"]==0
