"""Explicitly configured, read-only authorization test execution and verification.

Execution only collects repeatable observations. A separate verification step
checks the declared security property and is the only code that promotes a
result into a confirmed finding. All requests use the shared request gate.
"""
from __future__ import annotations
import hashlib, json, time, uuid
from urllib.parse import urljoin, urlsplit
from ..core.models import EvidenceItem, Finding, STATUS_VERIFIED


def _parse_json(exchange):
    try:
        data=json.loads(exchange.response_body)
        return data if isinstance(data,dict) else None
    except (ValueError,TypeError): return None


def _field_observations(obj, owner_field, owner_value, sensitive_fields):
    if not isinstance(obj,dict):
        return {"json_object":False,"owner_matches":False,"sensitive_fields_present":False}
    return {"json_object":True,"owner_matches":obj.get(owner_field)==owner_value,
            "sensitive_fields_present":all(k in obj for k in sensitive_fields)}


def expand_authorization_specs(auth_data):
    """Expand multi-role `other_identities` entries into explicit two-identity test specs."""
    raw_specs = auth_data.get("authorization_tests", []) if isinstance(auth_data, dict) else []
    expanded = []
    for spec in raw_specs:
        if not isinstance(spec, dict):
            continue
        others = spec.get("other_identities")
        if isinstance(others, list) and others:
            assertion = dict(spec.get("identity_assertion") or {})
            other_values = assertion.get("other_values") if isinstance(assertion.get("other_values"), dict) else {}
            for role_name in others:
                role_str = str(role_name)
                role_assertion = dict(assertion)
                role_assertion["other_value"] = str(other_values.get(role_str, assertion.get("other_value", role_str)))
                item = dict(spec)
                item["other_identity"] = role_str
                item["identity_assertion"] = role_assertion
                expanded.append(item)
        else:
            expanded.append(spec)
    return expanded


async def execute_authorization_tests(ctx):
    """Perform only the pre-planned, explicitly configured three-read comparison."""
    if not ctx.test_plan or ctx.stopped:
        return
    from ..core.profiles import get_profile
    profile=get_profile(ctx.config.profile_name)
    if not profile.allows_active:
        for planned in ctx.test_plan:
            planned.status="BLOCKED"
        ctx.emit("stage","Authorization tests blocked: selected profile is observation-only")
        return
    specs=getattr(ctx,"_authorization_test_specs",[])
    by_test={p.test_id:p for p in ctx.test_plan}
    for index,spec in enumerate(specs):
        if ctx.stopped: break
        planned=next((p for p in ctx.test_plan if p.status=="PLANNED" and p.test_id not in {t["test_id"] for t in ctx.tests}),None)
        if planned is None: break
        record={"test_id":planned.test_id,"hypothesis_id":planned.hypothesis_id,
                "type":planned.test_type,"status":"INCOMPLETE","endpoint":"",
                "started_at":time.time(),"verification_method":"Repeated read-only identity comparison"}
        try:
            url=urljoin(ctx.config.target,spec["url"])
            target=urlsplit(ctx.config.target); requested=urlsplit(url)
            if (requested.scheme,requested.hostname,requested.port)!=(target.scheme,target.hostname,target.port):
                raise ValueError("authorization test URL must be same-origin as the scan target")
            owner_name=spec["owner_identity"]; other_name=spec["other_identity"]
            identities=ctx.config.auth_data.get("identities",{})
            owner=identities[owner_name]["headers"]; other=identities[other_name]["headers"]
            owner_field=str(spec["owner_field"]); owner_value=spec["owner_value"]
            sensitive=[str(x) for x in spec.get("sensitive_fields",[])]
            if not sensitive: raise ValueError("at least one sensitive_fields entry is required")
            assertion=spec["identity_assertion"]; identity_header=str(assertion["header"])
            if not identity_header: raise ValueError("identity assertion response header is required")
            record["endpoint"]=url
            # Hypothesis and resource bindings are researcher-declared; raw credentials never enter the record.
            baseline=await ctx.requester.send("GET",url,headers={str(k):str(v) for k,v in owner.items()},module="authorization-test-baseline")
            cross1=await ctx.requester.send("GET",url,headers={str(k):str(v) for k,v in other.items()},module="authorization-test-cross-account")
            cross2=await ctx.requester.send("GET",url,headers={str(k):str(v) for k,v in other.items()},module="authorization-test-repeat")
            bdata=_parse_json(baseline); tdata=_parse_json(cross1); rdata=_parse_json(cross2)
            owner_identity=(baseline.header(identity_header)==str(assertion["owner_value"]))
            other_identity=(cross1.header(identity_header)==str(assertion["other_value"])
                           and cross2.header(identity_header)==str(assertion["other_value"]))
            bo=_field_observations(bdata,owner_field,owner_value,sensitive)
            co=_field_observations(tdata,owner_field,owner_value,sensitive)
            ro=_field_observations(rdata,owner_field,owner_value,sensitive)
            stable=bool(tdata is not None and rdata is not None and
                        all(tdata.get(k)==rdata.get(k) for k in [owner_field,*sensitive]))
            exchanges_ok=all(x.ok and 200<=x.status<300 for x in (baseline,cross1,cross2))
            record.update({"status":"EXECUTED" if exchanges_ok else "INCOMPLETE",
                "reproduction_status":"REPRODUCED" if exchanges_ok and stable else "CANDIDATE",
                "baseline_exchange_id":baseline.exchange_id,"cross_account_exchange_id":cross1.exchange_id,
                "repeat_exchange_id":cross2.exchange_id,"baseline_status":baseline.status,
                "cross_account_status":cross1.status,"repeat_status":cross2.status,
                "expected_owner_field":owner_field,"identity_assertion_header":identity_header,
                "owner_identity_verified":owner_identity,"other_identity_verified":other_identity,
                "baseline_owner_matches":bo["owner_matches"],"baseline_sensitive_fields_present":bo["sensitive_fields_present"],
                "cross_owner_matches":co["owner_matches"],"cross_sensitive_fields_present":co["sensitive_fields_present"],
                "repeat_owner_matches":ro["owner_matches"],"repeat_sensitive_fields_present":ro["sensitive_fields_present"],
                "repeat_response_stable":stable,"json_responses_valid":all(x["json_object"] for x in (bo,co,ro)),
                "sensitive_fields":sensitive,"baseline_response_sha256":hashlib.sha256((baseline.response_body or "").encode()).hexdigest(),
                "cross_account_response_sha256":hashlib.sha256((cross1.response_body or "").encode()).hexdigest(),
                "repeat_response_sha256":hashlib.sha256((cross2.response_body or "").encode()).hexdigest(),
                "security_boundary":"object-level authorization / cross-account ownership",
                "owner_identity_label":owner_name,"other_identity_label":other_name})
            planned.status="EXECUTED" if exchanges_ok else "INCOMPLETE"
        except (KeyError,TypeError,ValueError) as exc:
            record["status"]="NOT_RUN"; record["reason"]=str(exc); planned.status="BLOCKED"
            ctx.emit("stage",f"Authorization test not run: {exc}")
        record["finished_at"]=time.time(); ctx.tests.append(record)


def verify_authorization_tests(ctx):
    """Apply the security-property assertion; only this step may confirm BOLA."""
    hypotheses={h.hypothesis_id:h for h in ctx.hypotheses}
    for record in ctx.tests:
        if record.get("type")!="cross-account-object-authorization" or record.get("status") not in ("EXECUTED","INCOMPLETE"):
            continue
        proof=(record.get("status")=="EXECUTED"
            and record.get("owner_identity_verified") is True
            and record.get("other_identity_verified") is True
            and record.get("baseline_owner_matches") is True
            and record.get("baseline_sensitive_fields_present") is True
            and record.get("cross_owner_matches") is True
            and record.get("cross_sensitive_fields_present") is True
            and record.get("repeat_owner_matches") is True
            and record.get("repeat_sensitive_fields_present") is True
            and record.get("repeat_response_stable") is True
            and record.get("json_responses_valid") is True)
        record["status"]="VERIFIED" if proof else "CANDIDATE"
        record["reproduction_status"]="VERIFIED" if proof else record.get("reproduction_status","CANDIDATE")
        h=hypotheses.get(record.get("hypothesis_id"))
        if h: h.status="VERIFIED" if proof else "DEEPER_TESTING"
        if not proof: continue
        # Reconfirm the security-property violation and meaningful unauthorized effect.
        url=record["endpoint"]
        finding=Finding(title="Cross-account object authorization failure",category="authorization / BOLA",
            severity="medium",description=(f"The explicitly configured non-owner identity '{record['other_identity_label']}' "
                f"received a repeatable owner-bound object at {url}, including configured sensitive fields."),
            endpoint=url,method="GET",confidence=0.98,status=STATUS_VERIFIED,state="VERIFIED",
            evidence=[EvidenceItem(description="Owner baseline and repeated non-owner reads satisfied the declared identity and ownership assertions.",
                request_summary=f"GET {url} as configured owner and non-owner identities (credentials redacted)",
                response_summary=f"HTTP {record['baseline_status']} baseline; HTTP {record['cross_account_status']}/{record['repeat_status']} repeated cross-account reads",
                detail={**record,"test_id":record["test_id"]})],
            remediation="Enforce object-level authorization on every read using the authenticated principal; do not trust client-supplied object identifiers.",
            impact="Unauthorized cross-account access to the researcher-configured sensitive response fields.",
            manual_verification="Confirm the supplied identities and ownership mapping are valid and authorized.")
        finding.id="VF-"+uuid.uuid4().hex[:12]
        ctx.findings.append(finding); record["finding_id"]=finding.id

# Backward-compatible symbol: execution and verification remain distinct calls in the orchestrator.
run_authorization_tests=execute_authorization_tests
