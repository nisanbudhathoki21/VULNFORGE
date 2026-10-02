from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.store import Store
from vulnforge.engine.orchestrator import ScanConfig, run_scan


def test_explicit_cross_account_test_verifies_and_redacts(mock_server,tmp_path):
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="lab",allow_private=True,confirmed=True)
    auth_data={"identities":{"owner":{"headers":{"X-Lab-User":"alice"}},
                              "other":{"headers":{"X-Lab-User":"bob"}}},
        "authorization_tests":[{"url":"/authz/orders?id=1","owner_identity":"owner",
          "other_identity":"other","owner_field":"owner","owner_value":"alice",
          "identity_assertion":{"header":"X-Lab-Principal","owner_value":"alice","other_value":"bob"},
          "sensitive_fields":["email"]}]}
    cfg=ScanConfig(target=mock_server,profile_name="lab",allowed_hosts=["127.0.0.1"],allow_private=True,
       authorization_confirmed=True,active_requested=True,auth_data=auth_data,test_profile="critical")
    result=run_scan(cfg,auth)
    verified=[f for f in result.context.verified_findings if f.status=="VERIFIED"]
    assert len(verified)==1
    assert verified[0].category=="authorization / BOLA"
    assert verified[0].state=="VERIFIED"
    assert "alice@example.test" not in str(verified[0].to_dict())
    assert result.context.tests[0]["status"]=="VERIFIED"
    assert next(h for h in result.context.hypotheses if h.category=="object-level-authorization").status=="VERIFIED"
    phases={p.phase_id:p.status for p in result.context.phases}
    assert phases["phase-10"]=="PARTIAL" and phases["phase-11"]=="PARTIAL"
    assert phases["phase-13"]=="COMPLETE" and phases["phase-14"]=="COMPLETE"
    store=Store(str(tmp_path/"verify.db")); store.save_scan(result)
    chain=store.get_evidence_chain(verified[0].id)
    assert chain and chain[0]["test"]["status"]=="VERIFIED"
    assert chain[0]["test"]["hypothesis_id"]==verified[0].evidence[0].detail["hypothesis_id"]
    doc=store.get_report(result.context.scan_id)
    assert len(doc["phases"])==15 and doc["phases"][9]["status"]=="PARTIAL"
    assert doc["test_plan"][0]["status"]=="EXECUTED"
    assert doc["scan"]["test_profile"]=="critical"
    bola=next(row for row in doc["vulnerability_matrix"] if row["class_id"]=="bola")
    ssrf_row=next(row for row in doc["vulnerability_matrix"] if row["class_id"]=="ssrf")
    assert bola["selected"] and bola["status"]=="CONFIRMED" and bola["executed"]==1
    assert ssrf_row["selected"] and ssrf_row["supported"] is True and ssrf_row["status"] in {"TESTED_CLEAN","OBSERVATION_ONLY","NO_TEST_SURFACE"}
    assert doc["security_properties"] and doc["actors"] and doc["resources"]
    assert doc["application_model"] and doc["risk_summary"]["verified_total"]==1
    assert len(doc["findings"])==1 and doc["findings"][0]["status"]=="VERIFIED"
    assert doc["report_manifest"]["verified_finding_ids"]==[verified[0].id]
    assert doc["asset_nodes"] and next(h for h in doc["hypotheses"] if h["category"]=="object-level-authorization")["status"]=="VERIFIED"
    assert len(chain[0]["exchanges"]) == 3
    assert all("alice@example.test" not in str(x) for x in chain[0]["exchanges"])
    import sqlite3
    con=sqlite3.connect(tmp_path/"verify.db")
    raw=" ".join(r[0] for r in con.execute("select data_json from exchanges where url like '%/authz/orders%'"))
    assert "alice@example.test" not in raw and '"x-lab-user":"alice"' not in raw


def test_authorization_plan_is_blocked_without_explicit_active_mode(mock_server):
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="lab",allow_private=True,confirmed=True)
    auth_data={"identities":{"owner":{"headers":{"X-Lab-User":"alice"}},
                              "other":{"headers":{"X-Lab-User":"bob"}}},
        "authorization_tests":[{"url":"/authz/orders?id=1","owner_identity":"owner",
          "other_identity":"other","owner_field":"owner","owner_value":"alice",
          "identity_assertion":{"header":"X-Lab-Principal","owner_value":"alice","other_value":"bob"},
          "sensitive_fields":["email"]}]}
    cfg=ScanConfig(target=mock_server,profile_name="lab",allowed_hosts=["127.0.0.1"],allow_private=True,
       authorization_confirmed=True,active_requested=False,auth_data=auth_data)
    result=run_scan(cfg,auth)
    assert not result.context.tests
    assert result.context.test_plan
    assert all(plan.status=="BLOCKED" for plan in result.context.test_plan)
    assert any(plan.test_type=="cross-account-object-authorization" for plan in result.context.test_plan)
    assert any(plan.test_type=="sql-injection-validation" for plan in result.context.test_plan)
    authz=next(x for x in result.context.coverage if x["category"]=="Object-level authorization")
    assert authz["status"]=="BLOCKED"
    assert not result.context.verified_findings
    assert all(f.status!="VERIFIED" for f in result.context.findings)
