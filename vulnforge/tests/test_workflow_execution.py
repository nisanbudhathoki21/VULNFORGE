from vulnforge.core.authorization import AuthorizationContext
from vulnforge.engine.orchestrator import ScanConfig, run_scan
from vulnforge.engine.workflow_execution import plan_read_only_workflows


def test_workflow_planner_blocks_unsafe_methods_out_of_scope_and_budget_overflow():
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],allowed_methods=["GET"],
        profile_name="lab",allow_private=True,confirmed=True)
    specs=[
        {"workflow_id":"okay","steps":[{"url":"/about","method":"GET"}]},
        {"workflow_id":"mutating","steps":[{"url":"/save","method":"POST"}]},
        {"workflow_id":"external","steps":[{"url":"https://outside.example/x","method":"GET"}]},
        {"workflow_id":"too-many-steps","steps":[{"url":"/a"},{"url":"/b"}]},
    ]
    plans,runnable,reserved,errors=plan_read_only_workflows(specs,"http://127.0.0.1/",auth,
        can_run=True,available_requests=2)
    assert [item.test_id.removeprefix("test-workflow-") for item in plans]==["okay","external","too-many-steps"]
    assert plans[0].status=="PLANNED"
    assert plans[1].status=="BLOCKED"
    assert plans[2].status=="BLOCKED" # complete workflow is reserved all-or-nothing
    assert [item["workflow_id"] for item in runnable]==["okay"]
    assert reserved==1
    assert errors and "only GET, HEAD, and OPTIONS" in errors[0]


def test_pipeline_runs_only_explicit_read_only_steps_through_requester(mock_server):
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],allowed_methods=["GET"],
        profile_name="lab",allow_private=True,confirmed=True)
    config=ScanConfig(target=mock_server,profile_name="lab",allowed_hosts=["127.0.0.1"],
        allowed_methods=["GET"],allow_private=True,authorization_confirmed=True,
        active_requested=True,test_profile="critical",auth_data={"workflow_tests":[
            {"workflow_id":"home-to-about","steps":[
                {"step_id":"home","url":"/","method":"GET","expected_status":200},
                {"step_id":"about","url":"/about","method":"GET","expected_status":[200]}]},
            {"workflow_id":"fixed-redirect-control","steps":[
                {"url":"/redirect","method":"GET","expected_status":302},
                {"url":"/about","method":"GET","expected_status":200}]},
            {"workflow_id":"blocked-external","steps":[
                {"url":"https://outside.example/","method":"GET","expected_status":200}]},
            {"workflow_id":"not-allowed-method","steps":[
                {"url":"/authz/orders","method":"POST"}]},
        ]})
    result=run_scan(config,auth)
    records=[item for item in result.context.tests if item.get("type")=="configured-read-only-workflow"]
    assert len(records)==2
    assert [item["status"] for item in records]==["OBSERVED","OBSERVED"]
    assert all(item["security_property_verified"] is False and item["finding_promoted"] is False for item in records)
    assert all(all(step["status"] in {"OBSERVED","OBSERVED_EXPECTED_STATUS"} for step in item["steps"]) for item in records)
    assert all(step["redirect_followed"] is False for item in records for step in item["steps"])
    assert all("outside.example" not in ex.url for ex in result.context.requester.exchanges)
    plans=[item for item in result.context.test_plan if item.test_type=="configured-read-only-workflow"]
    assert len(plans)==3
    assert [item.status for item in plans]==["EXECUTED","EXECUTED","BLOCKED"]
    assert any("only GET, HEAD, and OPTIONS" in error for error in result.context.workflow_plan_errors)
    assert result.context.requester.budget.sent<=result.context.requester.budget.max_requests
    from vulnforge.report.json_report import build_report_dict
    report=build_report_dict(result)
    assert report["configured_workflow_summary"]["records"]==2
    assert report["configured_workflow_summary"]["security_properties_verified"]==0


def test_configured_workflows_are_blocked_without_active_mode():
    auth=AuthorizationContext(allowed_hosts=["example.test"],allowed_methods=["GET"],
        profile_name="standard",confirmed=True)
    plans,runnable,reserved,errors=plan_read_only_workflows(
        [{"workflow_id":"read-only","steps":[{"url":"/health"}]}],
        "https://example.test/",auth,can_run=False,available_requests=10)
    assert not errors and not runnable and reserved==0
    assert len(plans)==1 and plans[0].status=="BLOCKED"
