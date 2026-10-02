from types import SimpleNamespace

from vulnforge.core.models import Endpoint, HttpExchange
from vulnforge.engine.crawler import PageParser
from vulnforge.engine.workflow import build_workflow_model


def _page(url, body, exchange_id):
    exchange=HttpExchange(method="GET",url=url,status=200,
        response_headers={"content-type":"text/html"},response_body=body,
        exchange_id=exchange_id)
    parser=PageParser(url)
    parser.feed(body)
    parser.close()
    return exchange,parser


def test_static_workflow_map_distinguishes_markup_references_from_executed_steps():
    home="http://example.test/"
    next_url="http://example.test/next"
    update_url="http://example.test/account/update"
    excluded_url="http://example.test/private"
    home_page,home_parser=_page(home,
        '<title>Home</title><a href="/next">Next</a><a href="/private">Private</a>'
        '<a href="https://outside.test/">External</a>'
        '<form method="post" action="/account/update"><input name="username" value="alice">'
        '<input name="csrf" value="secret-token"></form>',"exchange-home")
    next_page,next_parser=_page(next_url,"<title>Next page</title>","exchange-next")
    ctx=SimpleNamespace(scan_id="scan-workflow",
        _crawl_result=SimpleNamespace(parsed=[(home_page,home_parser),(next_page,next_parser)]),
        endpoints={
            "home":Endpoint(url=home,normalized=home,scope_status="IN_SCOPE"),
            "next":Endpoint(url=next_url,normalized=next_url,scope_status="IN_SCOPE"),
            "update":Endpoint(url=update_url,normalized=update_url,method="POST",scope_status="IN_SCOPE"),
            "private":Endpoint(url=excluded_url,normalized=excluded_url,scope_status="OUT_OF_SCOPE"),
        })

    model=build_workflow_model(ctx)
    assert model["status"]=="STATIC_OBSERVATIONS_ONLY"
    assert model["summary"]["observed_views"]==2
    assert model["summary"]["executed_transitions"]==0
    assert model["summary"]["server_side_states_inferred"]==0
    home_state=next(state for state in model["states"] if state["url"]==home)
    assert home_state["authentication_state"]=="UNKNOWN"
    assert home_state["application_state"]=="NOT_INFERRED"

    link=next(item for item in model["transitions"] if item["transition_type"]=="ANCHOR_REFERENCE")
    form=next(item for item in model["transitions"] if item["transition_type"]=="FORM_DECLARATION")
    assert link["target_state_id"]
    assert link["status"]=="LINK_DECLARED_NOT_EXECUTED"
    assert form["method"]=="POST"
    assert form["status"]=="FORM_DECLARED_NOT_SUBMITTED"
    assert form["state_change_possible"] is True
    assert set(form["field_names"])=={"username","csrf"}
    assert "secret-token" not in repr(model)
    assert all("private" not in item.get("target_url","") for item in model["transitions"])
    assert all("outside.test" not in item.get("target_url","") for item in model["transitions"])
    assert model["limitations"]


def test_static_workflow_model_enforces_output_limits():
    first,first_parser=_page("http://example.test/","<a href='/b'>B</a>","exchange-1")
    second,second_parser=_page("http://example.test/b","<a href='/'>Home</a>","exchange-2")
    ctx=SimpleNamespace(scan_id="scan-limits",
        _crawl_result=SimpleNamespace(parsed=[(first,first_parser),(second,second_parser)]),
        endpoints={"a":Endpoint(url=first.url,normalized=first.url,scope_status="IN_SCOPE"),
                   "b":Endpoint(url=second.url,normalized=second.url,scope_status="IN_SCOPE")})
    model=build_workflow_model(ctx,max_states=1,max_transitions=1)
    assert len(model["states"])==1
    assert len(model["transitions"])<=1
    assert model["summary"]["omitted_states_due_to_limit"]==1
