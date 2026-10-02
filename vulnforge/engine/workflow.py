"""Offline static workflow/navigation observations; never submits forms or follows links."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any, Dict, List
from urllib.parse import urljoin

from .normalize import canonicalize


def _digest(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:12]


def build_workflow_model(ctx, *, max_states: int = 250, max_transitions: int = 1000) -> Dict[str, Any]:
    """Model fetched HTML views plus markup-declared links/forms as unexecuted leads.

    Only pages fetched by the scope-gated crawler are states. Link/form targets are
    represented only when the same-scan inventory marks them in scope. This is a
    static navigation map, not a browser session, server-side state machine, or
    proof that a transition succeeds.
    """
    max_states=max(0,int(max_states)); max_transitions=max(0,int(max_transitions))
    crawl=getattr(ctx,"_crawl_result",None)
    parsed=list(getattr(crawl,"parsed",[]) or [])
    endpoints=list(getattr(ctx,"endpoints",{}).values())
    endpoint_scope=defaultdict(list)
    for endpoint in endpoints:
        if getattr(endpoint,"scope_status","")=="IN_SCOPE":
            endpoint_scope[canonicalize(str(endpoint.url),drop_tracking=False)].append(endpoint)

    parsed=sorted(parsed,key=lambda pair:(canonicalize(pair[0].url,drop_tracking=False),pair[0].exchange_id))
    states=[]; state_by_url={}; page_by_id={}; omitted_states=0
    for page,parser in parsed:
        page_url=canonicalize(str(page.url),drop_tracking=False)
        if page_url in state_by_url:
            continue
        if len(states)>=max_states:
            omitted_states+=1
            continue
        state_id="view-"+_digest(page_url)
        state={"state_id":state_id,"state_type":"OBSERVED_HTTP_VIEW","url":str(page.url),
            "method":"GET","http_status":int(getattr(page,"status",0) or 0),
            "title":str(getattr(parser,"title","") or "")[:200],
            "content_type":str(page.header("content-type") or ""),
            "authentication_state":"UNKNOWN","application_state":"NOT_INFERRED",
            "provenance":"SCOPE_GATED_STATIC_CRAWL","evidence_ids":[str(page.exchange_id)]}
        states.append(state); state_by_url[page_url]=state_id; page_by_id[str(page.exchange_id)]=(page,parser)

    transitions=[]; seen=set(); omitted_transitions=0
    def add_transition(record):
        nonlocal omitted_transitions
        key=(record["transition_type"],record["source_state_id"],record.get("target_url",""),record.get("method",""),
             tuple(record.get("field_names",[])))
        if key in seen: return
        seen.add(key)
        if len(transitions)>=max_transitions:
            omitted_transitions+=1
            return
        transitions.append(record)

    for page,parser in parsed:
        source_url=canonicalize(str(page.url),drop_tracking=False)
        source_id=state_by_url.get(source_url)
        if not source_id:
            continue
        source_evidence=[str(page.exchange_id)]
        for raw_target in sorted(set(getattr(parser,"links",[]) or [])):
            target_url=canonicalize(str(raw_target),drop_tracking=False)
            scoped_get=any(str(getattr(ep,"method","GET")).upper()=="GET"
                           for ep in endpoint_scope.get(target_url,[]))
            if not scoped_get and target_url not in state_by_url:
                continue
            target_state=state_by_url.get(target_url,"")
            add_transition({"transition_id":"nav-"+_digest("link\0"+source_id+"\0"+target_url),
                "transition_type":"ANCHOR_REFERENCE","source_state_id":source_id,
                "target_state_id":target_state,"target_url":str(raw_target),"method":"GET",
                "status":"LINK_DECLARED_NOT_EXECUTED" if target_state else "LINK_TO_UNOBSERVED_IN_SCOPE_ENDPOINT",
                "evidence_ids":source_evidence,
                "destination_evidence_ids":([str(state["evidence_ids"][0]) for state in states if state["state_id"]==target_state]
                    if target_state else [])})
        for form in list(getattr(parser,"forms",[]) or []):
            method=str(form.get("method") or "GET").upper()
            raw_action=str(form.get("action") or page.url)
            resolved_action=urljoin(str(page.url),raw_action)
            action=canonicalize(resolved_action,drop_tracking=False)
            matching=[ep for ep in endpoint_scope.get(action,[]) if str(getattr(ep,"method","GET")).upper()==method]
            if not matching:
                continue
            target_state=state_by_url.get(action,"") if method=="GET" else ""
            field_names=[]
            for field in list(form.get("fields",[]) or []):
                name=str(field.get("name") or "").strip()
                if name and name not in field_names and len(field_names)<100:
                    field_names.append(name[:128])
            add_transition({"transition_id":"form-"+_digest("form\0"+source_id+"\0"+method+"\0"+action),
                "transition_type":"FORM_DECLARATION","source_state_id":source_id,
                "target_state_id":target_state,"target_url":resolved_action,"declared_action":raw_action,"method":method,
                "status":"FORM_DECLARED_NOT_SUBMITTED","field_names":field_names,
                "state_change_possible":method not in ("GET","HEAD","OPTIONS"),
                "evidence_ids":source_evidence,
                "destination_evidence_ids":([str(state["evidence_ids"][0]) for state in states if state["state_id"]==target_state]
                    if target_state else [])})

    transitions.sort(key=lambda item:(item["source_state_id"],item["transition_type"],item.get("target_url",""),item.get("method","")))
    return {"model_id":"workflow-"+_digest(str(getattr(ctx,"scan_id",""))),
        "status":"STATIC_OBSERVATIONS_ONLY","states":states,"transitions":transitions,
        "summary":{"observed_views":len(states),
            "link_references":sum(item["transition_type"]=="ANCHOR_REFERENCE" for item in transitions),
            "form_declarations":sum(item["transition_type"]=="FORM_DECLARATION" for item in transitions),
            "executed_transitions":0,"server_side_states_inferred":0,
            "omitted_states_due_to_limit":omitted_states,"omitted_transitions_due_to_limit":omitted_transitions},
        "limitations":["Links and forms are markup declarations; no browser navigation or form submission was performed.",
            "Authentication/session state and server-side workflow state remain UNKNOWN.",
            "A mapped edge does not prove that a user can traverse it or that the destination accepts the request."],
        "source":"same-scan scope-gated static crawl and in-scope endpoint inventory"}
