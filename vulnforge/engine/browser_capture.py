"""Bounded, offline HAR import and conservative capture-to-workflow correlation.

This module never sends requests. Captured request/response bodies are omitted;
headers, URLs, and referer data are redacted/scope-filtered before persistence.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qsl, urljoin, urlsplit

from ..core.models import HttpExchange
from ..core.redaction import REDACTED, SENSITIVE_HEADERS, redact_headers, redact_text, redact_url
from .normalize import canonicalize

MAX_HAR_BYTES=25*1024*1024
MAX_HAR_ENTRIES=500
MAX_HEADER_COUNT=100
MAX_HEADER_BYTES=16_384
MAX_URL_LENGTH=8192
MAX_WORKFLOW_SPEC_BYTES=1*1024*1024
MAX_WORKFLOW_TRANSITIONS=100
_SUPPORTED_METHODS={"GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE"}


def load_har(path: str) -> Dict[str, Any]:
    file=Path(path)
    size=file.stat().st_size
    if size>MAX_HAR_BYTES:
        raise ValueError(f"HAR exceeds the {MAX_HAR_BYTES//(1024*1024)} MiB import limit.")
    try:
        doc=json.loads(file.read_text(encoding="utf-8"))
    except (UnicodeError,json.JSONDecodeError,RecursionError) as exc:
        raise ValueError(f"Could not parse HAR JSON: {exc}") from exc
    if not isinstance(doc,dict) or not isinstance(doc.get("log"),dict) or not isinstance(doc["log"].get("entries"),list):
        raise ValueError("Expected a HAR 1.2 document with log.entries.")
    return doc


def load_workflow_spec(path: str) -> Dict[str,Any]:
    file=Path(path)
    if file.stat().st_size>MAX_WORKFLOW_SPEC_BYTES:
        raise ValueError("Workflow spec exceeds the 1 MiB limit.")
    try: doc=json.loads(file.read_text(encoding="utf-8"))
    except (UnicodeError,json.JSONDecodeError,RecursionError) as exc:
        raise ValueError(f"Could not parse workflow JSON: {exc}") from exc
    if not isinstance(doc,dict): raise ValueError("Workflow spec root must be a JSON object.")
    transitions=doc.get("transitions")
    if not isinstance(transitions,list) or len(transitions)>MAX_WORKFLOW_TRANSITIONS:
        raise ValueError(f"Workflow spec must contain a transitions list with at most {MAX_WORKFLOW_TRANSITIONS} items.")
    return doc


def _header_pairs(items, *, sensitive_extra=()):
    pairs=[]; total=0; truncated=False
    sensitive={str(name).lower() for name in SENSITIVE_HEADERS}
    sensitive.update(str(name).lower() for name in sensitive_extra)
    for item in (items if isinstance(items,list) else []):
        if len(pairs)>=MAX_HEADER_COUNT:
            truncated=True; break
        if not isinstance(item,dict): continue
        name=str(item.get("name") or "")[:256]
        value=str(item.get("value") or "")
        if not name or len(name)>256 or any(ord(ch)<0x20 for ch in name): continue
        if total+len(name)+len(value)>MAX_HEADER_BYTES:
            truncated=True; break
        total+=len(name)+len(value)
        secret_name=bool(re.search(r"(?:auth|token|secret|api.?key|cookie|session|credential|csrf|password)",name,re.I))
        safe_value=REDACTED if name.lower() in sensitive or secret_name else redact_text(value)
        if name.lower()=="referer" and "://" in safe_value:
            safe_value=redact_url(safe_value)
        pairs.append([name,safe_value])
    return pairs,truncated


def _headers_dict(pairs):
    result={}
    for name,value in pairs:
        result[name]=value
    return result


def _har_param_names(request: Dict[str,Any]) -> List[str]:
    names=[]
    try:
        names.extend(name for name,_ in parse_qsl(urlsplit(str(request.get("url",""))).query,keep_blank_values=True))
    except ValueError:
        pass
    for item in request.get("queryString",[]) if isinstance(request.get("queryString",[]),list) else []:
        if isinstance(item,dict) and item.get("name"): names.append(str(item["name"]))
    post=request.get("postData",{})
    if isinstance(post,dict):
        for item in post.get("params",[]) if isinstance(post.get("params",[]),list) else []:
            if isinstance(item,dict) and item.get("name"): names.append(str(item["name"]))
        text=post.get("text")
        mime=str(post.get("mimeType","")).lower()
        if isinstance(text,str) and len(text)<=MAX_HEADER_BYTES*4:
            if "application/x-www-form-urlencoded" in mime:
                names.extend(name for name,_ in parse_qsl(text,keep_blank_values=True))
            elif "json" in mime or text.lstrip().startswith(("{","[")):
                try: payload=json.loads(text)
                except (ValueError,TypeError,RecursionError): payload=None
                def walk(value,depth=0):
                    if depth>12: return
                    if isinstance(value,dict):
                        for key,item in value.items():
                            names.append(str(key)); walk(item,depth+1)
                    elif isinstance(value,list):
                        for item in value[:200]: walk(item,depth+1)
                walk(payload)
    return names


def parse_har_document(doc: Dict[str,Any], scope_check: Callable[[str,str],bool], *,
                       excluded_param: Optional[Callable[[str],bool]]=None,
                       capture_id: Optional[str]=None) -> Dict[str,Any]:
    """Convert in-scope HAR entries into redacted exchange records; no replay occurs."""
    entries=doc.get("log",{}).get("entries",[])
    if not isinstance(entries,list): raise ValueError("HAR log.entries must be a list.")
    if len(entries)>MAX_HAR_ENTRIES:
        raise ValueError(f"HAR has {len(entries)} entries; limit is {MAX_HAR_ENTRIES}.")
    capture_id=capture_id or ("capture-"+uuid.uuid4().hex[:16])
    exchanges=[]
    counts={"entries_seen":len(entries),"imported":0,"scope_rejected":0,
            "method_rejected":0,"excluded_parameter":0,"malformed":0,
            "headers_truncated":0,"request_body_bytes_omitted":0,
            "response_body_bytes_omitted":0}
    for index,entry in enumerate(entries):
        if not isinstance(entry,dict) or not isinstance(entry.get("request"),dict) or not isinstance(entry.get("response"),dict):
            counts["malformed"]+=1; continue
        request=entry["request"]; response=entry["response"]
        method=str(request.get("method") or "GET").upper()
        raw_url=str(request.get("url") or "")
        if (method not in _SUPPORTED_METHODS or not raw_url or len(raw_url)>MAX_URL_LENGTH):
            counts["malformed"]+=1; continue
        try:
            parts=urlsplit(raw_url)
            valid=parts.scheme.lower() in ("http","https") and bool(parts.hostname) and not (parts.username or parts.password)
            _=parts.port
        except ValueError:
            valid=False
        if not valid:
            counts["malformed"]+=1; continue
        try:
            if not scope_check(raw_url,method):
                counts["scope_rejected"]+=1; continue
        except Exception:
            counts["scope_rejected"]+=1; continue
        if excluded_param and any(excluded_param(name) for name in _har_param_names(request)):
            counts["excluded_parameter"]+=1; continue

        req_pairs,req_truncated=_header_pairs(request.get("headers",[]))
        res_pairs,res_truncated=_header_pairs(response.get("headers",[]))
        raw_referer=next((str(item.get("value") or "") for item in request.get("headers",[])
            if isinstance(item,dict) and str(item.get("name","")).lower()=="referer"),"")
        safe_referer=""
        if raw_referer:
            try:
                ref=urlsplit(raw_referer)
                if ref.scheme.lower() in ("http","https") and ref.hostname and not(ref.username or ref.password) and scope_check(raw_referer,"GET"):
                    safe_referer=redact_url(raw_referer)
            except Exception:
                safe_referer=""
        for pair in req_pairs:
            if pair[0].lower()=="referer": pair[1]=safe_referer or REDACTED
        for pair in res_pairs:
            if pair[0].lower()=="location":
                destination=urljoin(raw_url,pair[1])
                try: in_scope=scope_check(destination,"GET")
                except Exception: in_scope=False
                pair[1]=redact_url(destination) if in_scope else REDACTED
        if req_truncated or res_truncated: counts["headers_truncated"]+=1
        request_headers=_headers_dict(req_pairs); response_headers=_headers_dict(res_pairs)
        # Capture bodies can contain credentials, personal data, and CSRF tokens.
        # Keep byte counts only; never persist body contents from a browser HAR.
        post=request.get("postData",{})
        post_size=len(str(post.get("text") or "").encode("utf-8","replace")) if isinstance(post,dict) else 0
        content=response.get("content",{})
        body_size=0
        if isinstance(content,dict):
            raw_body=content.get("text")
            if isinstance(raw_body,str): body_size=len(raw_body.encode("utf-8","replace"))
            try: body_size=max(body_size,int(content.get("size",0) or 0))
            except (ValueError,TypeError): pass
        counts["request_body_bytes_omitted"]+=post_size
        counts["response_body_bytes_omitted"]+=body_size
        try: status=int(response.get("status",0) or 0)
        except (ValueError,TypeError): status=0
        if status<0 or status>599: status=0
        try: duration=float(entry.get("time",0) or 0)
        except (ValueError,TypeError): duration=0.0
        ex=HttpExchange(method=method,url=redact_url(raw_url),request_headers=redact_headers(request_headers),
            request_header_items=req_pairs,status=status,response_headers=redact_headers(response_headers),
            response_header_items=res_pairs,duration_ms=max(0.0,duration),module="browser-capture",
            exchange_id="capture-ex-"+hashlib.sha256(f"{capture_id}:{index}:{raw_url}".encode()).hexdigest()[:16])
        doc_record=ex.to_dict()
        resource_type=str(entry.get("_resourceType") or request.get("_resourceType") or "unknown")[:40].lower()
        mime_type=str(content.get("mimeType") or "")[:200] if isinstance(content,dict) else ""
        doc_record.update({"capture_id":capture_id,"capture_index":index,
            "capture_started_at":str(entry.get("startedDateTime") or "")[:80],
            "capture_page_ref":str(entry.get("pageref") or "")[:128],
            "capture_resource_type":resource_type,"capture_response_mime":mime_type,
            "capture_referer_url":safe_referer,"capture_bodies_stored":False,
            "capture_request_body_bytes_omitted":post_size,
            "capture_response_body_bytes_omitted":body_size,
            "capture_redaction":"URLs and sensitive headers redacted; bodies omitted entirely"})
        exchanges.append(doc_record)
        counts["imported"]+=1
    return {"capture_id":capture_id,"source_format":"HAR 1.2",
        "body_policy":"OMITTED","summary":counts,"exchanges":exchanges}


def correlate_capture_workflow(workflow_model: Dict[str,Any], exchanges: List[Dict[str,Any]]) -> Dict[str,Any]:
    """Record in-capture Referer/request associations without claiming causal or security proof."""
    states=workflow_model.get("states",[]) if isinstance(workflow_model,dict) else []
    state_by_url={canonicalize(redact_url(str(s.get("url",""))),drop_tracking=False):s.get("state_id","")
                  for s in states if isinstance(s,dict) and s.get("url")}
    edges=workflow_model.get("transitions",[]) if isinstance(workflow_model,dict) else []
    edge_keys={}
    for edge in edges:
        if not isinstance(edge,dict): continue
        edge_keys[(edge.get("source_state_id", ""),canonicalize(redact_url(str(edge.get("target_url",""))),drop_tracking=False),
                   str(edge.get("method","GET")).upper())]=edge.get("transition_id","")
    observations=[]
    for exchange in exchanges:
        resource=str(exchange.get("capture_resource_type","unknown")).lower()
        content_type=str(exchange.get("capture_response_mime","")).lower()
        if resource!="document" and not content_type.startswith("text/html"):
            continue
        target=canonicalize(redact_url(str(exchange.get("url",""))),drop_tracking=False)
        source=str(exchange.get("capture_referer_url") or "")
        if not source: continue
        source_key=canonicalize(source,drop_tracking=False)
        source_state=state_by_url.get(source_key,"")
        target_state=state_by_url.get(target,"")
        method=str(exchange.get("method","GET")).upper()
        match_id=edge_keys.get((source_state,target,method),"") if source_state else ""
        observations.append({"observation_id":"capture-flow-"+hashlib.sha256(
                f"{exchange.get('capture_id')}:{exchange.get('exchange_id')}:{source_key}:{target}".encode()).hexdigest()[:12],
            "source_url":source,"target_url":str(exchange.get("url","")),"method":method,
            "source_state_id":source_state,"target_state_id":target_state,
            "static_transition_id":match_id,
            "status":"CAPTURE_SEQUENCE_OBSERVED_NOT_VERIFIED",
            "exchange_ids":[str(exchange.get("exchange_id",""))],
            "causal_user_action_proven":False,"security_property_verified":False})
    return {"status":"CAPTURE_SEQUENCE_OBSERVATIONS_ONLY","observations":observations,
        "summary":{"document_requests_with_in_scope_referer":len(observations),
            "matched_static_transitions":sum(bool(x["static_transition_id"]) for x in observations),
            "security_properties_verified":0,"causal_user_actions_proven":0},
        "limitations":["HAR chronology and Referer headers do not prove which UI action caused a request.",
            "Imported traffic is corroborating observation only; it does not promote hypotheses or findings.",
            "Bodies are omitted and no captured request is replayed."]}


def validate_configured_workflow(spec: Dict[str,Any], exchanges: List[Dict[str,Any]],
                                 scope_check: Callable[[str,str],bool], *, base_url: str,
                                 excluded_param: Optional[Callable[[str],bool]]=None) -> Dict[str,Any]:
    """Check declared transitions against imported capture records, never by replay."""
    transitions=spec.get("transitions")
    if not isinstance(transitions,list) or len(transitions)>MAX_WORKFLOW_TRANSITIONS:
        raise ValueError(f"Workflow spec requires at most {MAX_WORKFLOW_TRANSITIONS} transitions.")
    workflow_id=str(spec.get("workflow_id") or "user-workflow")[:128]
    results=[]
    for index,item in enumerate(transitions):
        if not isinstance(item,dict):
            results.append({"transition_id":f"transition-{index+1}","status":"INVALID_SPEC"}); continue
        transition_id=str(item.get("transition_id") or f"transition-{index+1}")[:128]
        method=str(item.get("method") or "GET").upper()
        raw_from=str(item.get("from") or "")
        raw_to=str(item.get("to") or "")
        if method not in _SUPPORTED_METHODS or not raw_from or not raw_to or len(raw_from)>MAX_URL_LENGTH or len(raw_to)>MAX_URL_LENGTH:
            results.append({"transition_id":transition_id,"status":"INVALID_SPEC"}); continue
        source=urljoin(base_url,raw_from); target=urljoin(base_url,raw_to)
        try:
            source_parts=urlsplit(source); target_parts=urlsplit(target)
            if any(p.username or p.password for p in (source_parts,target_parts)) or any(p.scheme.lower() not in ("http","https") for p in (source_parts,target_parts)):
                raise ValueError
            in_scope=scope_check(source,"GET") and scope_check(target,method)
        except Exception:
            in_scope=False
        if excluded_param:
            for url in (source,target):
                try: names=[name for name,_ in parse_qsl(urlsplit(url).query,keep_blank_values=True)]
                except ValueError: names=[]
                if any(excluded_param(name) for name in names): in_scope=False
        if not in_scope:
            results.append({"transition_id":transition_id,"from":redact_url(source),"to":redact_url(target),
                "method":method,"status":"BLOCKED_BY_SAVED_SCOPE","matched_exchange_ids":[],
                "security_property_verified":False}); continue
        source_key=canonicalize(redact_url(source),drop_tracking=False)
        target_key=canonicalize(redact_url(target),drop_tracking=False)
        expected=item.get("expected_status",[])
        if isinstance(expected,int): expected=[expected]
        if not isinstance(expected,list) or not expected or len(expected)>10 or any(not isinstance(code,int) or code<100 or code>599 for code in expected):
            results.append({"transition_id":transition_id,"from":redact_url(source),"to":redact_url(target),
                "method":method,"status":"INVALID_EXPECTED_STATUS","matched_exchange_ids":[],
                "security_property_verified":False}); continue
        matches=[]
        for exchange in exchanges:
            if str(exchange.get("method","")).upper()!=method: continue
            if canonicalize(redact_url(str(exchange.get("url",""))),drop_tracking=False)!=target_key: continue
            referer=str(exchange.get("capture_referer_url") or "")
            if not referer or canonicalize(referer,drop_tracking=False)!=source_key: continue
            matches.append(exchange)
        matched_ids=[str(ex.get("exchange_id","")) for ex in matches]
        statuses=[int(ex.get("status",0) or 0) for ex in matches]
        if not matches: status="NOT_OBSERVED_IN_CAPTURE"
        elif all(code in expected for code in statuses): status="OBSERVED_EXPECTED_STATUS"
        else: status="OBSERVED_UNEXPECTED_STATUS"
        results.append({"transition_id":transition_id,"from":redact_url(source),"to":redact_url(target),
            "method":method,"expected_status":expected,"observed_statuses":statuses,
            "matched_exchange_ids":matched_ids,"status":status,
            "security_property_verified":False,"impact_proven":False})
    return {"workflow_id":workflow_id,"status":"CAPTURE_EVIDENCE_ONLY",
        "transitions":results,"summary":{"declared":len(transitions),
            "observed_expected_status":sum(x.get("status")=="OBSERVED_EXPECTED_STATUS" for x in results),
            "observed_unexpected_status":sum(x.get("status")=="OBSERVED_UNEXPECTED_STATUS" for x in results),
            "not_observed":sum(x.get("status")=="NOT_OBSERVED_IN_CAPTURE" for x in results),
            "blocked_or_invalid":sum(x.get("status") in {"BLOCKED_BY_SAVED_SCOPE","INVALID_SPEC","INVALID_EXPECTED_STATUS"} for x in results),
            "requests_replayed":0,"security_properties_verified":0},
        "limitations":["Assertions describe imported HAR records only; capture cannot prove the request was caused by a specific UI action.",
            "Matching status codes do not prove business success, authorization correctness, or impact.",
            "No requests were issued or replayed by VulnForge."]}
