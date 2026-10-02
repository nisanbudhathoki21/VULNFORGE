"""Bounded parser for observed JSON OpenAPI and Swagger documents.

Schema content is treated as an untrusted declaration: local references only
are resolved, remote references are never fetched, and operations are never
sent or promoted to observed endpoints by this module.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

_HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
_MAX_OPERATIONS = 2000
_MAX_PARAMETERS = 100


def _resolve_local_ref(document: Dict[str, Any], ref: Any) -> Optional[Dict[str, Any]]:
    """Resolve a bounded JSON Pointer within this document only."""
    if not isinstance(ref, str) or not ref.startswith("#/") or len(ref) > 512:
        return None
    current: Any = document
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or token not in current:
            return None
        current = current[token]
    return current if isinstance(current, dict) else None


def _inline(document: Dict[str, Any], item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    ref = item.get("$ref")
    if ref:
        return _resolve_local_ref(document, ref) or {}
    return item


def _schema_type(document: Dict[str, Any], schema: Any) -> str:
    if not isinstance(schema, dict):
        return "unknown"
    if "$ref" in schema:
        schema = _resolve_local_ref(document, schema["$ref"]) or {}
    values = schema.get("type")
    if isinstance(values, list):
        return "|".join(str(x)[:32] for x in values[:8]) or "unknown"
    if isinstance(values, str):
        return values[:64]
    if "properties" in schema:
        return "object"
    if "items" in schema:
        return "array"
    return "unknown"


def parse_openapi_json(body: str, *, document_url: str, exchange_id: str = "") -> Dict[str, Any]:
    """Parse JSON OpenAPI 3.x / Swagger 2.0 into a bounded declaration model.

    Invalid and unsupported documents return an explicit status and no
    operations. Descriptions, examples, default values, server URLs, and
    credentials are intentionally omitted from the normalized model.
    """
    result: Dict[str, Any] = {
        "document_url": document_url,
        "exchange_id": exchange_id,
        "format": "UNKNOWN",
        "status": "INVALID_OR_UNSUPPORTED",
        "validation_status": "DECLARED_NOT_VALIDATED",
        "operations": [],
        "warnings": [],
    }
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, TypeError, RecursionError):
        result["warnings"].append("Document is not valid JSON; YAML and other formats are unsupported.")
        return result
    if not isinstance(doc, dict):
        result["warnings"].append("Document root is not a JSON object.")
        return result
    if isinstance(doc.get("openapi"), str) and doc["openapi"].startswith("3."):
        version = "OpenAPI " + doc["openapi"][:32]
        swagger2 = False
    elif doc.get("swagger") == "2.0":
        version = "Swagger 2.0"
        swagger2 = True
    else:
        result["warnings"].append("No supported OpenAPI 3.x or Swagger 2.0 version marker was found.")
        return result

    paths = doc.get("paths")
    if not isinstance(paths, dict):
        result["format"] = version
        result["warnings"].append("Document has no paths object.")
        return result

    result["format"] = version
    result["status"] = "PARSED"
    result["warnings"].append("Declarations are not proof that an operation is reachable or implemented.")
    operations: List[Dict[str, Any]] = []
    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/") or len(raw_path) > 2048:
            continue
        if not isinstance(path_item, dict):
            continue
        path_item = _inline(doc, path_item)
        path_parameters = path_item.get("parameters", [])
        if not isinstance(path_parameters, list):
            path_parameters = []
        for method, operation in path_item.items():
            method = str(method).lower()
            if method not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            parameters: Dict[tuple, Dict[str, Any]] = {}
            for raw_param in (path_parameters + (operation.get("parameters", []) if isinstance(operation.get("parameters", []), list) else []))[:_MAX_PARAMETERS]:
                param = _inline(doc, raw_param)
                name, location = param.get("name"), param.get("in")
                if not isinstance(name, str) or not isinstance(location, str):
                    continue
                allowed_locations={"path", "query", "header", "cookie"}
                if swagger2: allowed_locations.add("body")
                if location not in allowed_locations:
                    continue
                schema = param.get("schema")
                if swagger2 and location == "body":
                    schema = param.get("schema")
                parameters[(name, location)] = {
                    "name": name[:200], "in": location,
                    "required": bool(param.get("required", False)),
                    "type": _schema_type(doc, schema),
                    "source": "OpenAPI declaration",
                }
            request_content_types: List[str] = []
            request_body = operation.get("requestBody")
            if isinstance(request_body, dict):
                request_body = _inline(doc, request_body)
                content = request_body.get("content", {})
                if isinstance(content, dict):
                    request_content_types.extend(str(x)[:128] for x in list(content)[:32])
            elif swagger2:
                for param in operation.get("parameters", []) if isinstance(operation.get("parameters", []), list) else []:
                    param = _inline(doc, param)
                    if param.get("in") == "body":
                        request_content_types.extend(str(x)[:128] for x in doc.get("consumes", [])[:32] if isinstance(x, str))
            responses = operation.get("responses", {})
            response_codes = sorted(str(x)[:32] for x in responses)[:64] if isinstance(responses, dict) else []
            response_types = set()
            if isinstance(responses, dict):
                for response in responses.values():
                    response = _inline(doc, response)
                    content = response.get("content", {}) if isinstance(response, dict) else {}
                    if isinstance(content, dict):
                        response_types.update(str(x)[:128] for x in list(content)[:32])
            if swagger2:
                response_types.update(str(x)[:128] for x in doc.get("produces", [])[:32] if isinstance(x, str))
            operations.append({
                "method": method.upper(),
                "path": raw_path,
                "operation_id": str(operation.get("operationId", ""))[:200],
                "parameters": list(parameters.values()),
                "request_content_types": sorted(set(request_content_types)),
                "response_codes": response_codes,
                "response_content_types": sorted(response_types),
                "source": "observed OpenAPI document",
                "validation_status": "DECLARED_NOT_VALIDATED",
            })
            if len(operations) >= _MAX_OPERATIONS:
                result["warnings"].append(f"Operation list capped at {_MAX_OPERATIONS} entries.")
                break
        if len(operations) >= _MAX_OPERATIONS:
            break
    result["operations"] = operations
    return result
