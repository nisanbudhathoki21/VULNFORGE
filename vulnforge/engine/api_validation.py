"""
VulnForge API contract validation.

Purpose:
    Convert declared OpenAPI/Swagger operations into bounded, evidence-backed
    reachability observations.

Security properties:
    - Every request uses the canonical Requester.
    - No direct network access.
    - Scope and request budgets remain enforced by Requester.
    - Destructive methods are not automatically invoked.
    - OpenAPI examples/defaults are never copied into requests.
    - A declaration is never promoted to an observed endpoint without HTTP
      evidence.
    - Authentication requirements are classified separately from reachability.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit


SAFE_READ_METHODS = {"GET", "HEAD", "OPTIONS"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE", "TRACE"}

_MAX_OPERATIONS = 100
_MAX_QUERY_PARAMS = 12
_MAX_PATH_PARAMS = 12


def _safe_placeholder(param: Dict[str, Any]) -> str:
    """
    Return a deterministic, non-secret placeholder.

    Never use OpenAPI examples/defaults because they may contain real-looking
    identifiers, tokens, emails, or other sensitive values.
    """
    name = str(param.get("name", "")).lower()
    location = str(param.get("in", "")).lower()
    type_hint = str(param.get("type", "")).lower()

    if location == "path":
        if "id" in name or type_hint in {"integer", "number"}:
            return "1"
        return "test"

    if "email" in name:
        return "vf-validation@example.invalid"

    if "uuid" in name:
        return "00000000-0000-4000-8000-000000000001"

    if "id" in name or type_hint in {"integer", "number"}:
        return "1"

    if type_hint == "boolean":
        return "false"

    return "test"


def _build_url(
    document_url: str,
    operation: Dict[str, Any],
) -> Tuple[str, List[str]]:
    """
    Construct a safe URL from the OpenAPI document origin and operation path.

    Returns:
        (url, unresolved_required_parameters)
    """
    path = str(operation.get("path", ""))
    if not path.startswith("/"):
        return document_url, ["invalid-path"]

    parameters = operation.get("parameters", [])
    if not isinstance(parameters, list):
        parameters = []

    by_key: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in parameters[:_MAX_QUERY_PARAMS + _MAX_PATH_PARAMS]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", ""))
        location = str(item.get("in", ""))
        if name and location:
            by_key[(name, location)] = item

    unresolved: List[str] = []

    # Path parameters.
    import re

    def replace_path(match):
        name = match.group(1)
        param = by_key.get((name, "path"))
        if not param:
            unresolved.append(name)
            return match.group(0)
        return quote(_safe_placeholder(param), safe="")

    path = re.sub(r"\{([^{}]+)\}", replace_path, path)

    # Query parameters.
    query_items: List[Tuple[str, str]] = []

    for (name, location), param in list(by_key.items())[:_MAX_QUERY_PARAMS]:
        if location != "query":
            continue

        # Only exercise required query parameters automatically. Optional
        # parameters are deliberately omitted to avoid creating arbitrary
        # application behavior.
        if not bool(param.get("required", False)):
            continue

        query_items.append((name, _safe_placeholder(param)))

    parts = urlsplit(document_url)
    base = f"{parts.scheme}://{parts.netloc}"
    url = urljoin(base + "/", path.lstrip("/"))

    if query_items:
        current = urlsplit(url)
        url = urlunsplit(
            (
                current.scheme,
                current.netloc,
                current.path,
                urlencode(query_items),
                "",
            )
        )

    return url, unresolved


def _classify_exchange(exchange: Any) -> Tuple[str, str]:
    """
    Classify HTTP evidence conservatively.

    This classification describes reachability only. It is NOT a finding.
    """
    if exchange is None:
        return "TRANSPORT_ERROR", "No HTTP exchange was returned."

    error = str(getattr(exchange, "error", "") or "")
    status = int(getattr(exchange, "status", 0) or 0)

    if error:
        if error.startswith("scope-denied:"):
            return "SCOPE_REJECTED", error
        return "TRANSPORT_ERROR", error

    if status in (401, 403):
        return "AUTH_REQUIRED", f"HTTP {status} indicates access control."

    if status == 404:
        return "UNREACHABLE", "HTTP 404: declared operation was not found."

    if status == 405:
        return "METHOD_REJECTED", "HTTP 405: method is not accepted by the route."

    if status == 429:
        return "RATE_LIMITED", "HTTP 429: target or intermediary requested rate limiting."

    if 500 <= status <= 599:
        return "SERVER_ERROR", f"HTTP {status}: server-side failure during validation."

    if 200 <= status <= 399:
        return "REACHABLE", f"HTTP {status}: operation produced an HTTP response."

    if status > 0:
        return "RESPONDED", f"HTTP {status}: operation responded."

    return "TRANSPORT_ERROR", "No usable HTTP status was recorded."


def _content_type(exchange: Any) -> str:
    headers = getattr(exchange, "response_headers", {}) or {}
    for key, value in headers.items():
        if str(key).lower() == "content-type":
            return str(value)
    return ""


def _contract_observation(exchange: Any, operation: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare lightweight HTTP metadata against the declared contract.

    This intentionally does not perform full JSON-schema validation.
    """
    declared_types = [
        str(x).lower()
        for x in (operation.get("response_content_types") or [])
    ]

    actual = _content_type(exchange).lower()

    if not declared_types or not actual:
        return {
            "status": "NOT_DETERMINED",
            "reason": "Insufficient content-type information for contract comparison.",
        }

    compatible = any(
        declared.split(";", 1)[0].strip() in actual
        or actual.split(";", 1)[0].strip() in declared
        or declared in actual
        for declared in declared_types
    )

    if compatible:
        return {
            "status": "MATCH",
            "reason": "Observed response content type is compatible with declaration.",
        }

    return {
        "status": "MISMATCH",
        "reason": (
            f"Observed content type {actual!r} does not match declared "
            f"types {declared_types!r}."
        ),
    }


async def validate_api_operations(ctx) -> List[Dict[str, Any]]:
    """
    Validate a bounded set of declared operations.

    Only safe read methods are automatically requested. Write operations are
    explicitly represented as NOT_AUTO_EXECUTED so the report can distinguish
    lack of validation from lack of implementation.
    """
    results: List[Dict[str, Any]] = []

    operations = [
        item
        for item in (getattr(ctx, "api_inventory", []) or [])
        if item.get("contract") == "DECLARED_NOT_VALIDATED"
    ]

    operations = operations[:_MAX_OPERATIONS]

    for operation in operations:
        method = str(operation.get("method", "GET")).upper()
        document_url = str(operation.get("document_url", ""))

        record: Dict[str, Any] = {
            "method": method,
            "path": operation.get("path", ""),
            "operation_id": operation.get("operation_id", ""),
            "document_url": document_url,
            "validation_status": "NOT_VALIDATED",
            "reason": "",
            "request_url": "",
            "exchange_id": "",
            "http_status": 0,
            "response_content_type": "",
            "contract_observation": {
                "status": "NOT_DETERMINED",
                "reason": "",
            },
        }

        if method not in SAFE_READ_METHODS:
            record["validation_status"] = "NOT_AUTO_EXECUTED"
            record["reason"] = (
                "State-changing method is declared but was not automatically "
                "executed by the read-only API contract validator."
            )
            results.append(record)
            continue

        request_url, unresolved = _build_url(document_url, operation)
        record["request_url"] = request_url

        if unresolved:
            record["validation_status"] = "UNRESOLVED_PARAMETERS"
            record["reason"] = (
                "Required path parameters could not be safely resolved: "
                + ", ".join(unresolved[:12])
            )
            results.append(record)
            continue

        allowed, reason = ctx.authorization.check(
            request_url,
            purpose="api-contract-validation",
            method=method,
        )

        if not allowed:
            record["validation_status"] = "SCOPE_REJECTED"
            record["reason"] = reason
            results.append(record)
            continue

        try:
            exchange = await ctx.requester.send(
                method,
                request_url,
                module="api-contract-validation",
                follow_redirects=True,
            )
        except Exception as exc:
            record["validation_status"] = "VALIDATION_ERROR"
            record["reason"] = f"Validator exception: {type(exc).__name__}: {exc}"
            results.append(record)
            continue

        status, reason = _classify_exchange(exchange)

        record.update(
            {
                "validation_status": status,
                "reason": reason,
                "exchange_id": getattr(exchange, "exchange_id", ""),
                "http_status": int(getattr(exchange, "status", 0) or 0),
                "response_content_type": _content_type(exchange),
                "contract_observation": _contract_observation(
                    exchange, operation
                ),
            }
        )

        results.append(record)

        # A global stop/budget exhaustion must prevent additional validation
        # attempts while preserving already collected evidence.
        if getattr(ctx.authorization, "stopped", False):
            break

    return results
