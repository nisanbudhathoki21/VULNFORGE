"""Research-workspace helpers: bounded JSON comparison and strict HTTP message parsing."""
from __future__ import annotations

import difflib
import json
import re
from typing import Any, Dict, List, Tuple

MAX_REQUEST_BYTES = 131_072
MAX_REQUEST_BODY_BYTES = 65_536
MAX_HEADER_BYTES = 16_384
MAX_HEADER_COUNT = 100
MAX_JSON_DIFF_ITEMS = 500


def _bounded_diff_value(value: Any, limit: int = 1024) -> Any:
    """Keep a single changed JSON value from inflating the diff response."""
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "…[value truncated]"
    if isinstance(value, (dict, list)):
        try:
            encoded=json.dumps(value,ensure_ascii=False,separators=(",",":"))
        except (TypeError,ValueError,RecursionError):
            return {"value_truncated": True, "type": type(value).__name__}
        if len(encoded) > limit * 2:
            return {"value_truncated": True, "type": type(value).__name__,
                    "items": len(value), "serialized_chars": len(encoded)}
    return value


def compare_response_bodies(body_a: str, body_b: str, *, max_items: int = MAX_JSON_DIFF_ITEMS) -> Dict[str, Any]:
    """Compare bodies structurally when both are JSON; otherwise return a bounded text diff.

    This reports observed differences only and deliberately makes no security verdict.
    """
    a_text = str(body_a or "")
    b_text = str(body_b or "")
    try:
        a = json.loads(a_text)
        b = json.loads(b_text)
    except (ValueError, TypeError, RecursionError):
        diff = list(difflib.unified_diff(a_text.splitlines(), b_text.splitlines(),
                                         fromfile="response-a", tofile="response-b", lineterm=""))
        return {"format": "text", "different": a_text != b_text,
                "bytes_a": len(a_text.encode("utf-8", "replace")),
                "bytes_b": len(b_text.encode("utf-8", "replace")),
                "unified_diff": diff[:200], "truncated": len(diff) > 200}

    changes: List[Dict[str, Any]] = []
    truncated = False
    missing = object()

    def emit(kind: str, path: str, old: Any = missing, new: Any = missing) -> None:
        nonlocal truncated
        if len(changes) >= max_items:
            truncated = True
            return
        item: Dict[str, Any] = {"kind": kind, "path": path or "/"}
        if old is not missing:
            item["before"] = _bounded_diff_value(old)
        if new is not missing:
            item["after"] = _bounded_diff_value(new)
        changes.append(item)

    def walk(old: Any, new: Any, path: str, depth: int = 0) -> None:
        nonlocal truncated
        if truncated:
            return
        if depth > 32:
            if old != new:
                emit("changed", path, old, new)
            return
        if isinstance(old, dict) and isinstance(new, dict):
            for key in sorted(set(old) | set(new), key=lambda x: str(x)):
                token = str(key).replace("~", "~0").replace("/", "~1")
                child = f"{path}/{token}"
                if key not in old:
                    emit("added", child, new=new[key])
                elif key not in new:
                    emit("removed", child, old=old[key])
                else:
                    walk(old[key], new[key], child, depth + 1)
                if truncated:
                    return
        elif isinstance(old, list) and isinstance(new, list):
            common = min(len(old), len(new))
            for index in range(common):
                walk(old[index], new[index], f"{path}/{index}", depth + 1)
                if truncated:
                    return
            for index in range(common, len(old)):
                emit("removed", f"{path}/{index}", old=old[index])
                if truncated:
                    return
            for index in range(common, len(new)):
                emit("added", f"{path}/{index}", new=new[index])
                if truncated:
                    return
        elif old != new:
            emit("changed", path, old, new)

    walk(a, b, "")
    return {"format": "json", "different": bool(changes) or truncated,
            "changes": changes, "truncated": truncated,
            "bytes_a": len(a_text.encode("utf-8", "replace")),
            "bytes_b": len(b_text.encode("utf-8", "replace"))}


def parse_raw_http_request(raw_text: str) -> Tuple[str, str, Dict[str, str], str]:
    """Parse one bounded origin-form HTTP/1 request, rejecting ambiguous framing."""
    if not isinstance(raw_text, str) or not raw_text.strip():
        raise ValueError("Request message cannot be empty.")
    if len(raw_text.encode("utf-8", "replace")) > MAX_REQUEST_BYTES:
        raise ValueError("Request message exceeds the 128 KiB limit.")
    text = raw_text.replace("\r\n", "\n")
    if "\r" in text:
        raise ValueError("Bare carriage-return characters are not allowed.")
    head, separator, body = text.partition("\n\n")
    if len(body.encode("utf-8", "replace")) > MAX_REQUEST_BODY_BYTES:
        raise ValueError("Request body exceeds the 64 KiB limit.")
    lines = head.split("\n")
    if len(lines) < 1 or len(lines) > MAX_HEADER_COUNT + 1:
        raise ValueError("Request has too many headers.")
    match = re.fullmatch(r"([A-Za-z]{1,16}) ([^\s]{1,8192}) HTTP/1\.[01]", lines[0].strip())
    if not match:
        raise ValueError("Use a request line like: GET /path HTTP/1.1")
    method, target = match.group(1).upper(), match.group(2)
    if not re.fullmatch(r"[A-Z]+", method):
        raise ValueError("Invalid HTTP method.")
    if not target.startswith("/") or target.startswith("//") or any(ord(ch) < 0x20 for ch in target) or "#" in target:
        raise ValueError("Only origin-form paths such as /path?query are accepted.")
    headers: Dict[str, str] = {}
    names = set()
    total = 0
    for line in lines[1:]:
        if not line or line[0] in " \t" or ":" not in line:
            raise ValueError("Malformed or folded HTTP header.")
        name, value = line.split(":", 1)
        name, value = name.strip(), value.strip()
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ValueError("Invalid HTTP header name.")
        if any(ord(ch) < 0x20 and ch != "\t" for ch in value) or "\r" in value or "\n" in value:
            raise ValueError("Invalid HTTP header value.")
        lowered = name.lower()
        if lowered in names:
            raise ValueError("Duplicate HTTP headers are not accepted by the guarded Repeater.")
        names.add(lowered)
        total += len(name.encode("utf-8")) + len(value.encode("utf-8"))
        if total > MAX_HEADER_BYTES:
            raise ValueError("Combined request headers exceed 16 KiB.")
        if lowered in {"content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection", "upgrade"}:
            raise ValueError(f"Transport-managed header {name!r} is not accepted.")
        headers[name] = value
    if not separator:
        body = ""
    return method, target, headers, body
