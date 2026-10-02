"""
VulnForge — parameter semantic classification (spec §13).

Name + value heuristics assign *roles* to parameters (identifier, redirect,
filename, token, price-like…). These classifications ONLY prioritize later
testing — a name is never evidence of a vulnerability.
"""
from __future__ import annotations

import re
from typing import List

_RULES = [
    ("redirect",   re.compile(r"^(url|uri|link|redir|redirect(?:_url|_uri)?|return(?:_url|_to)?|next|continue|goto|dest(?:ination)?|target|forward|callback_url|success_url|cancel_url|failure_url)$", re.I)),
    ("callback",   re.compile(r"(callback|webhook|notify|pingback|hook)", re.I)),
    ("filename",   re.compile(r"^(file(?:name)?|filename|path|filepath|dir|directory|folder|download|doc|document|page|template|view|layout|include|inc)$", re.I)),
    ("user_id",    re.compile(r"^(user_?id|uid|username|user|account_?id|acct|member_?id|customer_?id|client_?id|owner_?id|author_?id)$", re.I)),
    ("object_id",  re.compile(r"(^id$|_id$|^doc(?:ument)?_?id|^order_?id|^item_?id|^product_?id|^post_?id|^comment_?id|^message_?id|^file_?id|^project_?id|^invoice_?id)", re.I)),
    ("tenant_id",  re.compile(r"(tenant|org(?:anization)?|workspace|team|account|company|project|tenant_?id|org_?id|workspace_?id|team_?id)", re.I)),
    ("role_like",  re.compile(r"(^role$|_role$|is_?admin|admin|permission|perm|privilege|access_?level|user_?type|group)", re.I)),
    ("price_like", re.compile(r"(price|amount|total|cost|fee|balance|discount|currency|salary|payment)", re.I)),
    ("quantity_like", re.compile(r"(qty|quantity|count|number|num|limit|offset|size|per_?page|page_?size)", re.I)),
    ("token_like", re.compile(r"(token|csrf|xsrf|nonce|secret|key|api[-_]?key|session|jwt|auth|signature|hash)", re.I)),
    ("search",     re.compile(r"^(q|query|search|keyword|term|filter|find|s)$", re.I)),
    ("path_like",  re.compile(r"(path|folder|directory|dir|upload_?dir|save_?to|dest_?path)", re.I)),
]

_VALUE_RES = [
    ("url_value",     re.compile(r"^https?://", re.I)),
    ("numeric",       re.compile(r"^-?\d+$")),
    ("decimal",       re.compile(r"^-?\d+\.\d+$")),
    ("boolean",       re.compile(r"^(true|false|0|1|yes|no)$", re.I)),
    ("uuid",          re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)),
    ("path_value",    re.compile(r"^(/|\./|\.\./|[\w.-]+\.\w{1,5}$)")),
    ("email",         re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")),
    ("jwt_value",     re.compile(r"^eyJ[A-Za-z0-9_-]+\.")),
    ("date",          re.compile(r"^\d{4}-\d{2}-\d{2}")),
]


def classify_parameter(name: str, example: str = "", location: str = "query") -> List[str]:
    tags: List[str] = []
    for label, rx in _RULES:
        if rx.search(name or ""):
            tags.append(label)
    for label, rx in _VALUE_RES:
        if example and rx.search(str(example).strip()):
            tags.append(label)
    # generic identifier notion: id-ish names with numeric values
    if ("object_id" in tags or "user_id" in tags) and "numeric" in tags:
        tags.append("identifier")
    if "object_id" in tags or "user_id" in tags or "tenant_id" in tags:
        tags.append("object_reference")
    return sorted(set(tags))
