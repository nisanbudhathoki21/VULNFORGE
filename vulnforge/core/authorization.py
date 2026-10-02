"""
VulnForge — Authorization & Scope Gate (spec §3).

Hard rule: no HTTP request may leave the process unless this module has
approved it. The gate is consulted for *every* request by the Requester,
including redirect targets and discovery output.

Scope model
───────────
allowed_hosts   exact names and/or *.wildcards (wildcard also covers parent)
allowed_ips     IP literals / CIDR networks (hostname is resolved & checked)
allowed_ports   ports the target may be contacted on
allowed_prefixes URL prefixes with authority/path-boundary matching
excluded_hosts   exact names and/or explicit *.wildcards to block
excluded_paths  bounded regex list for paths to exclude
excluded_params parameter names that must never carry a test value
allowed_methods safe-by-default GET/HEAD/OPTIONS; mutations need elevated mode
not_before/expires_at optional timezone-aware authorization window

Safety invariants
─────────────────
• the primary scan target must match the scope, else the scan never starts
• redirect destinations are re-validated before being followed/queued
• discovered hosts/subdomains never silently become targets
• private-address targets (localhost/10.x/192.168.x/…) require the `lab`
  profile or an explicit `allow_private=True`
• LAB-only probe classes never run against public targets
• every approval/refusal is written to the append-only audit log
"""
from __future__ import annotations

import ipaddress
import math
import re
import socket
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

_PRIVATE_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


def _is_ip_literal(host: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _is_private_ip(ip: ipaddress._BaseAddress) -> bool:
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def parse_scope_time(value: Any, field_name: str) -> Optional[float]:
    """Parse a scope boundary as Unix seconds or an ISO-8601 timestamp.

    Naive timestamps are rejected so a scope window can never depend on the
    machine's local timezone.
    """
    if value in (None, ""):
        return None
    try:
        result = float(value)
        if math.isfinite(result):
            return result
    except (TypeError, ValueError):
        pass
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("timezone is required")
            return parsed.astimezone(timezone.utc).timestamp()
        except ValueError as exc:
            raise ValueError(f"Scope error: {field_name} must be Unix seconds or timezone-aware ISO-8601.") from exc
    raise ValueError(f"Scope error: {field_name} must be Unix seconds or timezone-aware ISO-8601.")


def _canonical_host(host: str) -> str:
    host=str(host).strip().rstrip(".")
    literal=_is_ip_literal(host)
    if literal is not None:
        return str(literal)
    return host.encode("idna").decode("ascii").lower()


def _normalize_host_rule(value: str, field_name: str = "host rule") -> str:
    rule = str(value).strip().lower().rstrip(".")
    wildcard = rule.startswith("*.")
    host = rule[2:] if wildcard else rule
    if not host or "*" in host or "/" in host or "://" in host or "@" in host:
        raise ValueError(f"Scope error: invalid {field_name} '{value}'.")
    if wildcard and "." not in host:
        raise ValueError(f"Scope error: wildcard {field_name} '{value}' is too broad.")
    try:
        host=_canonical_host(host)
    except UnicodeError as exc:
        raise ValueError(f"Scope error: invalid {field_name} '{value}'.") from exc
    literal=_is_ip_literal(host)
    if literal is not None:
        if wildcard:
            raise ValueError(f"Scope error: wildcard IP rule '{value}' is invalid.")
        return str(literal)
    if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                               for label in host.split(".")):
        raise ValueError(f"Scope error: invalid {field_name} '{value}'.")
    return "*." + host if wildcard else host


def _host_rule_matches(host: str, rule: str) -> bool:
    host = host.lower().strip(".")
    if rule.startswith("*."):
        base = rule[2:]
        return host == base or host.endswith("." + base)
    return host == rule


def _scope_items(value: Any, field_name: str) -> List[Any]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple, set)):
        raise ValueError(f"Scope error: {field_name} must be a list.")
    items=list(value)
    if len(items)>500:
        raise ValueError(f"Scope error: {field_name} may contain at most 500 entries.")
    return items


def _matches_url_prefix(url_parts, prefix: str) -> bool:
    prefix_parts=urlparse(prefix)
    scheme=url_parts.scheme.lower()
    prefix_scheme=prefix_parts.scheme.lower()
    try:
        port=(443 if scheme=="https" else 80) if url_parts.port is None else url_parts.port
        prefix_port=(443 if prefix_scheme=="https" else 80) if prefix_parts.port is None else prefix_parts.port
    except ValueError:
        return False
    try:
        request_host=_canonical_host(url_parts.hostname or "")
        prefix_host=_canonical_host(prefix_parts.hostname or "")
    except UnicodeError:
        return False
    if (scheme!=prefix_scheme or request_host!=prefix_host or port!=prefix_port):
        return False
    base=prefix_parts.path or "/"
    path=url_parts.path or "/"
    if base.endswith("/"):
        return path.startswith(base)
    return path==base or path.startswith(base+"/")


@dataclass
class AuditEntry:
    ts: float
    action: str        # scope_allow | scope_deny | scan_start | scan_stop | config
    detail: str
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"ts": self.ts, "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(self.ts)),
                "action": self.action, "detail": self.detail, "url": self.url}


class AuthorizationContext:
    """Authorization/scope decision point + audit trail + stop control."""

    def __init__(
        self,
        allowed_hosts: List[str],
        allowed_ips: Optional[List[str]] = None,
        allowed_ports: Optional[List[int]] = None,
        allowed_prefixes: Optional[List[str]] = None,
        excluded_paths: Optional[List[str]] = None,
        excluded_params: Optional[List[str]] = None,
        profile_name: str = "standard",
        allow_private: bool = False,
        confirmed: bool = False,
        excluded_hosts: Optional[List[str]] = None,
        allowed_methods: Optional[List[str]] = None,
        not_before: Any = None,
        expires_at: Any = None,
    ):
        host_items=_scope_items(allowed_hosts,"allowed_hosts")
        if not host_items:
            raise ValueError("Scope error: at least one allowed host is required.")
        if any(not isinstance(h,str) for h in host_items):
            raise ValueError("Scope error: allowed_hosts entries must be strings.")
        self.allowed_hosts = [_normalize_host_rule(h, "allowed host") for h in host_items if h and h.strip()]
        if not self.allowed_hosts:
            raise ValueError("Scope error: at least one valid allowed host is required.")
        excluded_host_items=_scope_items(excluded_hosts,"excluded_hosts")
        if any(not isinstance(h,str) for h in excluded_host_items):
            raise ValueError("Scope error: excluded_hosts entries must be strings.")
        self.excluded_hosts = [_normalize_host_rule(h, "excluded host") for h in excluded_host_items if h and h.strip()]
        if allowed_methods is not None and not isinstance(allowed_methods, (list, tuple, set)):
            raise ValueError("Scope error: allowed_methods must be a list of method names.")
        methods = [str(m).strip().upper() for m in (allowed_methods if allowed_methods is not None else ["GET", "HEAD", "OPTIONS"]) if str(m).strip()]
        supported_methods = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
        if not methods or any(method not in supported_methods for method in methods):
            raise ValueError("Scope error: allowed_methods may contain only GET, HEAD, OPTIONS, POST, PUT, PATCH, or DELETE.")
        self.allowed_methods = sorted(set(methods))
        self.methods_explicit = allowed_methods is not None
        state_changing={"POST","PUT","PATCH","DELETE"}.intersection(self.allowed_methods)
        if state_changing and profile_name not in {"safe-active","controlled-active","lab"}:
            raise ValueError("Scope error: state-changing methods require SAFE_ACTIVE, CONTROLLED_ACTIVE, or loopback LAB mode.")
        self.not_before = parse_scope_time(not_before, "not_before")
        self.expires_at = parse_scope_time(expires_at, "expires_at")
        if self.not_before is not None and self.expires_at is not None and self.not_before >= self.expires_at:
            raise ValueError("Scope error: not_before must be earlier than expires_at.")
        self.allowed_networks: List[ipaddress._BaseNetwork] = []
        for item in _scope_items(allowed_ips,"allowed_ips"):
            if not isinstance(item,str):
                raise ValueError("Scope error: allowed_ips entries must be strings.")
            item = item.strip()
            if not item:
                continue
            try:
                self.allowed_networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                raise ValueError(f"Scope error: invalid IP/CIDR entry '{item}'.")
        self.allowed_ports = set()
        for item in _scope_items(allowed_ports,"allowed_ports"):
            try:
                port = int(item)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Scope error: invalid port '{item}'.") from exc
            if not 1 <= port <= 65535:
                raise ValueError(f"Scope error: port must be between 1 and 65535 (got {item}).")
            self.allowed_ports.add(port)
        self.allowed_prefixes = []
        for prefix in _scope_items(allowed_prefixes,"allowed_prefixes"):
            if not isinstance(prefix,str):
                raise ValueError("Scope error: allowed_prefixes entries must be strings.")
            prefix = prefix.strip().lower()
            if len(prefix)>4096:
                raise ValueError("Scope error: allowed_prefixes entries may not exceed 4096 characters.")
            try:
                parsed_prefix = urlparse(prefix)
                prefix_port=parsed_prefix.port
                if prefix_port is not None and not 1<=prefix_port<=65535:
                    raise ValueError("port out of range")
            except ValueError as exc:
                raise ValueError(f"Scope error: invalid allowed URL prefix '{prefix}'.") from exc
            if (parsed_prefix.scheme not in ("http", "https") or not parsed_prefix.hostname
                    or parsed_prefix.username or parsed_prefix.password or parsed_prefix.query or parsed_prefix.fragment):
                raise ValueError(f"Scope error: invalid allowed URL prefix '{prefix}'.")
            self.allowed_prefixes.append(prefix)
        self.excluded_path_res = []
        for pat in _scope_items(excluded_paths,"excluded_paths"):
            if not isinstance(pat,str) or len(pat)>512:
                raise ValueError("Scope error: excluded_paths entries must be strings of at most 512 characters.")
            try:
                self.excluded_path_res.append(re.compile(pat, re.I))
            except re.error as e:
                raise ValueError(f"Scope error: bad excluded-path regex '{pat}': {e}")
        param_items=_scope_items(excluded_params,"excluded_params")
        if any(not isinstance(p,str) or len(p)>256 for p in param_items):
            raise ValueError("Scope error: excluded_params entries must be strings of at most 256 characters.")
        self.excluded_params = {p.strip().lower() for p in param_items if p.strip()}

        self.profile_name = profile_name
        self.allow_private = allow_private
        self.confirmed = confirmed            # user confirmed authorization text
        self.audit: List[AuditEntry] = []
        self._dns_cache: Dict[str, List[ipaddress._BaseAddress]] = {}
        self._stop = threading.Event()
        self.stop_reason = ""
        self._lock = threading.Lock()
        self.stats = {"allowed": 0, "denied": 0}

    # ------------------------------------------------------------------
    # user consent / mode display
    # ------------------------------------------------------------------
    AUTHORIZATION_TEXT = (
        "Only scan systems you own or have explicit permission to test."
    )

    def require_confirmation(self) -> None:
        if not self.confirmed:
            raise PermissionError(
                "Authorization not confirmed. You must confirm: "
                f"'{self.AUTHORIZATION_TEXT}'"
            )

    # ------------------------------------------------------------------
    # host matching
    # ------------------------------------------------------------------
    def _host_allowed(self, host: str) -> bool:
        return any(_host_rule_matches(host, rule) for rule in self.allowed_hosts)

    def _host_excluded(self, host: str) -> bool:
        return any(_host_rule_matches(host, rule) for rule in self.excluded_hosts)

    def _resolve(self, host: str) -> List[ipaddress._BaseAddress]:
        if host in self._dns_cache:
            return self._dns_cache[host]
        lit = _is_ip_literal(host)
        if lit is not None:
            self._dns_cache[host] = [lit]
            return [lit]
        ips: List[ipaddress._BaseAddress] = []
        try:
            for fam, _t, _p, _c, sa in socket.getaddrinfo(host, None):
                try:
                    ips.append(ipaddress.ip_address(sa[0]))
                except ValueError:
                    pass
        except (socket.gaierror, UnicodeError):
            pass
        self._dns_cache[host] = ips
        return ips

    def is_private_target(self, host: str) -> bool:
        host = host.lower()
        if host in _PRIVATE_HOSTNAMES or host.endswith(".local") or host.endswith(".internal"):
            return True
        ips = self._resolve(host)
        if not ips:  # unresolvable names are not "private"
            return False
        return any(_is_private_ip(ip) for ip in ips)

    # ------------------------------------------------------------------
    # the decision function
    # ------------------------------------------------------------------
    def check(self, url: str, purpose: str = "request", method: str = "GET") -> Tuple[bool, str]:
        """Return (allowed, reason). The Requester calls this before every hop."""
        try:
            parsed = urlparse(url)
            # Accessing .port also validates malformed port values.
            port = parsed.port
        except (TypeError, ValueError):
            return self._deny(url, f"unparsable URL ({purpose})")
        if parsed.scheme.lower() not in ("http", "https"):
            return self._deny(url, f"scheme '{parsed.scheme}' not http(s)")
        if parsed.username is not None or parsed.password is not None:
            return self._deny(url, "userinfo/embedded credentials in URL are forbidden")
        raw_host=parsed.hostname or ""
        if not raw_host:
            return self._deny(url, "no hostname")
        try:
            host=_canonical_host(raw_host)
        except UnicodeError:
            return self._deny(url,"hostname cannot be normalized safely")
        literal=_is_ip_literal(host)
        lab_loopback=bool(literal is not None and literal.is_loopback)
        if host in _PRIVATE_HOSTNAMES:
            resolved=self._resolve(host)
            lab_loopback=bool(resolved) and all(ip.is_loopback for ip in resolved)
        if self.profile_name=="lab" and not lab_loopback:
            return self._deny(url, "LAB profile is restricted to loopback targets")
        method = str(method or "GET").upper()
        if not re.fullmatch(r"[A-Z]+", method) or method not in self.allowed_methods:
            return self._deny(url, f"HTTP method {method!r} is not in allowed_methods")

        now = time.time()
        if self.not_before is not None and now < self.not_before:
            return self._deny(url, "authorization scope is not yet active")
        if self.expires_at is not None and now >= self.expires_at:
            return self._deny(url, "authorization scope has expired")

        # Explicit exclusions are evaluated before the allowlist.
        if self._host_excluded(host):
            return self._deny(url, f"host '{host}' matches excluded_hosts")

        # Ports: scheme default or explicit.
        port = (443 if parsed.scheme.lower() == "https" else 80) if port is None else port
        if not 1<=port<=65535:
            return self._deny(url,f"invalid port {port}")
        if self.allowed_ports and port not in self.allowed_ports:
            return self._deny(url, f"port {port} not in allowed ports")

        # Host must be inside the explicit allowlist (wildcards only match DNS suffixes).
        if not self._host_allowed(host):
            return self._deny(url, f"host '{host}' outside allowed_hosts")

        # IP rules: if defined, every resolved address must be covered.
        if self.allowed_networks:
            ips = self._resolve(host)
            if not ips:
                return self._deny(url, "host does not resolve; IP rules require resolution")
            for ip in ips:
                if not any(ip.version == net.version and ip in net for net in self.allowed_networks):
                    return self._deny(url, f"resolved IP {ip} outside allowed_ips")

        # Resolve hostnames before allowing traffic. Unknown resolution state is
        # ambiguous scope and therefore fails closed; any private answer makes
        # the hostname private, even when other answers are public.
        if _is_ip_literal(host) is None and host not in _PRIVATE_HOSTNAMES and not host.endswith((".local",".internal")):
            if not self._resolve(host):
                return self._deny(url, "host does not resolve; public/private address scope cannot be established")
        if self.is_private_target(host) and not (self.allow_private or self.profile_name == "lab"):
            return self._deny(url, "private/loopback target requires profile=lab or allow_private")

        # URL prefix restrictions use authority and path-segment boundaries;
        # `/api` does not accidentally authorize `/api-evil` or another port.
        if self.allowed_prefixes and not any(_matches_url_prefix(parsed,p) for p in self.allowed_prefixes):
            return self._deny(url, "URL outside allowed_prefixes")

        # Excluded paths
        for rx in self.excluded_path_res:
            if rx.search(parsed.path or "/"):
                return self._deny(url, f"path matches excluded rule '{rx.pattern}'")

        return self._allow(url, f"{method} {purpose}")

    def check_redirect(self, from_url: str, to_url: str, method: str = "GET") -> Tuple[bool, str]:
        ok, reason = self.check(to_url, purpose="redirect", method=method)
        if not ok:
            self._audit("scope_deny", f"redirect to out-of-scope blocked ({reason})", to_url)
        return ok, reason

    def param_excluded(self, name: str) -> bool:
        return (name or "").lower() in self.excluded_params

    # ------------------------------------------------------------------
    # stop control (spec: STOP SCAN at all times)
    # ------------------------------------------------------------------
    def stop(self, reason: str = "user requested stop") -> None:
        if not self._stop.is_set():
            self._audit("scan_stop", reason)
            self.stop_reason = reason
        self._stop.set()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    # ------------------------------------------------------------------
    # audit plumbing
    # ------------------------------------------------------------------
    def _allow(self, url: str, purpose: str) -> Tuple[bool, str]:
        with self._lock:
            self.stats["allowed"] += 1
        self._audit("scope_allow", purpose, url)
        return True, "in scope"

    def _deny(self, url: str, reason: str) -> Tuple[bool, str]:
        with self._lock:
            self.stats["denied"] += 1
        self._audit("scope_deny", reason, url)
        return False, reason

    def _audit(self, action: str, detail: str, url: str = "") -> None:
        with self._lock:
            self.audit.append(AuditEntry(time.time(), action, detail, url))

    def note(self, action: str, detail: str) -> None:
        self._audit(action, detail)

    def audit_dump(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [e.to_dict() for e in self.audit]

    def describe(self) -> Dict[str, Any]:
        return {
            "allowed_hosts": self.allowed_hosts,
            "allowed_ips": [str(n) for n in self.allowed_networks],
            "allowed_ports": sorted(self.allowed_ports),
            "allowed_prefixes": self.allowed_prefixes,
            "excluded_hosts": self.excluded_hosts,
            "excluded_paths": [r.pattern for r in self.excluded_path_res],
            "excluded_params": sorted(self.excluded_params),
            "allowed_methods": self.allowed_methods,
            "methods_explicit": self.methods_explicit,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "profile": self.profile_name,
            "allow_private": self.allow_private,
            "confirmed": self.confirmed,
        }
