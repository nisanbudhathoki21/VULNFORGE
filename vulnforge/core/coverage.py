"""Conservative, implementation-backed scan coverage matrix."""

def build_coverage(ctx):
    tests=getattr(ctx,"tests",[])
    plans=getattr(ctx,"test_plan",[])
    executed=[t for t in tests if t.get("status") in ("VERIFIED","CANDIDATE")]
    blocked=bool(plans) and not executed
    authz="PARTIAL" if executed else ("BLOCKED" if blocked else "NOT_TESTED")
    return [
      {"category":"DNS / target addresses","status":"PARTIAL","notes":"System-resolver A/AAAA addresses only; no passive subdomain sources or full DNS record set."},
      {"category":"Web services / redirects","status":"PARTIAL","notes":"Fetched HTTP(S) responses receive conservative live-state labels; failed transport is UNKNOWN except explicit timeout/refusal. No port sweep or virtual-host discovery."},
      {"category":"TLS certificate intelligence","status":"UNSUPPORTED","notes":"Certificate details are not exposed by the current transport; no certificate claims are made."},
      {"category":"WAF / CDN / technology fingerprints","status":"PARTIAL","notes":"Passive rules over fetched headers, cookies, HTML, and assets; not a comprehensive multi-source fingerprint database."},
      {"category":"Static application crawling","status":"PARTIAL","notes":"Bounded HTTP crawl, HTML links/forms, query parameters, and discovered JavaScript; no browser-rendered SPA execution."},
      {"category":"API / OpenAPI discovery","status":"PARTIAL","notes":"Explicitly linked JSON OpenAPI 3.x / Swagger 2.0 documents yield bounded declared operation metadata; YAML, full schema semantics, and operation reachability are not tested."},
      {"category":"Authentication / MFA","status":"PARTIAL","notes":"Text and route signals only; no MFA or authentication workflow validation."},
      {"category":"Object-level authorization","status":authz,"notes":"Only the explicitly configured, read-only two-identity comparison is supported; all other authorization cases remain untested."},
      {"category":"XSS / injection / SSRF / traversal / file upload","status":"NOT_TESTED","notes":"No controlled verification modules are implemented for these classes."},
      {"category":"CORS / CSRF / JWT / OAuth / WebSocket","status":"NOT_TESTED","notes":"These vulnerability classes are not actively tested in this build."},
      {"category":"Business logic / race conditions","status":"UNSUPPORTED","notes":"No stateful workflow or concurrency testing engine is implemented."},
    ]
