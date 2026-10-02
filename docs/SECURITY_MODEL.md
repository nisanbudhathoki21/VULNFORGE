# Security model

## Implemented

- `AuthorizationContext` owns authorization confirmation, allow rules, exclusions, audit notes, stop state, and URL scope checks.
- Built-in HTTP traffic goes through `Requester.send`; redirects are handled manually and rechecked.
- Profiles bound request rate, concurrency, request count, page depth/count, timeout, and response size. Active checks require explicit mode/configuration and an active-capable profile.
- `LAB` CLI mode is limited to loopback.
- Observed assets and researcher-declared actors/resources/security properties have different provenance labels.
- Active verifiers are deliberately narrow: configured BOLA checks use two supplied identities and read-only repeated GETs; CORS checks use three synthetic reserved Origin values and scoped GETs; open-redirect checks use an observed query parameter with a reserved external marker and a same-origin control; conservative SQLi checks use original/benign controls plus repeated single-quote GET probes. SQLi does not use blind/timing inference, extraction, stacked statements, writes, or out-of-band callbacks. All use methodology cards and independent evidence assertions. Redirects are not followed; findings state exactly what behavior was verified and avoid unsupported impact claims.
- The CLI's plain scan requests the Full implemented portfolio after explicit ownership/authorization confirmation; `--mode PASSIVE` opts out. Every request remains behind scope, method, rate, budget, timeout, response-size, and stop controls.
- Linked API-schema retrieval is limited to observed document links, refuses out-of-scope hosts, and uses the central `Requester`; schema-declared operations are never replayed automatically.
- The dashboard Repeater is bound to a completed source scan's persisted authorization policy. It cannot choose a new host/port or widen scope, requires fresh consent, uses the common requester with a one-request budget, 1 RPS and a 256 KiB response cap, and never follows redirects. Redaction placeholders are not replayed; mutating methods require explicit original method authorization and a separate per-request confirmation.
- Research exchanges have separate request/response identifiers and a parent exchange for Repeater provenance. History and structured response comparisons are observations, not vulnerability claims.

## Scope enforcement update

The primary runtime scope gate supports host/IP/CIDR/port/prefix bounds, host/path/parameter exclusions, per-request method allowlists (default `GET`, `HEAD`, `OPTIONS`; mutating methods require explicit policy plus an elevated safety mode), optional UTC validity windows, redirect-hop validation, and an append-only allow/deny audit. CLI `.txt`/`.ips` files are IP/CIDR constraints for one explicit target, not batch target lists. URL userinfo is rejected. An unresolved hostname is denied because public/private scope cannot be established; a hostname resolving to any private/reserved address is treated as private unless the loopback-only LAB policy or explicit private-target authorization applies. Responses are read as bounded raw HTTP chunks with `Accept-Encoding: identity`; the engine stores no more than the configured response cap.

DNS checks are not connection pinning: a DNS answer can still change between authorization and connection. That residual risk is not represented as solved.

## Not implemented

The current model is not a general-purpose scope language or policy engine. Optional Playwright browser workflows are limited to navigation and selector/URL observations, use the central `Requester`, and block writes, WebSockets, downloads, and binary assets; they are not a general browser exploit engine. External scanners are not used to create findings. There is no session vault, generalized tenant/workflow security-property library, or broad state-changing action model.

## Required invariants for extensions

1. No request source may bypass the central authorization/scope/safety/rate/budget gate.
2. Store the decision and reason for each request; unknown scope is not permission.
3. Out-of-scope redirects are blocked, not followed.
4. Active checks run only after explicit ownership/authorization confirmation and only for implemented tests in the selected portfolio; `--mode PASSIVE` suppresses active requests.
5. A lab profile must not become a public-target escalation path.
6. Credentials and session state are redacted from normal history and reports.
7. Unsupported checks remain `NOT_TESTED`, `UNSUPPORTED`, or `BLOCKED`.
