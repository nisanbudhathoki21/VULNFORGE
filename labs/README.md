# Local training labs

VULNFORGE includes three synthetic multi-page web applications for authorized, isolated regression training. Run them through the single public CLI; every server binds to `127.0.0.1` only.

```bash
vulnforge lab critical     # port 9001
vulnforge lab high         # port 9002
vulnforge lab medium       # port 9003
```

Use `--patched` to select that lab's paired fixed/control variant. Example:

```bash
vulnforge lab high --patched
```

The applications contain only synthetic tenants, users, and objects. They do not execute OS commands, access arbitrary local paths, call external URLs, or perform destructive writes. Do not expose these labs on a non-loopback interface.

For positive and negative scanner checks, configure only the fake accounts supplied by the lab examples under `examples/`. The scanner receives the same explicit authorization test configuration a user would provide; it does not receive a hidden vulnerability manifest.

Current demonstration scope:

- Critical: explicit owner/non-owner object authorization assertions; the vulnerable behavior is `VERIFIED`, the patched behavior is negative.
- High: documented JSON API routes, a tenant-scoped object boundary, and bounded SQL parser diagnostics. SQL behavior remains an observation only and is never reported as confirmed injection.
- Medium: paired external redirect behavior; CORS response behavior remains observation-only unless a future verification contract proves security impact.

Run acceptance tests with `python -m pytest -q`. Lab E2E tests use loopback targets only and assert both positive and patched outcomes.
