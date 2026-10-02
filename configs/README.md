# configs/

Put your **own** auth files, scope policies, and workflow configs for real
targets here — not in `examples/`. Everything in this folder except this
README and `.gitkeep` is gitignored, so your real tokens/cookies/session
headers never get committed.

Copy a template from `examples/` to get the shape right, e.g.:

```bash
cp ../examples/scope-policy.example.json configs/my-target-scope.json
cp ../examples/lab-auth.json configs/my-target-auth.json
# edit configs/my-target-auth.json with your real auth headers
vulnforge scan url https://your-authorized-target.example \
  --auth configs/my-target-auth.json --yes
```

`vulnforge` also reads `VULNFORGE_AUTH_FILE` as a default for `--auth` and
`VULNFORGE_SCOPE_FILE` as a default scope policy, so you can set these in a
local (gitignored) `.env` instead of typing a path every run. See
`.env.example` in the repo root.

## Authenticated scanning (Phase 2)

If the target gates everything behind a form login (not a static API
token), use `--login configs/my-target-login.json` instead of / alongside
`--auth`:

```bash
cp ../examples/login-flow.example.json configs/my-target-login.json
# edit configs/my-target-login.json with the real login URL and credentials
vulnforge scan url https://your-authorized-target.example \
  --login configs/my-target-login.json --yes
```

VulnForge does exactly one GET (to pick up a CSRF token if present) and one
POST to log in, before the scan starts. The resulting session cookie is then
reused for every request in the scan, the same way `--auth` headers are. The
login URL must already be inside the scan's `--scope` — VulnForge refuses to
log in against a host that wasn't separately authorized.

`VULNFORGE_LOGIN_FILE` works as an env-var default, same as `VULNFORGE_AUTH_FILE`.
