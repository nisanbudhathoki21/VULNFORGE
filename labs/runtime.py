"""Shared, loopback-only HTTP runtime for the three independent training labs.

All records and identities are synthetic and in-memory. This module deliberately
never launches processes, opens arbitrary local paths, or fetches attacker URLs.
"""
from __future__ import annotations

import html
import json
import secrets
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

LEVELS = {
    "critical": {"port": 9001, "title": "Critical Incident Portal"},
    "high": {"port": 9002, "title": "Northstar Work Hub"},
    "medium": {"port": 9003, "title": "Cedar Community Portal"},
}

# Deliberately fake local accounts. These are not credentials for any external system.
USERS = {
    "alice@example.test": {"password": "alice-lab-only", "user": "alice", "role": "member", "tenant": "acme"},
    "amy@example.test": {"password": "amy-lab-only", "user": "amy", "role": "member", "tenant": "acme"},
    "bob@example.test": {"password": "bob-lab-only", "user": "bob", "role": "member", "tenant": "globex"},
    "admin@example.test": {"password": "admin-lab-only", "user": "admin", "role": "admin", "tenant": "acme"},
}
ORDERS = {
    "1001": {"id": "1001", "owner": "alice", "tenant": "acme", "email": "alice@example.test", "item": "Sample design subscription"},
    "1002": {"id": "1002", "owner": "bob", "tenant": "globex", "email": "bob@example.test", "item": "Sample analytics subscription"},
}
DOCUMENTS = {
    "D-ACME-01": {"id": "D-ACME-01", "owner": "alice", "tenant": "acme", "title": "Acme roadmap", "body": "Fictional roadmap for local training."},
    "D-GLOBEX-02": {"id": "D-GLOBEX-02", "owner": "bob", "tenant": "globex", "title": "Globex invoice notes", "body": "Fictional invoice notes for local training."},
}


def _json(value) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def _page(title: str, body: str, *, vulnerable: bool) -> str:
    # Lab pages use inline CSS and no remote assets. The medium XSS route deliberately
    # bypasses this escaping only for the specific reflection scenario.
    headers = "" if vulnerable else "<meta http-equiv='Content-Security-Policy' content=\"default-src 'self'; object-src 'none'\">"
    return f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>{headers}<style>body{{font:16px system-ui;max-width:920px;margin:2rem auto;padding:0 1rem}}nav a{{margin-right:.7rem}}code{{background:#eee;padding:.15rem}}</style></head><body><nav><a href='/'>Home</a><a href='/login'>Login</a><a href='/dashboard'>Dashboard</a><a href='/profile'>Profile</a><a href='/projects'>Projects</a><a href='/documents'>Documents</a><a href='/orders'>Orders</a><a href='/invoices'>Invoices</a><a href='/settings'>Settings</a><a href='/notifications'>Notifications</a><a href='/admin'>Admin</a></nav><hr><h1>{html.escape(title)}</h1>{body}</body></html>"


class LabState:
    def __init__(self, level: str, patched: bool):
        self.level = level
        self.patched = patched
        self.users = {email: dict(account) for email, account in USERS.items()}
        self.sessions: dict[str, str] = {}
        self.reset_tokens: dict[str, str] = {}
        self.updated_email: dict[str, str] = {}
        self.lock = threading.RLock()

    def principal(self, handler: BaseHTTPRequestHandler) -> dict | None:
        # An explicit lab identity header makes scanner identity testing possible.
        # It is accepted only by these loopback fixtures; no real auth system uses it.
        override = handler.headers.get("X-Lab-User", "")
        if override and self.level in {"critical", "high"}:
            for account in self.users.values():
                if account["user"] == override:
                    return account
        cookie = SimpleCookie()
        try:
            cookie.load(handler.headers.get("Cookie", ""))
            sid = cookie.get("lab_session")
            email = self.sessions.get(sid.value) if sid else None
        except Exception:
            email = None
        return self.users.get(email) if email else None


def _render_home(level: str, patched: bool) -> str:
    links = [
        ("/login", "Sign in"), ("/register", "Create account"), ("/dashboard", "Dashboard"),
        ("/profile", "Profile"), ("/users", "Team members"), ("/projects", "Projects"),
        ("/documents", "Documents"), ("/orders", "Orders"), ("/invoices", "Invoices"),
        ("/settings", "Settings"), ("/notifications", "Notifications"), ("/admin", "Admin"),
        ("/api/openapi.json", "API description"),
    ]
    body = "<p>This isolated training app uses fictional people, tenants and objects.</p><ul>" + "".join(
        f"<li><a href='{path}'>{label}</a></li>" for path, label in links
    ) + "</ul><form action='/search' method='get'><label>Search <input name='q'></label><button>Search</button></form>"
    scenario_links = {
        "critical": [("/api/admin/settings", "Admin settings API"), ("/api/password-reset?email=alice%40example.test", "Password reset API"), ("/api/runner?task=status", "Training runner API"), ("/api/fetch?url=http%3A%2F%2Finternal.mock%2Fmetadata", "Mock internal fetch API")],
        "high": [("/api/orders?id=1001", "Order API"), ("/api/documents/D-ACME-01", "Document API"), ("/api/admin/users", "Team administration API"), ("/api/search?q=roadmap", "Catalog search API"), ("/api/file?name=guide.txt", "Document preview API")],
        "medium": [("/api/public", "Public content API"), ("/search?q=hello", "Search"), ("/redirect?next=%2Fdashboard", "Return navigation"), ("/api/cache-profile", "Profile cache API")],
    }[level]
    body += "<h2>Application APIs</h2><ul>" + "".join(f"<li><a href='{path}'>{label}</a></li>" for path, label in scenario_links) + "</ul>"
    body += f"<p>Lab: <code>{html.escape(level)}</code>. Network calls are limited to this local app.</p>"
    return _page(LEVELS[level]["title"], body, vulnerable=not patched)


class LabHandler(BaseHTTPRequestHandler):
    server: "LabHTTPServer"

    def log_message(self, *_args):
        return

    @property
    def state(self) -> LabState:
        return self.server.state

    def send_bytes(self, status: int, body: bytes | str, content_type="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.state.level == "medium" and not self.state.patched:
            # Intentional low-impact hardening gap for this local app.
            pass
        else:
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, value, headers=None):
        self.send_bytes(status, _json(value), "application/json; charset=utf-8", headers)

    def query(self):
        return parse_qs(urlsplit(self.path).query, keep_blank_values=True)

    def principal(self):
        return self.state.principal(self)

    def do_GET(self):
        req = urlsplit(self.path)
        path, q = req.path, self.query()
        level, patched = self.state.level, self.state.patched
        who = self.principal()
        lab_principal = who["user"] if who else "anonymous"
        principal_header = {"X-Lab-Principal": lab_principal}

        if path == "/":
            self.send_bytes(200, _render_home(level, patched)); return
        if path == "/login":
            body = "<form method='post' action='/login'><label>Email <input name='email'></label><label>Password <input type='password' name='password'></label><button>Sign in</button></form><p>Demo identities are in labs/README.md.</p>"
            self.send_bytes(200, _page("Sign in", body, vulnerable=not patched)); return
        if path == "/register":
            self.send_bytes(200, _page("Create account", "<form method='post' action='/register'><input name='email'><input name='password' type='password'><button>Create local demo account</button></form>", vulnerable=not patched)); return
        if path == "/logout":
            self.send_bytes(200, _page("Signed out", "<p>Training session ended.</p>", vulnerable=not patched), headers={"Set-Cookie": "lab_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"}); return
        if path == "/api/openapi.json":
            spec = {"openapi": "3.0.0", "info": {"title": LEVELS[level]["title"], "version": "1.0"}, "paths": {"/api/orders": {"get": {"parameters": [{"name": "id", "in": "query"}]}}, "/api/documents/{document_id}": {"get": {}}, "/api/admin/settings": {"get": {}}, "/api/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}}}}
            self.send_json(200, spec); return
        if path == "/dashboard" or path == "/profile":
            body = (f"<p>Signed in as <b>{html.escape(who['user'])}</b> in tenant <b>{html.escape(who['tenant'])}</b>.</p>" if who else "<p>Anonymous view. <a href='/login'>Sign in</a></p>")
            self.send_bytes(200, _page("Dashboard" if path == "/dashboard" else "Profile", body, vulnerable=not patched)); return
        if path in {"/users", "/projects", "/documents", "/orders", "/invoices", "/settings", "/notifications", "/admin"}:
            listing = {"/users": "Alice, Amy and Bob (fictional members)", "/projects": "Project Atlas · Project Orchard", "/documents": "Roadmaps and invoices are tenant-scoped demo records.", "/orders": "Order 1001 · Order 1002", "/invoices": "INV-ACME-001 · INV-GLOBEX-002", "/settings": "Profile and notification preferences", "/notifications": "Build finished · Monthly invoice ready", "/admin": "Admin functions are exercised by JSON APIs."}[path]
            body = f"<p>{html.escape(listing)}</p>"
            if path == "/settings":
                cookie = SimpleCookie()
                try:
                    cookie.load(self.headers.get("Cookie", ""))
                    sid = cookie.get("lab_session")
                    csrf = "csrf-" + sid.value if sid and patched else ""
                except Exception:
                    csrf = ""
                token_field = f"<input type='hidden' name='csrf_token' value='{html.escape(csrf)}'>" if patched else ""
                body += f"<form method='post' action='/api/settings/email'>{token_field}<label>Notification email <input name='email' value='user@example.test'></label><button>Save preference</button></form>"
            self.send_bytes(200, _page(path.strip("/").title(), body, vulnerable=not patched)); return

        if level == "critical":
            if path == "/api/admin/settings":
                # Intentional authentication/authorization bypass in this local lab.
                if patched and (not who or who["role"] != "admin"):
                    self.send_json(403, {"error": "forbidden"}, principal_header)
                else:
                    self.send_json(200, {"tenant": "acme", "feature_flags": {"training": True}, "owner": "admin"}, principal_header)
                return
            if path == "/api/password-reset":
                email = q.get("email", [""])[0].lower()
                if email not in self.state.users:
                    self.send_json(202, {"message": "If the account exists, a reset will be sent."}); return
                token = ("local-reset-" + self.state.users[email]["user"]) if not patched else secrets.token_urlsafe(24)
                with self.state.lock:
                    self.state.reset_tokens[token] = email
                if patched:
                    self.send_json(202, {"message": "If the account exists, a reset will be sent."})
                else:
                    self.send_json(200, {"message": "Training reset token generated", "token": token})
                return
            if path == "/api/fetch":
                url = q.get("url", [""])[0]
                # Simulated SSRF: lookup only one in-memory fixture. No sockets/network fetch.
                mock = {"http://internal.mock/metadata": {"service": "fictional-billing", "environment": "training"}}
                if patched or url not in mock:
                    self.send_json(403, {"error": "destination blocked; no network request was made"})
                else:
                    self.send_json(200, {"simulated_internal_response": mock[url], "network_access": False})
                return
            if path == "/api/runner":
                task = q.get("task", ["status"])[0]
                # Simulated command parsing. It never starts a process or invokes a shell.
                if patched and any(c in task for c in ";|&`$()"):
                    self.send_json(400, {"error": "invalid task"}); return
                output = {"status": "service=training, state=ready", "health": "all demo checks green"}.get(task, "unknown task")
                simulated = ("training parser observed a command separator; no command was run" if not patched and any(c in task for c in ";|&`$()") else output)
                self.send_json(200, {"output": simulated, "os_process_started": False}); return
            if path == "/api/exports":
                self.send_json(200 if not patched or who and who["role"] == "admin" else 403, {"tenant": "acme", "export": "fictional aggregate", "classification": "training"}, principal_header); return

        if level == "high":
            if path == "/api/orders":
                oid = q.get("id", ["1001"])[0]
                row = ORDERS.get(oid)
                if row is None:
                    self.send_json(404, {"error": "not found"}, principal_header); return
                allowed = (not patched) or (who and who["user"] == row["owner"] and who["tenant"] == row["tenant"])
                self.send_json(200 if allowed else 403, row if allowed else {"error": "forbidden"}, principal_header); return
            if path.startswith("/api/documents/"):
                doc_id = path.rsplit("/", 1)[-1]
                row = DOCUMENTS.get(doc_id)
                if row is None:
                    self.send_json(404, {"error": "not found"}, principal_header); return
                allowed = (not patched) or (who and who["user"] == row["owner"] and who["tenant"] == row["tenant"])
                self.send_json(200 if allowed else 403, row if allowed else {"error": "forbidden"}, principal_header); return
            if path == "/api/admin/users":
                if patched and (not who or who["role"] != "admin"):
                    self.send_json(403, {"error": "forbidden"}, principal_header)
                else:
                    self.send_json(200, {"users": [{"user": u["user"], "role": u["role"], "tenant": u["tenant"]} for u in self.state.users.values()]}, principal_header)
                return
            if path == "/api/search":
                term = q.get("q", [""])[0]
                # High-lab SQL behavior is a constrained SQLite SELECT over fake in-memory data.
                # execute() accepts a single statement; there are no write APIs in this route.
                import sqlite3
                con = sqlite3.connect(":memory:")
                con.execute("CREATE TABLE catalog (id INTEGER, title TEXT)")
                con.executemany("INSERT INTO catalog VALUES (?,?)", [(1, "Fictional roadmap"), (2, "Sample invoice")])
                try:
                    if patched:
                        rows = con.execute("SELECT id,title FROM catalog WHERE title LIKE ?", (f"%{term}%",)).fetchall()
                    else:
                        rows = con.execute("SELECT id,title FROM catalog WHERE title LIKE '%" + term + "%'").fetchall()
                    self.send_json(200, {"results": rows})
                except sqlite3.Error:
                    # Intentional training diagnostic: exposes a DB-family parser
                    # fingerprint, but the scanner must keep this as a candidate.
                    self.send_json(500, {"error": 'SQLite parser diagnostic: sqlite3.OperationalError: near "quote": syntax error'})
                finally:
                    con.close()
                return
            if path == "/api/file":
                name = q.get("name", ["guide.txt"])[0]
                # A tiny virtual filesystem; traversal can expose only a fake in-memory document.
                virtual = {"guide.txt": "Fictional user guide.", "private/training-note.txt": "Synthetic training-only note."}
                key = name.replace("\\", "/").lstrip("/")
                if not patched and (".." in key.split("/")):
                    self.send_json(200, {"file": virtual["private/training-note.txt"], "source": "virtual fixture only"})
                elif key in virtual:
                    self.send_json(200, {"file": virtual[key], "source": "virtual fixture"})
                else:
                    self.send_json(404, {"error": "not found"})
                return

        if level == "medium":
            if path == "/api/public":
                origin = self.headers.get("Origin", "")
                if patched:
                    allow = "https://portal.example.test" if origin == "https://portal.example.test" else ""
                else:
                    allow = origin
                headers = {"Vary": "Origin"}
                if allow:
                    headers["Access-Control-Allow-Origin"] = allow
                    headers["Access-Control-Allow-Credentials"] = "true"
                self.send_json(200, {"message": "public synthetic content"}, headers); return
            if path == "/redirect":
                destination = q.get("next", ["/dashboard"])[0]
                if patched:
                    parsed = urlsplit(destination)
                    if parsed.scheme or parsed.netloc or not destination.startswith("/") or destination.startswith("//"):
                        destination = "/dashboard"
                # Location is returned but never followed by the lab server.
                self.send_bytes(302, "", headers={"Location": destination}); return
            if path == "/search":
                term = q.get("q", [""])[0]
                rendered = term if not patched else html.escape(term, quote=True)
                body = f"<p>Search results for: {rendered}</p><p>No external assets or scripts are loaded.</p>"
                self.send_bytes(200, _page("Search", body, vulnerable=not patched)); return
            if path == "/api/cache-profile":
                headers = {"Cache-Control": "public, max-age=300"} if not patched else {"Cache-Control": "private, no-store"}
                self.send_json(200, {"user": who["user"] if who else "anonymous", "cache": "training fixture"}, headers); return

        self.send_bytes(404, _page("Not found", "<p>Not found</p>", vulnerable=not patched))

    def do_POST(self):
        req = urlsplit(self.path)
        path = req.path
        length = min(int(self.headers.get("Content-Length", "0") or 0), 16_384)
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        data = parse_qs(raw, keep_blank_values=True)
        state, who = self.state, self.principal()
        if path == "/login":
            email = data.get("email", [""])[0].lower()
            password = data.get("password", [""])[0]
            account = state.users.get(email)
            if account and secrets.compare_digest(password, account["password"]):
                sid = secrets.token_urlsafe(18)
                with state.lock:
                    state.sessions[sid] = email
                self.send_bytes(303, "", headers={"Location": "/dashboard", "Set-Cookie": f"lab_session={sid}; Path=/; HttpOnly; SameSite=Lax"})
            else:
                self.send_bytes(401, _page("Sign in", "<p>Demo sign-in failed.</p>", vulnerable=not state.patched))
            return
        if path == "/register":
            self.send_bytes(201, _page("Local account created", "<p>Registration is disabled in this seeded training fixture.</p>", vulnerable=not state.patched)); return
        if path == "/api/reset-password":
            token = data.get("token", [""])[0]
            with state.lock:
                email = state.reset_tokens.pop(token, None)
            if email:
                new_password = data.get("password", [""])[0][:128]
                if new_password:
                    with state.lock:
                        state.users[email]["password"] = new_password
                self.send_json(200, {"message": "fictional password reset accepted; no external account exists", "password_updated_in_memory": bool(new_password)})
            else:
                self.send_json(400, {"error": "invalid training token"})
            return
        if path == "/api/settings/email":
            if not who:
                self.send_json(401, {"error": "sign in required"}); return
            if state.level == "medium" and state.patched:
                cookie = SimpleCookie(); cookie.load(self.headers.get("Cookie", "")); sid = cookie.get("lab_session")
                expected = "csrf-" + (sid.value if sid else "")
                if self.headers.get("X-CSRF-Token", "") != expected and data.get("csrf_token", [""])[0] != expected:
                    self.send_json(403, {"error": "csrf token required"}); return
            new_email = data.get("email", [""])[0][:160]
            with state.lock:
                state.updated_email[who["user"]] = new_email
            self.send_json(200, {"user": who["user"], "email": new_email, "persisted": False}); return
        self.send_json(404, {"error": "not found"})


class LabHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, level: str, patched: bool):
        self.state = LabState(level, patched)
        super().__init__(address, LabHandler)


def create_server(level: str, host="127.0.0.1", port: int | None = None, patched=False):
    if level not in LEVELS:
        raise ValueError(f"unknown lab {level!r}; choose critical, high, or medium")
    if host != "127.0.0.1":
        raise ValueError("training labs bind only to the explicit IPv4 loopback address 127.0.0.1")
    selected_port = LEVELS[level]["port"] if port is None else port
    return LabHTTPServer((host, selected_port), level, patched)


def serve(level: str, patched=False, host="127.0.0.1", port: int | None = None):
    server = create_server(level, host, port, patched)
    variant = "patched control" if patched else "intentionally vulnerable"
    print(f"VulnForge {level} lab ({variant}) listening on http://{host}:{server.server_port}")
    print("Synthetic data only; loopback binding; no arbitrary process execution or outbound URL fetching.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping lab.")
    finally:
        server.server_close()
