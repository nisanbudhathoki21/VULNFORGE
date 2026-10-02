"""Legacy deterministic Handler fixture used only by unit tests.

This module is not a user-facing lab server. New training apps live in ``labs/``.
"""
from __future__ import annotations
import html, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def reply(self, status, body, ctype="text/html; charset=utf-8", headers=None):
        if isinstance(body,str): body=body.encode()
        self.send_response(status); self.send_header("Content-Type",ctype)
        self.send_header("Content-Length",str(len(body)))
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("Referrer-Policy","strict-origin-when-cross-origin")
        self.send_header("Set-Cookie","lab_session=demo-value; Path=/; HttpOnly; SameSite=Lax")
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        p=urlsplit(self.path); path=p.path; q=parse_qs(p.query)
        if path=="/":
            self.reply(200,"""<!doctype html><title>VulnForge Local Lab</title><h1>Local Security Lab</h1>
<a href='/search?q=hello'>Search (simulated SQL-error fixture)</a><a href='/search-safe?q=hello'>Search (patched control)</a>
<a href='/account'>Account</a><a href='/old'>Redirect sample</a>
<a href='/redirect?next=%2Faccount'>Redirect validation fixture</a><a href='/safe-redirect?next=%2Faccount'>Redirect patched control</a>
<a href='/cors/reflect'>CORS reflection fixture</a><a href='/cors/allowlist'>CORS allowlist control</a>
<a href='/api/orders?id=1001'>Order API (vulnerable lab object)</a>
<a href='/api/orders-isolated?id=1001'>Order API (patched ownership control)</a><a href='/openapi.json'>OpenAPI</a>
<a href='/login'>Login</a><form action='/search' method='GET'><input name='q'><button>Search</button></form>
<script src='/app.js'></script>""")
        elif path=="/search":
            val=q.get("q",[""])[0]
            # Deliberately simulated parser error for the bounded quote-probe regression.
            # No database is connected and no query is executed.
            if "'" in val:
                self.reply(500,'sqlite3.OperationalError: near "quote": syntax error',"text/plain; charset=utf-8")
            else:
                self.reply(200,f"<title>Search</title><h2>Results</h2><div>{html.escape(val,quote=True)}</div>")
        elif path=="/search-safe":
            val=html.escape(q.get("q",[""])[0],quote=True)
            self.reply(200,f"<title>Search</title><h2>Results</h2><div>{val}</div>")
        elif path=="/app.js": self.reply(200,"fetch('/api/orders?id=1001');\nconst doc='/openapi.json';", "application/javascript")
        elif path=="/openapi.json": self.reply(200,json.dumps({"openapi":"3.0.0","paths":{"/api/orders":{"get":{"operationId":"getLabOrder"}},"/api/orders-isolated":{"get":{"operationId":"getPatchedLabOrder"}}}}),"application/json")
        elif path=="/api/orders":
            oid=q.get("id",["1001"])[0]
            # Intentionally broken authorization: the response ignores X-Lab-User.
            orders={"1001":{"owner":"alice","email":"alice@example.test","item":"demo order A"},"1002":{"owner":"bob","email":"bob@example.test","item":"demo order B"}}
            principal=self.headers.get("X-Lab-User","anonymous")
            self.reply(200,json.dumps(orders.get(oid,{"error":"not found"})),"application/json",headers={"X-Lab-Principal":principal})
        elif path=="/api/orders-isolated":
            oid=q.get("id",["1001"])[0]
            principal=self.headers.get("X-Lab-User","anonymous")
            orders={"1001":{"owner":"alice","email":"alice@example.test","item":"demo order A"},"1002":{"owner":"bob","email":"bob@example.test","item":"demo order B"}}
            order=orders.get(oid)
            if order is None:
                self.reply(404,json.dumps({"error":"not found"}),"application/json",headers={"X-Lab-Principal":principal})
            elif order["owner"]!=principal:
                self.reply(403,json.dumps({"error":"forbidden"}),"application/json",headers={"X-Lab-Principal":principal})
            else:
                self.reply(200,json.dumps(order),"application/json",headers={"X-Lab-Principal":principal})
        elif path=="/cors/reflect":
            origin=self.headers.get("Origin","")
            self.reply(200,json.dumps({"fixture":"toy public data"}),"application/json",headers={
                "Access-Control-Allow-Origin":origin,"Access-Control-Allow-Credentials":"true","Vary":"Origin"})
        elif path=="/cors/allowlist":
            self.reply(200,json.dumps({"fixture":"toy public data"}),"application/json",headers={
                "Access-Control-Allow-Origin":"https://trusted.example","Access-Control-Allow-Credentials":"true"})
        elif path=="/redirect":
            location=q.get("next",["/"])[0]
            self.reply(302,"",headers={"Location":location})
        elif path=="/safe-redirect":
            location=q.get("next",["/"])[0]
            if not location.startswith("/") or location.startswith("//") or "://" in location:
                location="/"
            self.reply(302,"",headers={"Location":location})
        elif path=="/account": self.reply(401,"<title>Sign in</title><h1>Sign in</h1><form><input type='password' name='password'></form>")
        elif path=="/login": self.reply(200,"<title>Login</title><form method='post'><input name='username'><input type='password' name='password'></form><p>Two-factor authentication with TOTP can be configured after login.</p>")
        elif path=="/old": self.reply(302,"",headers={"Location":"/new"})
        elif path=="/new": self.reply(200,"<title>Redirect destination</title><p>Reached destination.</p>")
        elif path=="/robots.txt": self.reply(200,"User-agent: *\nDisallow: /account\n","text/plain")
        else: self.reply(404,"<title>Not found</title><p>Not found</p>")
    def do_POST(self):
        self.reply(200,json.dumps({"status":"accepted","note":"demo state is not persisted"}),"application/json")

