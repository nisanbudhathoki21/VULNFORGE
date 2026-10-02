"""Shared fixtures: a local mock web app served over HTTP for tests."""
import json
import threading
from urllib.parse import parse_qs, urlsplit
import pytest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX_HTML = """<!doctype html><html><head><title>Home</title>
<meta name="generator" content="WordPress 6.5">
</head><body>
<h1>Mock Target</h1>
<a href="/about">About</a>
<a href="/user/1">User one</a>
<a href="/user/2">User two</a>
<a href="/search?q=shoes">Search</a>
<a href="/cors/reflect">CORS reflection fixture</a>
<a href="/cors/allowlist">CORS allowlist fixture</a>
<a href="/open-redirect?next=%2Fabout">Open redirect positive fixture</a>
<a href="/safe-redirect?next=%2Fabout">Open redirect negative fixture</a>
<a href="http://out-of-scope.example/">External, must not be followed</a>
<a href="/page-error">Error page</a>
<a href="/openapi.json">OpenAPI contract</a>
<a href="/openapi.yaml">YAML contract is unsupported</a>
<a href="https://out-of-scope.example/openapi.json">External contract, must not be fetched</a>
<script src="/static/app.js"></script>
<form action="/search" method="GET">
  <input type="text" name="q" value="">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="submit" value="go">
</form>
<form action="https://out-of-scope.example/submit" method="POST">
  <input type="email" name="contact_email" value="">
</form>
</body></html>"""

APP_JS = """
const base = "/api/v1";
fetch('/api/v1/users?role=admin');
axios.post('/graphql', {query:"{ viewer { id } }"});
const sock = new WebSocket("wss://demo.example/socket");
var config = {"api_key": "AKIAIOSFODNN7EXAMPLE"};
//# sourceMappingURL=app.js.map
"""

ERROR_HTML = """<html><body><pre>
Traceback (most recent call last):
  File "/srv/app/views.py", line 42, in get
    return render(db.query(uid))
ValueError: invalid literal
</pre></body></html>"""

ROBOTS = "User-agent: *\nDisallow: /admin/panel\nSitemap: /sitemap.xml\nSitemap: /sitemap-index.xml\n"
SITEMAP = """<?xml version="1.0"?><urlset>
<url><loc>{base}/about</loc></url>
<url><loc>{base}/legacy/report?id=7</loc></url>
</urlset>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype="text/html", status=200, extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        path = self.path.split("?")[0]
        if path == "/":
            self._send(INDEX_HTML, extra={"Set-Cookie": "session=xyz; Path=/"})
        elif path == "/about":
            self._send("<html><title>About</title><body>About us</body></html>")
        elif path == "/redirect":
            self._send("", status=302, extra={"Location": "/about"})
        elif path == "/external-redirect":
            self._send("", status=302, extra={"Location": "http://out-of-scope.example/"})
        elif path in ("/user/1", "/user/2"):
            n = path.rsplit("/", 1)[-1]
            self._send(f"<html><title>User {n}</title><body>Profile {n}</body></html>")
        elif path == "/search":
            self._send(f"<html><body>results for query</body></html>")
        elif path == "/sqli/search":
            value=parse_qs(urlsplit(self.path).query).get("q",[""])[0]
            if value.endswith("'"):
                self._send("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", "text/plain", status=500)
            else:
                self._send("Search results", "text/plain")
        elif path == "/sqli/safe":
            self._send("Search results", "text/plain")
        elif path == "/legacy/report":
            self._send("<html><body>report</body></html>")
        elif path == "/auth-required":
            self._send("<html><body>login required</body></html>", "text/html", status=401)
        elif path == "/authz/orders":
            self._send('{"owner":"alice","email":"alice@example.test","item":"controlled-order"}', "application/json", extra={"X-Lab-Principal":self.headers.get("X-Lab-User","anonymous")})
        elif path == "/cors/reflect":
            origin=self.headers.get("Origin","")
            self._send('{"ok":true}',"application/json",extra={
                "Access-Control-Allow-Origin":origin,"Access-Control-Allow-Credentials":"true","Vary":"Origin"})
        elif path == "/cors/allowlist":
            self._send('{"ok":true}',"application/json",extra={
                "Access-Control-Allow-Origin":"https://trusted.example","Access-Control-Allow-Credentials":"true"})
        elif path == "/open-redirect":
            location=parse_qs(urlsplit(self.path).query).get("next",["/about"])[0]
            self._send("",status=302,extra={"Location":location})
        elif path == "/safe-redirect":
            self._send("",status=302,extra={"Location":"/about"})
        elif path == "/admin/panel":
            self._send("<html><body>admin</body></html>")
        elif path == "/page-error":
            self._send(ERROR_HTML)
        elif path == "/large":
            self._send(b"x" * 65536, "text/plain")
        elif path == "/robots.txt":
            self._send(ROBOTS, "text/plain")
        elif path == "/sitemap.xml":
            self._send(SITEMAP.format(base=base), "application/xml")
        elif path == "/sitemap-index.xml":
            self._send(f"<sitemapindex><sitemap><loc>{base}/sitemap-child.xml</loc></sitemap></sitemapindex>", "application/xml")
        elif path == "/sitemap-child.xml":
            self._send(f"<urlset><url><loc>{base}/from-index</loc></url></urlset>", "application/xml")
        elif path == "/openapi.json":
            contract = {"openapi":"3.0.3","paths":{"/api/orders/{order_id}":{"parameters":[{"name":"order_id","in":"path","required":True,"schema":{"type":"integer"}}],"get":{"operationId":"getOrder","parameters":[{"name":"expand","in":"query","schema":{"type":"boolean"}}],"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object"}}}}}}}}}
            self._send(json.dumps(contract), "application/json")
        elif path == "/static/app.js":
            self._send(APP_JS, "application/javascript")
        else:
            self._send("<html><body>not found</body></html>", status=404)


@pytest.fixture(scope="session")
def mock_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
