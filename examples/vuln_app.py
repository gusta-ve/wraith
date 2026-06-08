"""A deliberately vulnerable demo app — a small lab to practise against and to
exercise wraith's web phases. FOR LOCAL TESTING ONLY.

    python3 examples/vuln_app.py            # default port 8009 (PORT env to change)

Planted issues (and the phase that finds each):
  /admin                  logged-in but no role check     -> access-control (BAC)
  /account/orders/<id>    no ownership check on id         -> access-control (IDOR)
  /search?q=              reflects q unescaped             -> injection (XSS)
  /product?id=            quote triggers a SQL error       -> injection (SQLi)
  /go?url=                redirects to user input          -> injection (open redirect)
  /api/data              reflects Origin + credentials     -> security-headers (CORS)
  (no CSP/XFO/HSTS, insecure cookie on /)                  -> security-headers
Control (must NOT be flagged):
  /admin-secure           proper admin role enforcement
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = int(os.environ.get("PORT", "8009"))

USERS = {"admin-token": ("admin", "admin"), "alice-token": ("alice", "user"), "bob-token": ("bob", "user")}
ORDERS = {1: ("alice", "Keyboard — $80"), 2: ("bob", "Monitor — $300"), 3: ("admin", "Server rack — $5000")}
OWN_ORDER = {"alice": 1, "bob": 2, "admin": 3}
LOGIN_TOKENS = {"alice": "alice-token", "bob": "bob-token", "admin": "admin-token"}


def page(body: str) -> bytes:
    return f"<html><head><title>shop</title></head><body>{body}</body></html>".encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _user(self):
        for part in self.headers.get("Cookie", "").split(";"):
            if part.strip().startswith("session="):
                return USERS.get(part.strip().split("=", 1)[1])
        return None

    def _send(self, status, body=b"", location=None, extra=None):
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/login":
            length = int(self.headers.get("Content-Length", "0") or 0)
            form = parse_qs(self.rfile.read(length).decode("utf-8", "ignore"))
            user = (form.get("user") or form.get("username") or [""])[0]
            token = LOGIN_TOKENS.get(user, "alice-token")
            # VULNERABLE: accepts any password; cookie has no HttpOnly/Secure/SameSite.
            return self._send(302, location="/account", extra={"Set-Cookie": f"session={token}; Path=/"})
        return self._send(404, page("<h1>Not found</h1>"))

    def do_GET(self):
        parts = urlsplit(self.path)
        path, query = parts.path, parse_qs(parts.query)
        user = self._user()

        if path == "/":
            # insecure tracking cookie + no security headers anywhere
            return self._send(200, page(
                "<h1>ShopDemo</h1>"
                '<a href="/account">My account</a> '
                '<a href="/admin">Admin</a> '
                '<a href="/admin-secure">Admin (secure)</a> '
                '<a href="/search?q=test">Search</a> '
                '<a href="/product?id=1">Product</a> '
                '<a href="/go?url=/account">Go</a> '
                '<a href="/login">Login</a>'
            ), extra={"Set-Cookie": "tracking=1; Path=/"})

        if path == "/login":
            return self._send(200, page(
                '<h1>Login</h1>'
                '<form method="post" action="/login">'
                '<input name="user"><input type="password" name="password">'
                '<input type="submit"></form>'
            ))

        if path == "/search":
            q = (query.get("q") or [""])[0]
            # VULNERABLE: reflects user input without encoding.
            return self._send(200, page(f"<h1>Results for {q}</h1><p>nothing found</p>"))

        if path == "/product":
            pid = (query.get("id") or [""])[0]
            # VULNERABLE: simulates an error-based SQL injection.
            if "'" in pid or '"' in pid:
                return self._send(500, page(
                    "<h1>Error</h1><pre>You have an error in your SQL syntax; check the manual "
                    "near \"'\" at line 1</pre>"))
            return self._send(200, page(f"<h1>Product {pid}</h1><p>A fine product.</p>"))

        if path == "/go":
            # VULNERABLE: open redirect.
            return self._send(302, location=(query.get("url") or ["/"])[0])

        if path == "/api/data":
            # VULNERABLE: reflects any Origin and allows credentials.
            origin = self.headers.get("Origin", "*")
            return self._send(200, b'{"ok":true}', extra={
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            })

        if path == "/account":
            if not user:
                return self._send(302, location="/login")
            name, _ = user
            oid = OWN_ORDER.get(name, 0)
            return self._send(200, page(
                f"<h1>Account: {name}</h1><a href=\"/account/orders/{oid}\">My order #{oid}</a>"))

        if path.startswith("/account/orders/"):
            if not user:
                return self._send(302, location="/login")
            try:
                oid = int(path.rsplit("/", 1)[1])
            except ValueError:
                return self._send(404, page("<h1>Not found</h1>"))
            if oid not in ORDERS:
                return self._send(404, page("<h1>Order not found</h1>"))
            owner, desc = ORDERS[oid]
            # VULNERABLE: no ownership check.
            return self._send(200, page(f"<h1>Order #{oid}</h1><p>Owner: {owner}</p><p>{desc}</p>"))

        if path == "/admin":
            if not user:
                return self._send(302, location="/login")
            # VULNERABLE: only checks login, not the admin role.
            return self._send(200, page("<h1>Admin Dashboard</h1><p>Revenue: $1,204,553</p>"))

        if path == "/admin-secure":
            if not user:
                return self._send(302, location="/login")
            if user[1] != "admin":
                return self._send(403, page("<h1>403 Forbidden</h1>"))
            return self._send(200, page("<h1>Admin Dashboard (secure)</h1><p>Revenue: $1,204,553</p>"))

        return self._send(404, page("<h1>Not found</h1>"))


if __name__ == "__main__":
    print(f"vuln_app listening on http://127.0.0.1:{PORT}")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
