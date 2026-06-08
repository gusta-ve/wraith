"""A deliberately vulnerable demo app to exercise the access-control phase.

Run it, then point wraith at it with examples/sessions.json:

    python3 examples/vuln_app.py &
    PYTHONPATH=src python3 -m wraith run 127.0.0.1 \
        --phases access-control --sessions examples/sessions.json

Vulnerabilities planted:
  * /admin                  — logged-in check only, NO role check   (vertical BAC)
  * /account/orders/<id>    — NO ownership check on the id           (IDOR)
Control (must NOT be flagged):
  * /admin-secure           — proper admin role enforcement
  * /                       — genuinely public
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

PORT = int(os.environ.get("PORT", "8009"))

# cookie token -> (display name, role)
USERS = {
    "admin-token": ("admin", "admin"),
    "alice-token": ("alice", "user"),
    "bob-token": ("bob", "user"),
}

# order id -> (owner, description). Each user "owns" one order.
ORDERS = {
    1: ("alice", "Keyboard — $80"),
    2: ("bob", "Monitor — $300"),
    3: ("admin", "Server rack — $5000"),
}
OWN_ORDER = {"alice": 1, "bob": 2, "admin": 3}


def page(body: str) -> bytes:
    return f"<html><head><title>shop</title></head><body>{body}</body></html>".encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # quiet

    def _user(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if part.strip().startswith("session="):
                token = part.strip().split("=", 1)[1]
                return USERS.get(token)
        return None

    def _send(self, status, body=b"", location=None):
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        user = self._user()

        if path == "/":
            return self._send(200, page(
                "<h1>ShopDemo</h1>"
                '<a href="/account">My account</a> '
                '<a href="/admin">Admin</a> '
                '<a href="/admin-secure">Admin (secure)</a>'
            ))

        if path == "/login":
            return self._send(200, page(
                '<h1>Login</h1><form method="post">'
                '<input name="user"><input type="password" name="pass"></form>'
            ))

        if path == "/account":
            if not user:
                return self._send(302, location="/login")
            name, _ = user
            oid = OWN_ORDER.get(name, 0)
            return self._send(200, page(
                f"<h1>Account: {name}</h1>"
                f'<a href="/account/orders/{oid}">My order #{oid}</a>'
            ))

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
            # VULNERABLE: never checks that `user` owns this order.
            return self._send(200, page(f"<h1>Order #{oid}</h1><p>Owner: {owner}</p><p>{desc}</p>"))

        if path == "/admin":
            if not user:
                return self._send(302, location="/login")
            # VULNERABLE: only checks login, not the admin role.
            return self._send(200, page("<h1>Admin Dashboard</h1><p>Revenue: $1,204,553</p><p>Users: 91,402</p>"))

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
