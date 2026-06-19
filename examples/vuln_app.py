"""A deliberately vulnerable demo app — a small lab to practise against and to
exercise wraith's web phases. FOR LOCAL TESTING ONLY.

    python3 examples/vuln_app.py            # default port 8080 (PORT env to change)

Planted issues (and the phase that finds each):
  /admin                  logged-in but no role check     -> access-control (BAC)
  /account/orders/<id>    no ownership check on id         -> access-control (IDOR)
  /search?q=              reflects q unescaped             -> injection (XSS)
  /product?id=            quote triggers a SQL error       -> injection (SQLi error-based)
  /profile?id=            verbose DB error leaks via it     -> error-based exfil lab (hickok extractvalue)
  /items?id=              FALSE condition empties the page -> injection (SQLi boolean-blind)
  /db?id=                 boolean-blind SQLi over a real sqlite DB (walk it with hickok sql)
  /news?id=               UNION-based SQLi (reflected) over the same DB
  /lookup?token=          honours an injected SQL sleep    -> injection (SQLi time-blind)
  /watch?id=              sleeps only on a paren breakout  -> injection (SQLi time-blind, paren context)
  /ping?host=             shell metachars run (sleep)      -> injection (command injection)
  /render?name=           evaluates {{a*b}} server-side    -> injection (SSTI)
  /download?file=         ../../etc/passwd traversal       -> injection (path traversal/LFI)
  /go?url=                redirects to user input          -> injection (open redirect)
  /api/data              reflects Origin + credentials     -> security-headers (CORS)
  (no CSP/XFO/HSTS, insecure cookie on /)                  -> security-headers
Control (must NOT be flagged):
  /admin-secure           proper admin role enforcement
"""

import html
import os
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = int(os.environ.get("PORT", "8080"))

# A real (tiny) database behind a boolean-blind SQL injection, so a tool can
# walk it: enumerate tables/columns and dump rows. FOR LOCAL TESTING ONLY.
_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB_LOCK = threading.Lock()
_DB.executescript(
    "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);"
    "INSERT INTO users VALUES (1,'admin','s3cr3t!'),(2,'alice','wonderland'),(3,'bob','hunter2');"
    "CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT, value TEXT);"
    "INSERT INTO secrets VALUES (1,'flag','HCK{the_house_always_collects}');"
    "CREATE TABLE news (id INTEGER PRIMARY KEY, title TEXT, body TEXT);"
    "INSERT INTO news VALUES (1,'Welcome','first post'),(2,'Update','second post');"
)
# A sleep() so the in-memory sqlite can honour conditional time-based payloads
# (real sqlite has none) — lets the lab exercise time-based blind SQLi.
_DB.create_function("sleep", 1, lambda n: time.sleep(min(float(n), 8)) or 0)


def _sql_sleep(raw: str) -> None:
    """Simulate a blind SQLi sink: honour an injected SLEEP/pg_sleep/WAITFOR so
    the response time leaks the truth even when the output never changes."""
    m = re.search(r"(?:sleep|pg_sleep)\((\d+)\)|WAITFOR DELAY '0:0:(\d+)'", raw, re.I)
    if m:
        time.sleep(min(int(m.group(1) or m.group(2)), 10))


def _render_template(s: str) -> str:
    """Simulate a template engine that evaluates `a*b` (the SSTI sink)."""
    mul = lambda m: str(int(m.group(1)) * int(m.group(2)))
    for pat in (r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", r"\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}",
                r"<%=\s*(\d+)\s*\*\s*(\d+)\s*%>", r"#\{\s*(\d+)\s*\*\s*(\d+)\s*\}"):
        s = re.sub(pat, mul, s)
    return s

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
                '<a href="/profile?id=1">Profile</a> '
                '<a href="/items?id=1">Items</a> '
                '<a href="/db?id=1">DB</a> '
                '<a href="/lookup?token=abc">Lookup</a> '
                '<a href="/watch?id=1">Watch</a> '
                '<a href="/ping?host=127.0.0.1">Ping</a> '
                '<a href="/render?name=guest">Greet</a> '
                '<a href="/download?file=readme.txt">Download</a> '
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
            # VULNERABLE: error-based SQLi — only an *unbalanced* quote breaks the
            # query (a balanced one parses fine), exactly like a real string sink.
            if pid.count("'") % 2 or pid.count('"') % 2:
                return self._send(500, page(
                    "<h1>Error</h1><pre>You have an error in your SQL syntax; check the manual "
                    "near \"'\" at line 1</pre>"))
            return self._send(200, page(f"<h1>Product {pid}</h1><p>A fine product.</p>"))

        if path == "/profile":
            # VULNERABLE: error-based SQLi with a *verbose* DB error. The app echoes
            # the database error, so an extractvalue/updatexml-style payload leaks
            # data inside it (the classic error-based exfil) — a ground-truth lab
            # for an error-based oracle: send
            #   id=1 AND extractvalue(1,concat(0x7e,(SELECT password FROM users WHERE id=1)))
            # and read the value back out of the error. A bare odd quote just errors.
            raw = (query.get("id") or ["1"])[0]
            sub = re.search(r"\((SELECT\b(?:[^()]|\([^()]*\))*)\)", raw, re.I)
            if re.search(r"extractvalue|updatexml", raw, re.I) and sub:
                try:
                    with _DB_LOCK:
                        row = _DB.execute(sub.group(1)).fetchone()
                    leaked = "" if row is None else str(row[0])
                except Exception as exc:
                    leaked = str(exc)
                return self._send(500, page(f"<pre>XPATH syntax error: '~{html.escape(leaked)}'</pre>"))
            if raw.count("'") % 2 or raw.count('"') % 2:
                return self._send(500, page(
                    "<h1>Error</h1><pre>You have an error in your SQL syntax; check the manual "
                    "near \"'\" at line 1</pre>"))
            return self._send(200, page(f"<h1>Profile {html.escape(raw)}</h1><p>member since 2021.</p>"))

        if path == "/items":
            # VULNERABLE: boolean-blind SQLi — a FALSE condition empties the list.
            raw = (query.get("id") or ["1"])[0]
            _sql_sleep(raw)
            if re.search(r"'1'\s*=\s*'2|\"1\"\s*=\s*\"2|\b1\s*=\s*2\b", raw):
                return self._send(200, page("<h1>Items</h1><p>No items found.</p>"))
            return self._send(200, page("<h1>Items</h1><ul><li>Widget — $9.99</li>"
                                        "<li>Gadget — $19.99</li></ul>"))

        if path == "/lookup":
            # VULNERABLE: time-blind SQLi — output is constant, only timing leaks.
            _sql_sleep((query.get("token") or ["abc"])[0])
            return self._send(200, page("<h1>Lookup</h1><p>Token processed.</p>"))

        if path == "/watch":
            # VULNERABLE: time-blind SQLi in a *parenthesised string* context — the
            # value sits inside func('…'), so a sleep only fires when the payload
            # closes both the quote and the paren ( ') ). A plain 1' (string) or 1
            # (numeric) breakout leaves the paren unclosed and never delays — only
            # the paren variant works, exercising that time-based context.
            raw = (query.get("id") or ["1"])[0]
            if "')" in raw:
                _sql_sleep(raw)
            return self._send(200, page("<h1>Watch</h1><p>access logged.</p>"))

        if path == "/db":
            # VULNERABLE: boolean-blind SQLi over a real database — the input is
            # concatenated into a string-context query. A tool can extract data
            # bit by bit (account active vs not) to walk the whole DB.
            raw = (query.get("id") or ["1"])[0]
            try:
                with _DB_LOCK:
                    row = _DB.execute(f"SELECT username FROM users WHERE id = '{raw}'").fetchone()
            except Exception:
                row = None                       # malformed query -> error swallowed
            return self._send(200, page("<h1>Account active</h1>" if row
                                        else "<h1>No such account</h1>"))

        if path == "/vault":
            # VULNERABLE: time-blind SQLi — the response is ALWAYS identical, so
            # nothing leaks but the response *time* (only time-based works here).
            raw = (query.get("id") or ["1"])[0]
            try:
                with _DB_LOCK:
                    _DB.execute(f"SELECT 1 FROM users WHERE id = '{raw}'").fetchone()
            except Exception:
                pass
            return self._send(200, page("<h1>Vault</h1><p>Access logged.</p>"))

        if path == "/news":
            # VULNERABLE: UNION-based SQLi — two columns reflected into the page,
            # so a tool can UNION SELECT data straight into the response.
            raw = (query.get("id") or ["1"])[0]
            try:
                with _DB_LOCK:
                    row = _DB.execute(f"SELECT title, body FROM news WHERE id = '{raw}'").fetchone()
            except Exception:
                row = None
            if row:
                return self._send(200, page(f"<h1>{html.escape(str(row[0]))}</h1>"
                                            f"<p>{html.escape(str(row[1]))}</p>"))
            return self._send(200, page("<h1>No article</h1>"))

        if path == "/ping":
            # VULNERABLE: command injection — shell metacharacters execute.
            raw = (query.get("host") or ["127.0.0.1"])[0]
            m = re.search(r"sleep\s+(\d+)", raw)
            if m:
                time.sleep(min(int(m.group(1)), 10))
            return self._send(200, page(f"<h1>Ping</h1><pre>PING {html.escape(raw)}</pre>"))

        if path == "/render":
            # VULNERABLE: SSTI — the name is rendered through a template engine.
            name = (query.get("name") or ["guest"])[0]
            return self._send(200, page(f"<h1>Welcome {html.escape(_render_template(name))}</h1>"))

        if path == "/download":
            # VULNERABLE: path traversal / LFI — the path isn't constrained.
            f = (query.get("file") or ["readme.txt"])[0]
            low = f.replace("\\", "/").lower()
            if "etc/passwd" in low:
                return self._send(200, (b"root:x:0:0:root:/root:/bin/bash\n"
                                        b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                                        b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"))
            if "win.ini" in low:
                return self._send(200, b"[fonts]\r\n[extensions]\r\n[mci extensions]\r\n")
            return self._send(200, page(f"<h1>{html.escape(f)}</h1><pre>(file contents)</pre>"))

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
    # Threaded so concurrent time-based probes don't queue behind each other.
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
