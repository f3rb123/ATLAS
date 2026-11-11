"""Loopback-only dashboard; read the real controller and mutate only its owned runs."""

import hmac
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


def start(controller, port=6777):
    nonce = secrets.token_urlsafe(32)
    assets = Path(__file__).parent / "data/skunk"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def allowed_host(self):
            try:
                hostname = urlsplit("http://" + self.headers.get("Host", "")).hostname
            except ValueError:
                return False
            return hostname in ("127.0.0.1", "localhost", "::1") or bool(hostname and hostname.endswith(".ts.net"))

        def reply(self, status, body, kind="application/json; charset=utf-8"):
            content = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(content)

        def do_GET(self):
            if not self.allowed_host():
                return self.reply(403, '{"error":"Host denied"}')
            path = urlsplit(self.path).path
            if path == "/api/state":
                try:
                    return self.reply(200, json.dumps({**controller.snapshot(), "control_nonce": nonce}))
                except Exception:
                    return self.reply(503, '{"error":"State is temporarily unavailable"}')
            if path == "/skunk.svg":
                from .skunk_art import svg
                return self.reply(200, svg(), "image/svg+xml")
            files = {"/": ("index.html", "text/html; charset=utf-8"),
                     "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                     "/style.css": ("style.css", "text/css; charset=utf-8")}
            if path not in files:
                return self.reply(404, '{"error":"Not found"}')
            name, kind = files[path]
            return self.reply(200, (assets / name).read_bytes(), kind)

        def do_POST(self):
            if not self.allowed_host() or urlsplit(self.path).path != "/api/control":
                return self.reply(403, '{"error":"Denied"}')
            if not hmac.compare_digest(self.headers.get("X-SKUNK-Control", ""), nonce):
                return self.reply(403, '{"error":"Control token missing"}')
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 512 or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                    raise ValueError("Invalid control request")
                body = json.loads(self.rfile.read(size))
                if set(body) != {"action"}:
                    raise ValueError("Only pause, resume and cancel are supported")
                controller.control(body["action"])
                return self.reply(200, '{"ok":true}')
            except (ValueError, TypeError, KeyError) as error:
                return self.reply(400, json.dumps({"error": str(error)[:180]}))
            except Exception:
                return self.reply(503, '{"error":"Control could not be committed; try again"}')

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="skunk-dashboard", daemon=True)
    thread.start()
    return server
