"""Controlled local HTTP/DNS harness; no public target requests."""

import time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
import atlas.policy as p


def test_pinned_transport_rebinding_redirect_size_timeout_and_scope_edges(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path == "/slow":
                time.sleep(0.2)
            self.send_response(302 if self.path == "/redirect" else 200)
            if self.path == "/redirect":
                self.send_header("Location", "http://uncontrolled.invalid/")
            self.end_headers()
            try:
                self.wfile.write(b"bounded local fixture response")
            except BrokenPipeError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    port = server.server_port
    lookups = []

    def resolver(h, port, *args, **kw):
        lookups.append(h)
        # Host DNS is allowed once; transport must connect using the pinned numeric IP.
        ip = "127.0.0.1" if h == "127.0.0.1" or lookups.count(h) == 1 else "127.0.0.2"
        return [(2, 1, 6, "", (ip, port))]

    monkeypatch.setattr(p.socket, "getaddrinfo", resolver)
    original = p.authorize
    monkeypatch.setattr(
        p,
        "authorize",
        lambda scope, url, method="GET": original(
            scope, url, method, resolver=resolver
        ),
    )
    scope = p.Scope(
        allow=[p.Rule(host="lab.example.invalid", ports=[port], schemes=["http"])],
        lab_networks=["127.0.0.1/32"],
    )
    url = f"http://lab.example.invalid:{port}"
    try:
        assert p.request(url, scope=scope)[0] == 200
        assert lookups == ["lab.example.invalid", "127.0.0.1"]
        lookups.clear()
        with pytest.raises(p.Denied, match="Redirect"):
            p.request(url + "/redirect", scope=scope)
        lookups.clear()
        with pytest.raises(p.Denied, match="size"):
            p.request(url, scope=scope, max_bytes=3)
        lookups.clear()
        with pytest.raises(TimeoutError):
            p.request(url + "/slow", scope=scope, timeout=0.03)
    finally:
        server.shutdown()
    for url in [
        "https://example.com:0",
        "https://example.com:65536",
        "https://example.com/a/../b",
        "https://example.com/%2fprivate",
    ]:
        with pytest.raises(p.Denied):
            p.normalize(url)
    assert p.normalize("https://BÜCHER.example./safe")[1] == "xn--bcher-kva.example"
    assert p.match(
        p.Rule(host="2001:4860::/32"), "2001:4860:4860::8888", 443, "/", "https", "HEAD"
    )
    with pytest.raises(p.Denied, match="expired"):
        original(
            p.Scope(allow=[p.Rule(host="example.com")], expires=time.time() - 1),
            "https://example.com",
        )
