"""Isolated scanner subprocess entrypoint. Stdlib only; no database or credentials.

Runs inside an empty network namespace. The sole bridge is a bounded Unix
socket whose parent enforces the run's target policy for every HTTP request.
"""

import http.server
import json
import os
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        packet, connection = self.request
        try:
            if len(packet) > 4096 or len(packet) < 17 or packet[4:6] != b"\x00\x01":
                return
            offset = 12
            labels = []
            while packet[offset]:
                count = packet[offset]
                if count > 63:
                    raise ValueError("Invalid DNS label")
                labels.append(packet[offset + 1 : offset + 1 + count].decode("ascii"))
                offset += count + 1
            end = offset + 5
            record_type = struct.unpack("!H", packet[offset + 1 : offset + 3])[0]
            if record_type not in (1, 28):
                addresses = []
            else:
                addresses = rpc(
                    {
                        "kind": "dns",
                        "hostname": ".".join(labels),
                        "record_type": "A" if record_type == 1 else "AAAA",
                    }
                ).get("addresses", [])
            records = []
            for address in addresses[:50]:
                value = socket.inet_pton(
                    socket.AF_INET if record_type == 1 else socket.AF_INET6, address
                )
                records.append(
                    b"\xc0\x0c"
                    + struct.pack("!HHIH", record_type, 1, 30, len(value))
                    + value
                )
            header = (
                packet[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, len(records), 0, 0)
            )
            connection.sendto(
                header + packet[12:end] + b"".join(records), self.client_address
            )
        except (OSError, ValueError, IndexError, KeyError, struct.error):
            pass


class Socks(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            version, count = self.rfile.read(2)
            if version != 5:
                return
            self.rfile.read(count)
            self.wfile.write(b"\x05\x00")
            self.wfile.flush()
            version, command, _, kind = self.rfile.read(4)
            if version != 5 or command != 1:
                return
            if kind == 1:
                hostname = socket.inet_ntop(socket.AF_INET, self.rfile.read(4))
            elif kind == 4:
                hostname = socket.inet_ntop(socket.AF_INET6, self.rfile.read(16))
            elif kind == 3:
                hostname = self.rfile.read(self.rfile.read(1)[0]).decode("ascii")
            else:
                return
            port = struct.unpack("!H", self.rfile.read(2))[0]
            result = rpc({"kind": "connect", "hostname": hostname, "port": port})
            self.wfile.write(
                b"\x05"
                + (b"\x00" if result.get("open") else b"\x05")
                + b"\x00\x01"
                + b"\x00" * 6
            )
            self.wfile.flush()
        # Connect-only scanning never forwards arbitrary application bytes.
        except (OSError, ValueError, IndexError):
            pass


def rpc(value):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(40)
        connection.connect("/bridge/requests.sock")
        connection.sendall(json.dumps(value).encode() + b"\n")
        with connection.makefile("rb") as source:
            data = source.readline(2 * 1024 * 1024)
        return json.loads(data)


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    tunnel = None

    def log_message(self, *_):
        pass

    def do_CONNECT(self):
        self.tunnel = self.path
        self.send_response(200, "Connection established")
        self.end_headers()
        self.wfile.flush()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("/work/proxy.crt", "/work/proxy.key")
        try:
            self.connection = context.wrap_socket(self.connection, server_side=True)
            self.rfile = self.connection.makefile("rb")
            self.wfile = self.connection.makefile("wb")
            self.close_connection = False
            self.handle_one_request()
        except (OSError, ssl.SSLError):
            pass
        self.close_connection = True

    def forward(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 <= length <= 16384 or self.headers.get("Transfer-Encoding"):
            self.send_error(413)
            return
        url = ("https://" + self.tunnel + self.path) if self.tunnel else self.path
        if urlsplit(url).scheme not in ("http", "https"):
            self.send_error(400)
            return
        permitted = {
            "accept",
            "user-agent",
            "content-type",
            "origin",
            "referer",
            "range",
            "if-none-match",
            "if-modified-since",
        }
        value = {
            "url": url,
            "method": self.command,
            "headers": {
                k: v for k, v in self.headers.items() if k.lower() in permitted
            },
            "body": self.rfile.read(length).decode("utf-8") if length else None,
        }
        try:
            result = rpc(value)
            if result.get("error"):
                self.send_error(403, "ATLAS scope or quota denied")
                return
            body = result.get("body", "").encode()
            self.send_response(result["status"])
            for k, v in result.get("headers", {}).items():
                if k.lower() not in (
                    "content-length",
                    "transfer-encoding",
                    "connection",
                    "content-encoding",
                    "proxy-authenticate",
                ):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (ValueError, OSError, KeyError):
            self.send_error(502, "ATLAS bridge unavailable")

    do_GET = forward
    do_HEAD = forward
    do_OPTIONS = forward
    do_POST = forward
    do_PUT = forward
    do_DELETE = forward


def main():
    config = json.load(open("/work/config.json"))
    proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    dns = socketserver.ThreadingUDPServer(("127.0.0.1", 15353), DNS)
    socks = socketserver.ThreadingTCPServer(("127.0.0.1", 18081), Socks)
    threading.Thread(target=dns.serve_forever, daemon=True).start()
    threading.Thread(target=socks.serve_forever, daemon=True).start()
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "GOMAXPROCS": "2",
        "GOMEMLIMIT": "512MiB",
        "SSL_CERT_FILE": "/work/ca.crt",
        "HTTP_PROXY": "http://127.0.0.1:18080",
        "HTTPS_PROXY": "http://127.0.0.1:18080",
        "http_proxy": "http://127.0.0.1:18080",
        "https_proxy": "http://127.0.0.1:18080",
        "NO_PROXY": "",
        "no_proxy": "",
    }
    with tempfile.TemporaryFile() as capture:
        try:
            process = subprocess.run(
                config["argv"],
                input=config.get("stdin", "").encode(),
                stdout=capture,
                stderr=subprocess.STDOUT,
                env=env,
                timeout=config["timeout"],
            )
            code = process.returncode
            timed_out = False
        except subprocess.TimeoutExpired:
            code = None
            timed_out = True
        capture.seek(0)
        output = capture.read(1024 * 1024).decode(errors="replace")
    extra = None
    if os.path.isfile("/tmp/tool-output.json"):
        with open("/tmp/tool-output.json") as source:
            text = source.read(1024 * 1024)
        try:
            extra = json.loads(text)
        except ValueError:
            pass
    print(
        json.dumps(
            {
                "exit_code": code,
                "timed_out": timed_out,
                "output": output,
                "structured_output": extra,
            }
        )
    )


if __name__ == "__main__":
    main()
