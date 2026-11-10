"""Canonical URLs and connection-time pinned DNS. Deny wins; no model authority."""

import http.client, ipaddress, socket, ssl, os, re
import time, threading
from urllib.parse import urlsplit, urlunsplit, unquote
from urllib.request import getproxies, proxy_bypass
from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated


class Denied(ValueError):
    pass


def readonly_target_request(url, method):
    """Execution-layer guard, independent of model instructions or consent text."""
    from urllib.parse import parse_qsl

    if method.upper() not in ("GET", "HEAD"):
        raise Denied("State-changing target methods are unavailable")
    parsed = urlsplit(url)
    if re.search(
        r"(?i)(?:^|/)_?(?:delete|remove|drop|truncate|destroy|purge|wipe|logout|signout|revoke|deactivate|shutdown|terminate|erase)(?:[/._-]|$)",
        unquote(parsed.path),
    ):
        raise Denied("Destructive target routes are unavailable")
    forbidden = re.compile(
        r"(?i)\b(?:delete|drop|truncate|alter|shutdown|reboot|remove-item|rmdir|unlink|rm\s+-(?=[a-z]*r)[a-z]+)\b"
    )
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in {"cmd", "command", "exec", "shell", "powershell"}:
            raise Denied("Remote command interfaces are unavailable")
        if forbidden.search(value) or (
            key.lower()
            in {"action", "operation", "op", "cmd", "command", "method", "_method"}
            and re.search(
                r"(?i)\b(?:delete|remove|drop|truncate|destroy|purge|wipe|shutdown|reboot)\b",
                value,
            )
        ):
            raise Denied("Destructive target parameters are unavailable")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Rule(Strict):
    host: str
    ports: list[Annotated[int, Field(ge=1, le=65535, strict=True)]] = [443]
    schemes: list[str] = ["https"]
    paths: list[str] = ["/"]
    methods: list[str] = ["GET", "HEAD"]


class Scope(Strict):
    allow: list[Rule] = Field(default=[], max_length=100)
    deny: list[Rule] = Field(default=[], max_length=100)
    lab_networks: list[str] = Field(default=[], max_length=20)
    expires: float | None = Field(default=None, gt=0, allow_inf_nan=False)
    max_requests: int = Field(default=100, ge=1, le=100000)
    max_response_bytes: int = Field(default=1024 * 1024, ge=1, le=10 * 1024 * 1024)
    max_seconds: int = Field(default=15, ge=1, le=30)
    min_request_interval: float = Field(default=1, ge=0.01, le=60, allow_inf_nan=False)
    test_classes: list[str] = Field(default=["surface", "headers"], max_length=20)
    post_paths: list[str] = Field(default=[], max_length=50)


def nondestructive_target_request(scope, url, method, body=None, purpose="navigation"):
    """A fixed execution boundary for web assessments, independent of model consent."""
    import json

    method = method.upper()
    if method not in ("GET", "HEAD", "OPTIONS", "POST"):
        raise Denied("Destructive or unregistered target method")
    # Reuse the route/query guard for every allowed verb, including POST/OPTIONS.
    readonly_target_request(url, "GET")
    if body is not None:
        if len(body.encode()) > 16384:
            raise Denied("Target request body quota exceeded")
        text = re.sub(r"/\*.*?\*/", " ", unquote(body), flags=re.S)
        if re.search(
            r"(?i)\b(?:drop|truncate|delete|shutdown|reboot|unlink|rmdir)\b|\brm\s+-[a-z]*r",
            text,
        ):
            raise Denied("Destructive target body denied")
    if method == "POST":
        path = urlsplit(url).path or "/"
        if path not in scope.post_paths:
            raise Denied("POST endpoint was not explicitly authorized")
        if purpose not in ("graphql_read", "authentication", "read_json"):
            raise Denied("POST requires a registered non-destructive purpose")
        if purpose == "graphql_read":
            if "graphql" not in scope.test_classes:
                raise Denied("GraphQL checks not authorized")
            try:
                query = json.loads(body or "{}").get("query", "")
            except (ValueError, AttributeError):
                raise Denied("GraphQL requires a JSON query") from None
            # Reject alternate operations even when hidden in comments/strings.
            if (
                not isinstance(query, str)
                or not query.strip()
                or re.search(r"(?i)\b(?:mutation|subscription)\b", query)
            ):
                raise Denied("Only read-only GraphQL queries are registered")
        elif purpose not in scope.test_classes:
            raise Denied("Target POST purpose not authorized")
    elif body is not None:
        raise Denied("Request bodies require an explicitly authorized POST")


def host(h):
    h = h.rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    try:
        h = h.encode("idna").decode("ascii")
    except UnicodeError:
        raise Denied("Invalid IDNA host")
    if len(h) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", s)
        for s in h.split(".")
    ):
        raise Denied("Malformed hostname")
    if re.fullmatch(r"[0-9.xa-f]+", h) and (
        h.startswith("0x") or h.replace(".", "").isdigit()
    ):
        raise Denied("Ambiguous numeric host")
    return h


def normalize(url):
    if re.search(r"[\x00-\x20\x7f\\]", url):
        raise Denied("Unsafe URL character")
    try:
        u = urlsplit(url)
        if (
            u.scheme not in ("https", "http")
            or not u.hostname
            or u.username
            or u.password
        ):
            raise Denied("Unsupported URL")
        h = host(u.hostname)
        p = u.port if u.port is not None else (443 if u.scheme == "https" else 80)
        if not 1 <= p <= 65535:
            raise Denied("Invalid destination port")
    except ValueError:
        raise Denied("Invalid URL host or port")
    path = u.path or "/"
    decoded = unquote(path)
    if (
        decoded != path
        or any(s in (".", "..") for s in path.split("/"))
        or "//" in path
    ):
        raise Denied("Ambiguous encoded path")
    net = f"[{h}]" if ":" in h else h
    return urlunsplit((u.scheme, f"{net}:{p}", path, u.query, "")), h, p, path, u.scheme


def match(rule, h, p, path, scheme, method):
    pattern = rule.host
    if "/" in pattern:
        try:
            ok = ipaddress.ip_address(h) in ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            ok = False
    elif pattern.startswith("*."):
        suffix = host(pattern[2:])
        ok = h.endswith("." + suffix) and h != suffix
    else:
        ok = h == host(pattern)
    return (
        ok
        and p in rule.ports
        and scheme in rule.schemes
        and method in rule.methods
        and any(path == x or path.startswith(x.rstrip("/") + "/") for x in rule.paths)
    )


def addresses(h, p, lab=(), resolver=socket.getaddrinfo):
    try:
        ips = sorted({r[4][0] for r in resolver(h, p, type=socket.SOCK_STREAM)})
    except OSError:
        raise Denied("DNS resolution failed")
    if not ips:
        raise Denied("No destination addresses")
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if (
            addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
            or getattr(addr, "ipv4_mapped", None)
        ):
            raise Denied("Forbidden destination")
        permitted = any(addr in ipaddress.ip_network(n) for n in lab)
        if not addr.is_global and not permitted:
            raise Denied("Non-public destination")
    return ips


def authorize(scope, url, method="GET", resolver=socket.getaddrinfo):
    import time

    s = Scope.model_validate(scope) if isinstance(scope, dict) else scope
    if s.expires and s.expires < time.time():
        raise Denied("Policy expired")
    n, h, p, path, scheme = normalize(url)
    if any(match(r, h, p, path, scheme, method) for r in s.deny) or not any(
        match(r, h, p, path, scheme, method) for r in s.allow
    ):
        raise Denied("Out of scope")
    return n, h, p, addresses(h, p, s.lab_networks, resolver)


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self, hostname, ip, port, tls, timeout):
        super().__init__(hostname, port, timeout=timeout)
        self.ip = ip
        self.tls = tls

    def connect(self):
        proxies = getproxies()
        proxy = proxies.get("https" if self.tls else "http")
        if proxy and not proxy_bypass(self.host):
            u = urlsplit(proxy)
            if u.scheme != "http" or u.username or u.password:
                raise Denied("Unsupported egress proxy configuration")
            relay = http.client.HTTPConnection(
                u.hostname, u.port or 80, timeout=self.timeout
            )
            self.proxy_connection = relay
            relay.set_tunnel(self.ip, self.port)
            relay.connect()
            self.sock = relay.sock
        else:
            self.sock = socket.create_connection((self.ip, self.port), self.timeout)
        if getattr(self, "deadline_monotonic", None) is not None:
            left = self.deadline_monotonic - time.monotonic()
            if left <= 0:
                self.sock.close()
                raise TimeoutError("HTTP request deadline exceeded")
            self.sock.settimeout(left)
        if self.tls:
            self.sock = ssl.create_default_context().wrap_socket(
                self.sock, server_hostname=self.host
            )


def request(
    url,
    method="GET",
    headers=None,
    body=None,
    scope=None,
    max_bytes=1048576,
    timeout=15,
    return_redirect=False,
    deadline=None,
):
    n, h, p, ips = authorize(scope, url, method)
    if deadline is not None:
        timeout = min(timeout, deadline - time.time())
    if timeout <= 0:
        raise TimeoutError("HTTP request deadline exceeded before dispatch")
    c = PinnedConnection(h, ips[0], p, n.startswith("https:"), timeout)
    c.deadline_monotonic = time.monotonic() + timeout
    expired = threading.Event()
    response_sockets = []

    def abort():
        expired.set()
        for connection in [
            getattr(c, "sock", None),
            getattr(getattr(c, "proxy_connection", None), "sock", None),
            *response_sockets,
        ]:
            if connection:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except (OSError, AttributeError):
                    pass

    timer = threading.Timer(timeout, abort)
    timer.daemon = True
    timer.start()
    u = urlsplit(n)
    target = u.path + ("?" + u.query if u.query else "")
    try:
        c.request(method, target, body=body, headers=headers or {})
        r = c.getresponse()
        reader_socket = getattr(
            getattr(getattr(r, "fp", None), "raw", None), "_sock", None
        )
        if reader_socket:
            response_sockets.append(reader_socket)
        if 300 <= r.status < 400 and not return_redirect:
            raise Denied(
                "Redirect disabled; destination must be independently approved"
            )
        if r.getheader("Content-Encoding", "identity") != "identity":
            raise Denied("Compressed responses not accepted")
        content = bytearray()
        reader = getattr(r, "read1", r.read)
        while len(content) <= max_bytes:
            if expired.is_set():
                raise TimeoutError("HTTP response deadline exceeded")
            chunk = reader(min(65536, max_bytes + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        content = bytes(content)
        if len(content) > max_bytes:
            raise Denied("Response size exceeded")
        received = dict(r.getheaders())
        cookies = [
            value for key, value in r.getheaders() if key.lower() == "set-cookie"
        ]
        if cookies:
            received["Set-Cookie"] = "\n".join(cookies)
        if expired.is_set():
            raise TimeoutError("HTTP response deadline exceeded")
        return r.status, received, content
    except Exception:
        if expired.is_set():
            raise TimeoutError("HTTP request deadline exceeded") from None
        raise
    finally:
        timer.cancel()
        c.close()
