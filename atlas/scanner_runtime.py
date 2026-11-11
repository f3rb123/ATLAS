"""Pinned binary execution behind a network-isolated, policy-enforcing bridge."""

import hashlib
import json
import os
from pathlib import Path
import resource
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field

from .config import settings
from .db import Document, canonical, digest, session
from .policy import Denied, Strict, authorize, normalize
from .vault import redact


HTTP_TOOLS = {"httpx", "katana", "ffuf", "nuclei"}
PASSIVE_TOOLS = {"subfinder", "gau", "waybackurls"}
NETWORK_TOOLS = {"dnsx", "naabu"}
EXECUTABLE_TOOLS = HTTP_TOOLS | PASSIVE_TOOLS | NETWORK_TOOLS


class ScannerInput(Strict):
    tool: Literal[
        "httpx",
        "katana",
        "ffuf",
        "nuclei",
        "subfinder",
        "gau",
        "waybackurls",
        "dnsx",
        "naabu",
    ]
    url: str = Field(max_length=4096)
    max_requests: int = Field(default=15, ge=1, le=100)
    timeout_seconds: int = Field(default=30, ge=5, le=60)
    identity_id: str | None = None
    ports: list[int] = Field(default=[], max_length=20)
    words: list[str] = Field(
        default=[
            "robots.txt",
            "sitemap.xml",
            ".well-known/security.txt",
            "openapi.json",
            "swagger.json",
        ],
        min_length=1,
        max_length=100,
    )


def manifest():
    return json.loads((Path(__file__).parent / "data/research_tools.json").read_text())


def executable(name):
    info = manifest()[name]
    root = Path(
        settings().research_tools_dir or (Path(settings().data_dir) / "research-tools")
    )
    path = root / name / name
    if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
        raise Denied("Pinned tool is not installed: " + name)
    if hashlib.sha256(path.read_bytes()).hexdigest() != info["binary_sha256"]:
        raise Denied("Pinned tool integrity check failed: " + name)
    return path.resolve()


def command(args):
    proxy = "http://127.0.0.1:18080"
    hostname = urlsplit(args.url).hostname
    if args.tool == "subfinder":
        return [
            "/tool",
            "-d",
            hostname,
            "-s",
            "crtsh",
            "-proxy",
            proxy,
            "-silent",
            "-oJ",
            "-rl",
            "2",
            "-timeout",
            "8",
            "-max-time",
            "1",
            "-duc",
        ]
    if args.tool == "gau":
        return [
            "/tool",
            "--providers",
            "wayback",
            "--subs",
            "--threads",
            "1",
            "--timeout",
            "8",
            "--retries",
            "0",
            "--proxy",
            proxy,
            hostname,
        ]
    if args.tool == "waybackurls":
        return ["/tool"]
    if args.tool == "dnsx":
        return [
            "/tool",
            "-l",
            "/work/domains",
            "-r",
            "127.0.0.1:15353",
            "-a",
            "-resp",
            "-json",
            "-silent",
            "-retry",
            "1",
            "-t",
            "1",
            "-rl",
            "2",
            "-duc",
        ]
    if args.tool == "naabu":
        return [
            "/tool",
            "-host",
            hostname,
            "-p",
            ",".join(str(p) for p in args.ports),
            "-scan-type",
            "c",
            "-proxy",
            "127.0.0.1:18081",
            "-r",
            "127.0.0.1:15353",
            "-silent",
            "-json",
            "-rate",
            "2",
            "-c",
            "1",
            "-retries",
            "1",
            "-timeout",
            "1000",
            "-Pn",
            "-duc",
        ]
    if args.tool == "httpx":
        return [
            "/tool",
            "-l",
            "/work/targets",
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-proxy",
            proxy,
            "-threads",
            "1",
            "-rate-limit",
            "2",
            "-timeout",
            "8",
            "-no-fallback",
            "-duc",
        ]
    if args.tool == "katana":
        return [
            "/tool",
            "-u",
            args.url,
            "-jsonl",
            "-silent",
            "-proxy",
            proxy,
            "-concurrency",
            "1",
            "-parallelism",
            "1",
            "-rate-limit",
            "2",
            "-timeout",
            "8",
            "-depth",
            "2",
            "-duc",
        ]
    if args.tool == "ffuf":
        return [
            "/tool",
            "-u",
            args.url.rstrip("/") + "/FUZZ",
            "-w",
            "/work/words",
            "-x",
            proxy,
            "-t",
            "1",
            "-rate",
            "2",
            "-timeout",
            "8",
            "-maxtime",
            str(args.timeout_seconds - 2),
            "-of",
            "json",
            "-o",
            "/tmp/tool-output.json",
            "-s",
            "-noninteractive",
        ]
    if args.tool == "nuclei":
        return [
            "/tool",
            "-l",
            "/work/targets",
            "-t",
            "/work/templates",
            "-jsonl",
            "-silent",
            "-proxy",
            proxy,
            "-c",
            "1",
            "-rl",
            "2",
            "-timeout",
            "8",
            "-retries",
            "0",
            "-duc",
            "-ni",
            "-no-httpx",
        ]
    raise Denied("Tool has no registered command profile")


def certificates(directory, hosts):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "ATLAS isolated scanner bridge")]
    )
    timestamp = datetime.now(timezone.utc)
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(timestamp - timedelta(minutes=1))
        .not_valid_after(timestamp + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    sans = []
    for host in set(hosts):
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            sans.append(x509.DNSName(host))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(timestamp - timedelta(minutes=1))
        .not_valid_after(timestamp + timedelta(hours=2))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )
    (directory / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (directory / "proxy.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "proxy.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def limits():
    from .tools import sandbox_limits

    sandbox_limits()
    # Go reserves a larger virtual arena than Python; physical memory is still
    # bounded by the worker cgroup and Go's environment memory limit.
    # sandbox_limits already set a hard 512MiB limit, so use a separate profile.


def scanner_limits():
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**2, 2 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))


def _run(db, run, args):
    from .web_research import WebRequest, scope_for, send
    from .swarm import check_fence
    import shutil

    scope = scope_for(db, run)
    required = (
        "passive_sources"
        if args.tool in PASSIVE_TOOLS
        else "dns"
        if args.tool == "dnsx"
        else "ports"
        if args.tool == "naabu"
        else "scanners"
    )
    if (
        required not in scope.test_classes
        or run.value().get("assessment_profile") == "smoke_readonly"
    ):
        raise Denied("Scanner execution is outside the frozen campaign policy")
    if not shutil.which("bwrap"):
        raise Denied("Scanner network sandbox unavailable")
    binary = executable(args.tool)
    from .network_research import scoped_origin, METADATA_HOSTS

    hostname = urlsplit(args.url).hostname
    if not hostname:
        raise Denied("Scanner target requires an exact URL/hostname")
    if args.tool in PASSIVE_TOOLS:
        scoped_origin(scope, hostname, metadata=True)
    else:
        authorize(scope, args.url, "GET")
    if args.tool == "naabu":
        if not args.ports:
            args.ports = [
                urlsplit(args.url).port
                or (443 if args.url.startswith("https:") else 80)
            ]
        for port in args.ports:
            if not 1 <= port <= 65535:
                raise Denied("Invalid explicit scan port")
            scoped_origin(scope, hostname, port)
    if any(
        not word
        or len(word) > 200
        or any(ord(c) < 33 for c in word)
        or ".." in word
        or "://" in word
        for word in args.words
    ):
        raise Denied("Content wordlist must contain bounded relative paths")
    claim = getattr(run, "_swarm_claim", None)
    run_id = run.id
    observations = []
    denials = []
    request_count = 0
    lock = threading.Lock()
    job_deadline = min(time.time() + args.timeout_seconds, run.value()["deadline"])
    db.commit()
    with tempfile.TemporaryDirectory(prefix="atlas-scanner-") as temp:
        work = Path(temp) / "work"
        bridge = Path(temp) / "bridge"
        work.mkdir()
        bridge.mkdir()

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                nonlocal request_count
                try:
                    value = json.loads(self.rfile.readline(65536))
                    with lock:
                        if request_count >= args.max_requests:
                            raise Denied("Scanner request quota exhausted")
                        request_count += 1
                    with session() as other:
                        current = other.get(Document, run_id)
                        state = other.get(
                            Document,
                            digest("binary-tool:" + current.owner + ":" + args.tool)[
                                :36
                            ],
                            populate_existing=True,
                        )
                        if state and not state.value().get("enabled"):
                            raise Denied("Scanner disabled during execution")
                        if args.tool == "nuclei":
                            from .scanner_templates import pinned

                            pinned(other, current)
                        if claim:
                            current._swarm_claim = claim
                        from .network_research import send as network_send

                        if value.get("kind") in ("dns", "connect"):
                            if args.tool not in NETWORK_TOOLS:
                                raise Denied("Tool has no raw-network capability")
                            if value["kind"] == "connect":
                                if (
                                    args.tool != "naabu"
                                    or value["port"] not in args.ports
                                ):
                                    raise Denied("Port was not explicitly selected")
                                import ipaddress

                                if value["hostname"] != hostname:
                                    from .policy import addresses

                                    if value["hostname"] not in addresses(
                                        hostname, value["port"], scope.lab_networks
                                    ):
                                        raise Denied(
                                            "SOCKS destination is outside the pinned hostname"
                                        )
                                value["hostname"] = hostname
                            result = network_send(
                                other, current, value, request_deadline=job_deadline
                            )
                        elif args.tool in PASSIVE_TOOLS:
                            if value.get("method") != "GET" or value.get("body"):
                                raise Denied(
                                    "Passive sources allow fixed read-only index queries"
                                )
                            result = network_send(
                                other,
                                current,
                                {
                                    "kind": "metadata",
                                    "hostname": hostname,
                                    "url": value["url"],
                                },
                                request_deadline=job_deadline,
                            )
                        else:
                            request = WebRequest.model_validate(
                                {
                                    **value,
                                    "identity_id": args.identity_id,
                                    "purpose": "probe",
                                }
                            )
                            result = send(
                                other,
                                current,
                                request,
                                "scanner:" + args.tool,
                                request_deadline=job_deadline,
                            )
                    with lock:
                        observations.append(result["observation_id"])
                except Exception as exc:
                    with lock:
                        if len(denials) < 50:
                            denials.append(type(exc).__name__)
                    result = {"error": "Request denied or failed"}
                try:
                    self.wfile.write(canonical(result).encode() + b"\n")
                except OSError:
                    pass

        class Server(socketserver.ThreadingUnixStreamServer):
            daemon_threads = True

        server = Server(str(bridge / "requests.sock"), Handler)
        os.chmod(bridge / "requests.sock", 0o600)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        hosts = (
            [urlsplit(args.url).hostname]
            + list(METADATA_HOSTS)
            + [r.host for r in scope.allow if "/" not in r.host]
        )
        certificates(work, hosts)
        (work / "targets").write_text(args.url + "\n")
        (work / "domains").write_text(hostname + "\n")
        (work / "words").write_text("\n".join(args.words) + "\n")
        templates = work / "templates"
        templates.mkdir()
        for path in (Path(__file__).parent / "data/scanner_templates").glob("*.yaml"):
            (templates / path.name).write_bytes(path.read_bytes())
        from .scanner_templates import pinned

        for row in pinned(db, run):
            (templates / ("owner-" + row.id + ".yaml")).write_text(row.value()["yaml"])
        (work / "config.json").write_text(
            canonical(
                {
                    "argv": command(args),
                    "timeout": args.timeout_seconds,
                    "stdin": hostname + "\n" if args.tool == "waybackurls" else "",
                }
            )
        )
        from .skunk_sandbox import interpreter
        python, runtime_mount = interpreter()
        argv = [
            "bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
            str(work),
            "/work",
            "--ro-bind",
            str(bridge),
            "/bridge",
            "--ro-bind",
            str(binary),
            "/tool",
            "--ro-bind",
            str(Path(__file__).with_name("scanner_child.py")),
            "/scanner_child.py",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/tmp",
            *runtime_mount,
            python,
            "-I",
            "/scanner_child.py",
        ]
        try:
            with tempfile.TemporaryFile() as output:
                process = subprocess.run(
                    argv,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    timeout=args.timeout_seconds + 5,
                    preexec_fn=scanner_limits,
                )
                output.seek(0)
                text = output.read(2 * 1024 * 1024).decode(errors="replace")
            if process.returncode:
                raise Denied("Scanner sandbox failed: " + text[:150])
            result = json.loads(text)
        except subprocess.TimeoutExpired:
            result = {
                "exit_code": None,
                "timed_out": True,
                "output": "Scanner deadline exceeded",
            }
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
    db.expire_all()
    check_fence(db, run)
    result["output"] = redact(result.get("output", ""))[:65536]
    result.update(
        tool=args.tool,
        version=manifest()[args.tool]["version"],
        binary_sha256=manifest()[args.tool]["binary_sha256"],
        observation_ids=observations,
        denied_requests=len(denials),
        request_attempts=request_count,
        network_isolation="unshared namespace; Unix bridge only",
        claims="Unverified scanner observations; independent validation required",
    )
    result.update(discoveries(result, scope))
    return result


def discoveries(result, scope):
    """Normalize vendor output as untrusted, scoped observations, never findings."""
    from .network_research import scoped_origin
    from .policy import host, match

    urls = []
    hosts = []
    matches = []
    values = []
    for line in result.get("output", "").splitlines()[:1000]:
        line = line.strip()
        if line.startswith(("http://", "https://")):
            urls.append(line.split()[0])
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                values.append(value)
        except ValueError:
            pass
    extra = result.get("structured_output")
    if isinstance(extra, dict):
        values.extend(
            item for item in extra.get("results", [])[:200] if isinstance(item, dict)
        )
    for value in values[:500]:
        for key in ("url", "endpoint", "matched-at"):
            if isinstance(value.get(key), str) and value[key].startswith(
                ("http://", "https://")
            ):
                urls.append(value[key])
        if isinstance(value.get("request"), dict) and isinstance(
            value["request"].get("endpoint"), str
        ):
            urls.append(value["request"]["endpoint"])
        for key in ("host", "hostname", "input"):
            if isinstance(value.get(key), str):
                hosts.append(value[key])
        if value.get("template-id"):
            matches.append(
                {
                    "template_id": value["template-id"],
                    "severity": value.get("info", {}).get("severity"),
                    "url": value.get("matched-at"),
                    "status": "unverified_observation",
                }
            )
    accepted_urls = []
    accepted_hosts = []
    for value in dict.fromkeys(urls):
        try:
            normalized, h, p, path, scheme = normalize(value)
            if any(
                match(r, h, p, path, scheme, "GET") for r in scope.allow
            ) and not any(match(r, h, p, path, scheme, "GET") for r in scope.deny):
                accepted_urls.append(normalized)
        except (Denied, ValueError):
            continue
    for value in dict.fromkeys(hosts):
        try:
            hostname = host(urlsplit(value).hostname if "://" in value else value)
            scoped_origin(scope, hostname)
            accepted_hosts.append(hostname)
        except (Denied, ValueError, AttributeError):
            continue
    return {
        "discovered_urls": accepted_urls[:100],
        "discovered_hosts": accepted_hosts[:100],
        "template_observations": matches[:50],
    }


def tool_state(db, owner, name):
    if name not in EXECUTABLE_TOOLS:
        raise Denied("No executable HTTP profile registered")
    row = db.get(Document, digest("binary-tool:" + owner + ":" + name)[:36])
    value = row.value() if row else {"enabled": True, "health": "integrity_verified"}
    try:
        path = executable(name)
        available = __import__("shutil").which("bwrap") is not None
        reason = None if available else "Linux namespace sandbox unavailable"
        if manifest()[name].get("owner_managed") and not value.get(
            "owner_permission_attested"
        ):
            available = False
            reason = manifest()[name]["license_status"]
    except (Denied, OSError) as exc:
        available = False
        reason = str(exc)
    return {
        "name": name,
        "installed": available,
        "available": available,
        "version": manifest()[name]["version"],
        "binary_sha256": manifest()[name]["binary_sha256"],
        "enabled": value.get("enabled", False),
        "health": value.get("health", "untested"),
        "owner_managed": bool(manifest()[name].get("owner_managed")),
        "reason": reason
        or "Pinned profile; all target traffic passes through the scope relay",
    }


def configure(db, owner, name, enabled=None, probe=False):
    from .db import append, document

    info = tool_state(db, owner, name)
    if probe:
        if not info["available"]:
            raise Denied(info["reason"] or "Pinned tool unavailable")
        binary = executable(name)
        version_flag = (
            "-V"
            if name == "ffuf"
            else "--version"
            if name == "gau"
            else "-h"
            if name == "waybackurls"
            else "-version"
        )
        argv = [
            "bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--cap-drop",
            "ALL",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
            str(binary),
            "/tool",
            "--clearenv",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "GOMAXPROCS",
            "2",
            "/tool",
            version_flag,
        ]
        result = subprocess.run(
            argv, capture_output=True, timeout=10, preexec_fn=scanner_limits
        )
        text = (result.stdout + result.stderr).decode(errors="replace")[:4096]
        info["health"] = (
            "tested"
            if result.returncode == 0
            and (info["version"].lstrip("v") in text or name == "waybackurls")
            else "failed"
        )
        if info["health"] == "failed":
            info["enabled"] = False
    if enabled is not None:
        if enabled and not info["available"]:
            raise Denied("Install and verify the pinned tool before enabling it")
        info["enabled"] = enabled
    id = digest("binary-tool:" + owner + ":" + name)[:36]
    row = db.get(Document, id) or document(db, "binary_tool", owner, {}, id)
    previous = row.value()
    row.data = canonical({**previous, **info})
    append(
        db,
        owner,
        owner,
        "binary_tool_configured",
        {"name": name, "enabled": info["enabled"], "health": info["health"]},
    )
    return info


def pins(db, owner):
    return {
        name: {"version": state["version"], "binary_sha256": state["binary_sha256"]}
        for name in sorted(EXECUTABLE_TOOLS)
        if (state := tool_state(db, owner, name))["available"] and state["enabled"]
    }


def run(db, run, args):
    import fcntl

    info = tool_state(db, run.owner, args.tool)
    if not info["available"] or not info["enabled"]:
        raise Denied("The pinned scanner profile is unavailable or disabled")
    pin = run.value().get("tool_pins", {}).get(args.tool)
    if not pin or pin["binary_sha256"] != info["binary_sha256"]:
        raise Denied("Scanner was not enabled and pinned when this run started")
    lock_path = Path(settings().data_dir) / "scanner-execution.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {
                "tool": args.tool,
                "status": "capacity_wait",
                "executed": False,
                "reason": "Another bounded scanner job is running; use its shared observations or schedule a later task",
            }
        return _run(db, run, args)
