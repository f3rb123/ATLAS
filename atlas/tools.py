"""Typed, bounded repository tools and an offline Linux namespace sandbox."""

import ast, os, re, resource, shutil, subprocess, zipfile, io
from pathlib import Path
from typing import Literal
from pydantic import Field
from .policy import Strict, Denied, Scope, request
from .db import document, append, canonical, digest, uid, now
from .config import settings
from .vault import redact
from .knowledge import (
    CAPABILITIES as KNOWLEDGE_CAPABILITIES,
    execute as knowledge_execute,
)
from .research_artifacts import ResearchNote, ChainLink, store_note, link_chain
from .tool_registry import IntelligenceLookup, MCPRead, MCPToolLookup
from .web_research import CAPABILITIES as WEB_CAPABILITIES, execute as web_execute
from .scanner_runtime import ScannerInput
from .web_experiments import HTTPExperiment
from .source_experiments import SourceExperiment

EXCLUDED = {
    ".git",
    ".env",
    ".venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    "__pycache__",
}
SECRET = re.compile(
    r"(?i)(\.env|id_rsa|id_ed25519|\.pem$|\.key$|credentials|secret|\.p12$)"
)


NoteInput = ResearchNote


class RecordInput(Strict):
    record_id: str = Field(max_length=36)


class LinkInput(Strict):
    finding_id: str = Field(max_length=36)
    record_id: str = Field(max_length=36)


class ReasonInput(Strict):
    reason: str = Field(min_length=1, max_length=2000)


class BudgetInput(ReasonInput):
    requested_usd: float = Field(gt=0, le=100)


class ApprovalInput(ReasonInput):
    action: dict


class HypothesisStatus(Strict):
    hypothesis_id: str = Field(max_length=36)
    status: Literal["refuted", "inconclusive", "duplicate", "promoted_to_candidate"]
    notes: str = Field(max_length=4000)


class HttpInput(Strict):
    url: str = Field(max_length=4096)
    method: Literal["GET", "HEAD"] = "GET"
    max_redirects: int = Field(default=0, ge=0, le=3)


class DiffInput(Strict):
    previous_repository_id: str = Field(max_length=36)
    path: str | None = None


class ReadInput(Strict):
    path: str
    start: int = Field(default=1, ge=1)
    end: int = Field(default=200, ge=1, le=1000000)


class SearchInput(Strict):
    query: str = Field(min_length=1, max_length=200)


class ExecutionInput(Strict):
    template: Literal["python_unittest", "python_compile"]
    test_path: str = Field(default="tests")


class Repository:
    def __init__(self, root):
        self.root = Path(root).resolve()

    def path(self, path):
        p = (self.root / path).resolve()
        if (
            not p.is_relative_to(self.root)
            or any(x in EXCLUDED for x in p.relative_to(self.root).parts)
            or SECRET.search(path)
        ):
            raise Denied("Path excluded or outside snapshot")
        return p

    def files(self):
        files = []
        ignored = []
        total = 0
        for root, dirs, names in os.walk(self.root, followlinks=False):
            dirs[:] = sorted(
                d for d in dirs if d not in EXCLUDED and not Path(root, d).is_symlink()
            )
            for name in sorted(names):
                p = Path(root, name)
                rel = str(p.relative_to(self.root))
                if p.is_symlink() or SECRET.search(rel) or p.stat().st_size > 512000:
                    ignored.append(rel)
                    continue
                total += p.stat().st_size
                if len(files) >= 10000 or total > 50 * 1024 * 1024:
                    raise Denied("Repository indexing quota exceeded")
                files.append(rel)
        return files, ignored

    def read(self, r):
        if r.end - r.start > 400:
            raise Denied("Read range too large")
        p = self.path(r.path)
        if not p.is_file() or p.stat().st_size > 512000:
            raise Denied("File exceeds read policy")
        text = redact(p.read_text(errors="replace"))
        lines = text.splitlines()
        return {
            "path": r.path,
            "start": r.start,
            "end": min(r.end, len(lines)),
            "text": "\n".join(lines[r.start - 1 : r.end]),
            "sha256": digest(p.read_bytes()),
            "trust": "untrusted_repository_data",
        }

    def inventory(self):
        files, ignored = self.files()
        symbols = []
        for f in files:
            if f.endswith(".py"):
                try:
                    tree = ast.parse(self.path(f).read_text())
                    for node in ast.walk(tree):
                        if isinstance(
                            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                        ):
                            symbols.append(
                                {
                                    "path": f,
                                    "name": node.name,
                                    "line": node.lineno,
                                    "end": node.end_lineno,
                                }
                            )
                except (SyntaxError, UnicodeDecodeError):
                    pass
        return {
            "files": files,
            "ignored": ignored,
            "symbols": symbols[:10000],
            "snapshot_hash": digest(
                canonical([(f, digest(self.path(f).read_bytes())) for f in files])
            ),
        }

    def call_graph(self, query):
        files, _ = self.files()
        edges = []
        for f in files:
            if not f.endswith(".py"):
                continue
            try:
                tree = ast.parse(self.path(f).read_text())
            except (SyntaxError, UnicodeDecodeError):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for call in ast.walk(node):
                    if isinstance(call, ast.Call):
                        name = (
                            call.func.id
                            if isinstance(call.func, ast.Name)
                            else call.func.attr
                            if isinstance(call.func, ast.Attribute)
                            else None
                        )
                        if name and (node.name == query or name == query):
                            edges.append(
                                {
                                    "caller": node.name,
                                    "callee": name,
                                    "path": f,
                                    "line": call.lineno,
                                }
                            )
        return {
            "language": "python",
            "edges": edges[:200],
            "limitations": "Syntax call relationships, not dynamic dispatch resolution",
        }

    def syntax_analysis(self):
        files, _ = self.files()
        errors = []
        parsed = 0
        for f in files:
            if not f.endswith(".py"):
                continue
            try:
                ast.parse(self.path(f).read_text())
                parsed += 1
            except SyntaxError as e:
                errors.append({"path": f, "line": e.lineno, "reason": "syntax_error"})
            except UnicodeDecodeError:
                errors.append({"path": f, "reason": "not_utf8"})
        return {
            "parsed_files": parsed,
            "parse_errors": errors,
            "vulnerability_claims": [],
        }

    def search(self, query):
        files, _ = self.files()
        results = []
        for f in files:
            text = redact(self.path(f).read_text(errors="replace"))
            for i, line in enumerate(text.splitlines(), 1):
                if query.casefold() in line.casefold():
                    results.append({"path": f, "line": i, "text": line[:500]})
                if len(results) >= 100:
                    return results
        return results


def upload_snapshot(data):
    if len(data) > 20 * 1024 * 1024:
        raise Denied("Upload too large")
    root = Path(settings().data_dir) / "repos" / uid()
    root.mkdir(parents=True, mode=0o700)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            if len(infos) > 10000 or sum(i.file_size for i in infos) > 50 * 1024 * 1024:
                raise Denied("Archive quota exceeded")
            for i in infos:
                if i.is_dir():
                    continue
                p = Path(i.filename)
                if (
                    p.is_absolute()
                    or ".." in p.parts
                    or (i.external_attr >> 16) & 0o170000 == 0o120000
                ):
                    raise Denied("Unsafe archive path")
                if any(x in EXCLUDED for x in p.parts) or SECRET.search(i.filename):
                    continue
                target = root / p
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(z.read(i))
        return root
    except Exception:
        shutil.rmtree(root)
        raise


def sandbox_limits():
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    current_uid = os.getuid()
    existing = 0
    for process in Path("/proc").iterdir():
        try:
            if process.name.isdigit() and process.stat().st_uid == current_uid:
                existing += len(list((process / "task").iterdir()))
        except FileNotFoundError:
            pass
    # RLIMIT_NPROC counts all host processes of this UID, including the API/Node.
    resource.setrlimit(resource.RLIMIT_NPROC, (existing + 32, existing + 32))


def execute_offline(repo, args, timeout=30):
    if not shutil.which("bwrap"):
        raise Denied("Offline sandbox unavailable")
    target = repo.path(args.test_path)
    if not target.exists():
        raise Denied("Test path missing")
    python = (
        "/usr/bin/python3"
        if Path("/usr/bin/python3").exists()
        else "/usr/local/bin/python3"
    )
    if args.template == "python_unittest":
        command = [
            python,
            "-I",
            "-c",
            'import sys,unittest;sys.path.insert(0,"/work");suite=unittest.defaultTestLoader.discover(sys.argv[1]);result=unittest.TextTestRunner(verbosity=2).run(suite);sys.exit(not result.wasSuccessful())',
            "/work/" + args.test_path,
        ]
    else:
        command = [
            python,
            "-I",
            "-c",
            'import ast,pathlib,sys; p=pathlib.Path(sys.argv[1]); files=p.rglob("*.py") if p.is_dir() else [p]; [ast.parse(f.read_text(),filename=str(f)) for f in files]',
            "/work/" + args.test_path,
        ]
    base = [
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
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        str(repo.root),
        "/work",
        "--chdir",
        "/work",
        "--clearenv",
        "--setenv",
        "LD_LIBRARY_PATH",
        "/usr/local/lib",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "PYTHONDONTWRITEBYTECODE",
        "1",
    ]
    # Output to bounded file avoids PIPE RAM exhaustion; process creates a new session.
    import tempfile

    with tempfile.TemporaryFile() as f:
        try:
            p = subprocess.run(
                base + command,
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=min(30, timeout),
                preexec_fn=sandbox_limits,
            )
            f.seek(0)
            text = redact(f.read(1024 * 1024).decode(errors="replace"))
            return {
                "exit_code": p.returncode,
                "output": text,
                "template": args.template,
                "snapshot": repo.inventory()["snapshot_hash"],
                "timed_out": False,
            }
        except subprocess.TimeoutExpired:
            return {"exit_code": None, "output": "Sandbox timeout", "timed_out": True}


TOOLS = {
    "search_security_memory": ("read_only", SearchInput),
    "get_advisory_record": ("read_only", RecordInput),
    "get_dependency_record": ("read_only", SearchInput),
    "store_research_note": ("read_only", NoteInput),
    "link_attack_chain": ("read_only", ChainLink),
    "external_intelligence_lookup": ("low_impact", IntelligenceLookup),
    "mcp_read_resource": ("read_only", MCPRead),
    "mcp_intelligence_lookup": ("low_impact", MCPToolLookup),
    "link_finding_to_reference": ("read_only", LinkInput),
    "pause_run": ("read_only", ReasonInput),
    "request_more_budget": ("read_only", BudgetInput),
    "request_user_approval": ("read_only", ApprovalInput),
    "mark_hypothesis_status": ("read_only", HypothesisStatus),
    "http_request": ("low_impact", HttpInput),
    "scanner.run": ("low_impact", ScannerInput),
    "web.experiment": ("low_impact", HTTPExperiment),
    "source.experiment": ("gated", SourceExperiment),
    "fetch_allowed_url": ("low_impact", HttpInput),
    "inspect_redirect_chain": ("low_impact", HttpInput),
    "list_repo_files": ("read_only", None),
    "read_file_range": ("read_only", ReadInput),
    "get_callers_callees": ("read_only", SearchInput),
    "get_git_diff": ("read_only", DiffInput),
    "run_static_analyzer": ("read_only", None),
    "run_dependency_audit": ("read_only", None),
    "search_symbols": ("read_only", SearchInput),
    "search_text": ("read_only", SearchInput),
    "read_manifest": ("read_only", ReadInput),
    "read_test_metadata": ("read_only", ReadInput),
    "get_repo_commit_metadata": ("read_only", None),
    "run_approved_test_command": ("gated", ExecutionInput),
    "run_local_reproduction": ("gated", ExecutionInput),
}
TOOLS.update(
    {name: ("read_only", schema) for name, schema in KNOWLEDGE_CAPABILITIES.items()}
)
TOOLS.update(
    {name: ("low_impact", schema) for name, schema in WEB_CAPABILITIES.items()}
)


def broker(db, run, repo, name, payload, actor):
    db.refresh(run, with_for_update=True)
    v = run.value()
    decision = "deny"
    reason = None
    try:
        import time

        if name not in TOOLS:
            raise Denied("Tool not registered")
        from .swarm import check_fence

        check_fence(db, run)
        if repo is not None and v.get("repository_id"):
            pinned = db.get(type(run), v["repository_id"])
            if (
                not pinned
                or pinned.owner != run.owner
                or pinned.kind != "repository"
                or pinned.value()["snapshot_hash"] != repo.inventory()["snapshot_hash"]
            ):
                raise Denied(
                    "Repository snapshot integrity changed; acquire and authorize a new snapshot"
                )
        if v.get("deadline", 0) and v["deadline"] < time.time():
            raise Denied("Run deadline exhausted")
        if v.get("status") not in ("running", "queued"):
            raise Denied("Run is not active")
        kill = db.get(type(run), "kill-switch")
        if kill and kill.value().get("enabled"):
            raise Denied("Emergency stop active")
        if v.get("tool_calls", 0) >= v.get("max_tool_calls", 50):
            raise Denied("Tool budget exhausted")
        risk, model = TOOLS[name]
        args = model.model_validate(payload) if model else None
        if risk == "gated" and not v.get("offline_execution_approved"):
            raise Denied("Explicit offline execution approval required")
        # Reserve the attempt before any external work. The relay/gateway must
        # be able to lock this run independently while a tool is executing.
        v["tool_calls"] = v.get("tool_calls", 0) + 1
        run.data = canonical(v)
        db.commit()
        if name == "source.experiment":
            from .source_experiments import execute as execute_source_experiment

            result = execute_source_experiment(db, run, repo, args)
        elif name == "web.experiment":
            from .web_experiments import execute as execute_experiment

            result = execute_experiment(db, run, args)
        elif name == "scanner.run":
            from .scanner_runtime import run as run_scanner

            result = run_scanner(db, run, args)
        elif name in WEB_CAPABILITIES:
            result = web_execute(db, run, name, args)
        elif name in KNOWLEDGE_CAPABILITIES:
            result = knowledge_execute(db, run, name, args, actor)
        elif name in KNOWLEDGE_CONTROLS:
            result = knowledge_control(db, run, name, args, actor)
        elif name in (
            "external_intelligence_lookup",
            "mcp_read_resource",
            "mcp_intelligence_lookup",
        ):
            if settings().gateway_url:
                import httpx

                claim = getattr(run, "_swarm_claim", (None, None))
                with httpx.Client(timeout=55, trust_env=False) as client:
                    response = client.post(
                        settings().gateway_url + "/integration-read",
                        headers={
                            "Authorization": "Bearer "
                            + Path(settings().service_token_file).read_text().strip()
                        },
                        json={
                            "run_id": run.id,
                            "capability": name,
                            "input": args.model_dump(),
                            "task_id": claim[0],
                            "lease_token": claim[1],
                        },
                    )
                    if response.status_code != 200:
                        raise Denied(
                            "Credential service denied or failed the integration read"
                        )
                    result = response.json()
            else:
                from .tool_registry import execute

                result = execute(db, run, name, args)
        elif name in ("http_request", "fetch_allowed_url", "inspect_redirect_chain"):
            if not settings().relay_url or not settings().service_token_file:
                raise Denied("Scoped target relay is not configured")
            import httpx

            token = Path(settings().service_token_file).read_text().strip()
            with httpx.Client(timeout=60, trust_env=False) as client:
                response = client.post(
                    settings().relay_url + "/request",
                    headers={"Authorization": "Bearer " + token},
                    json={"run_id": run.id, **args.model_dump()},
                )
                if response.status_code != 200:
                    raise Denied("Scoped relay denied or failed the target request")
                result = response.json()
        elif repo is None:
            raise Denied("Repository tool requires a snapshot")
        elif name == "list_repo_files":
            result = repo.inventory()
        elif name in ("read_file_range", "read_manifest", "read_test_metadata"):
            result = repo.read(args)
        elif name in ("search_symbols", "search_text"):
            result = repo.search(args.query)
        elif name == "get_callers_callees":
            result = repo.call_graph(args.query)
        elif name == "run_static_analyzer":
            result = repo.syntax_analysis()
        elif name == "get_git_diff":
            previous = db.get(
                __import__("atlas.db", fromlist=["Document"]).Document,
                args.previous_repository_id,
            )
            if (
                not previous
                or previous.kind != "repository"
                or previous.owner != run.owner
                or previous.value()["campaign_id"] != v["campaign_id"]
            ):
                raise Denied("Previous snapshot is not authorized for this campaign")
            result = snapshot_diff(
                Repository(previous.value()["path"]), repo, args.path
            )
        elif name == "run_dependency_audit":
            result = dependency_context(db, repo)
        elif name == "get_repo_commit_metadata":
            result = {
                "snapshot_hash": repo.inventory()["snapshot_hash"],
                "origin": "owner_upload",
            }
        else:
            result = execute_offline(
                repo,
                args,
                timeout=max(
                    0.1, min(30, v.get("deadline", time.time() + 30) - time.time())
                ),
            )
        check_fence(db, run)
        v = run.value()
        if isinstance(result, dict) and (
            result.get("timed_out")
            or ("exit_code" in result and result["exit_code"] != 0)
        ):
            warnings = v.get("tool_warnings", [])
            warnings.append(
                {
                    "tool": name,
                    "code": "timeout" if result.get("timed_out") else "nonzero_exit",
                    "task_id": getattr(run, "_swarm_claim", (None, None))[0],
                }
            )
            v["tool_warnings"] = warnings[-100:]
            run.data = canonical(v)
        decision = "allow"
        artifact = document(
            db,
            "artifact",
            run.owner,
            {
                "run_id": run.id,
                "task_id": getattr(run, "_swarm_claim", (None, None))[0],
                "campaign_id": v["campaign_id"],
                "tool_name": name,
                "tool_version": "1.0",
                "sha256": digest(canonical(result)),
                "media_type": "application/json",
                "payload": result,
                "sensitivity": "campaign_private",
            },
        )
        return {
            "artifact_id": artifact.id,
            "trust": "untrusted_tool_data",
            "result": result,
        }
    except Denied as exc:
        reason = str(exc)[:200]
        raise
    except ValueError:
        reason = "invalid_tool_arguments"
        raise
    except Exception:
        reason = "tool_execution_failed"
        raise
    finally:
        append(
            db,
            run.id,
            actor,
            "policy_decision",
            {
                "tool": name,
                "task_id": getattr(run, "_swarm_claim", (None, None))[0],
                "decision": decision,
                "reason": reason,
                "input_hash": digest(canonical(payload)),
            },
            v["campaign_id"],
        )
        db.commit()


def dependency_context(db, repo):
    """Deterministic manifest inventory plus attributed advisory candidates; never automatic confirmation."""
    import json
    from .db import Knowledge

    packages = []
    files, _ = repo.files()
    for name in files:
        if Path(name).name == "package.json":
            try:
                v = json.loads(repo.path(name).read_text())
                for group in ["dependencies", "devDependencies"]:
                    for package, version in v.get(group, {}).items():
                        packages.append(
                            {
                                "package": package,
                                "version_spec": redact(str(version)),
                                "ecosystem": "npm",
                                "path": name,
                            }
                        )
            except (ValueError, UnicodeDecodeError):
                pass
        elif Path(name).name.startswith("requirements") and name.endswith(".txt"):
            for line in repo.path(name).read_text(errors="replace").splitlines():
                match = re.fullmatch(
                    r"\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)\s*", line
                )
                if match:
                    packages.append(
                        {
                            "package": match[1],
                            "version_spec": match[2],
                            "ecosystem": "PyPI",
                            "path": name,
                        }
                    )
    candidates = []
    for package in packages[:100]:
        needle = '"package":' + canonical(package["package"])
        for k in (
            db.query(Knowledge)
            .filter_by(owner="public")
            .filter(Knowledge.record.contains(needle))
            .limit(10)
        ):
            record = __import__("json").loads(k.record)
            if record["target"]["ecosystem"] == package["ecosystem"]:
                candidates.append(
                    {
                        "dependency": package,
                        "advisory_id": k.id,
                        "title": k.title,
                        "source_url": record["source"]["source_url"],
                        "affected_versions": record["target"]["affected_versions"],
                        "fixed_versions": record["target"]["fixed_versions"],
                        "status": "requires_version_range_and_independent_verification",
                    }
                )
    return {
        "dependencies": packages[:100],
        "advisory_candidates": candidates,
        "vulnerabilities_confirmed": 0,
        "limitations": "npm and exact-pinned requirements.txt inventory; candidate matching is not proof of an affected installed version",
    }


def snapshot_diff(before, after, path=None):
    import difflib

    left, _ = before.files()
    right, _ = after.files()
    names = sorted(set(left) | set(right))
    if path:
        before.path(path)
        after.path(path)
        names = [
            name
            for name in names
            if name == path or name.startswith(path.rstrip("/") + "/")
        ]
    changes = []
    size = 0
    for name in names:
        a = (
            before.path(name).read_text(errors="replace").splitlines()
            if name in left
            else []
        )
        b = (
            after.path(name).read_text(errors="replace").splitlines()
            if name in right
            else []
        )
        delta = redact(
            "\n".join(
                difflib.unified_diff(
                    a, b, fromfile="before/" + name, tofile="after/" + name
                )
            )
        )
        if delta:
            changes.append({"path": name, "diff": delta})
            size += len(delta.encode())
        if len(changes) >= 50 or size > 1024 * 1024:
            break
    return {
        "before_snapshot": before.inventory()["snapshot_hash"],
        "after_snapshot": after.inventory()["snapshot_hash"],
        "changes": changes,
        "bounded": len(changes) >= 50 or size > 1024 * 1024,
        "provenance": "Explicit authorized snapshots; no claim about unprovided Git ancestry",
    }


KNOWLEDGE_CONTROLS = {
    "search_security_memory",
    "get_advisory_record",
    "get_dependency_record",
    "store_research_note",
    "link_attack_chain",
    "link_finding_to_reference",
    "pause_run",
    "request_more_budget",
    "request_user_approval",
    "mark_hypothesis_status",
}


def knowledge_control(db, run, name, args, actor):
    from .db import Document, Knowledge
    from .corpus import search
    import time

    if name in ("search_security_memory", "get_dependency_record"):
        return {
            "results": search(db, args.query, owner=run.owner),
            "trust": "untrusted_attributed_knowledge",
        }
    if name == "get_advisory_record":
        k = db.get(Knowledge, args.record_id)
        if not k or k.owner not in ("public", run.owner):
            raise Denied("Knowledge record not authorized")
        from .corpus_privacy import record_view

        r = record_view(db, __import__("json").loads(k.record))
        return {"record": r, "trust": "source_reported_not_independently_reproduced"}
    if name == "store_research_note":
        return store_note(db, run, args, actor)
    if name == "link_attack_chain":
        return link_chain(db, run, args, actor)
    if name == "link_finding_to_reference":
        f = db.get(Document, args.finding_id)
        k = db.get(Knowledge, args.record_id)
        if (
            not f
            or f.kind != "finding"
            or f.owner != run.owner
            or f.value()["run_id"] != run.id
            or not k
            or k.owner not in ("public", run.owner)
        ):
            raise Denied("Reference/finding not authorized")
        v = f.value()
        v["references"] = sorted(set(v.get("references", []) + [k.id]))
        f.data = canonical(v)
        return {"linked": True}
    if name == "pause_run":
        from .workflow import control

        control(db, run, "pause", actor)
        return {"status": "paused", "reason": redact(args.reason)}
    if name in ("request_more_budget", "request_user_approval"):
        action = (
            {"type": "budget", "requested_usd": args.requested_usd}
            if name == "request_more_budget"
            else args.action
        )
        if action.get("type") not in ("budget", "offline_execution"):
            raise Denied(
                "Unsupported approval type; cannot authorize prohibited/unknown actions"
            )
        d = document(
            db,
            "approval",
            run.owner,
            {
                "run_id": run.id,
                "campaign_id": run.value()["campaign_id"],
                "action": action,
                "reason": redact(args.reason),
                "policy_hash": run.value()["policy_hash"],
                "status": "pending",
                "expires": min(run.value()["deadline"], time.time() + 600),
                "requested_by": actor,
            },
        )
        from .workflow import control

        control(db, run, "pause", actor)
        return {"approval_id": d.id, "status": "pending", "scope_unchanged": True}
    if name == "mark_hypothesis_status":
        h = db.get(Document, args.hypothesis_id)
        if (
            not h
            or h.kind != "hypothesis"
            or h.owner != run.owner
            or h.value()["run_id"] != run.id
        ):
            raise Denied("Hypothesis not authorized")
        v = h.value()
        v.update(status=args.status, notes=redact(args.notes))
        h.data = canonical(v)
        return {"status": args.status, "finding_confirmed": False}
    raise Denied("Unsupported control")
