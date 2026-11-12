"""A host-owned CLI controller over the existing ATLAS services and durable swarm."""

import json
import os
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, urlsplit

from .config import settings
from .db import Base, Document, Journal, Knowledge, SwarmTask, append, canonical, digest, document, engine, now, session
from .policy import Denied, Rule, Scope, host, match, normalize
from .skunk_prompts import MODELS

CORPUS_SHA256 = "e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025"


def installation_root():
    return Path(os.environ.get("SKUNK_INSTALL_ROOT", Path(__file__).resolve().parents[1])).resolve()


def parse_scope(value, deep=False):
    value = value.strip()
    if not value or "," in value or any(char.isspace() for char in value):
        raise ValueError("Use one hostname, URL, IP, or quoted wildcard such as '*.example.com'.")
    wildcard = value.startswith("*")
    if wildcard:
        name = host(value[1:].lstrip("."))
        if "." not in name or "/" in value or ":" in value or "*" in value[1:]:
            raise ValueError("A wildcard needs a fully qualified domain, e.g. '*.example.com'.")
        rule = Rule(host="*." + name, ports=[80, 443], schemes=["http", "https"], methods=["GET", "HEAD", "OPTIONS", "POST"] if deep else ["GET", "HEAD"])
        seed = None
    else:
        seed, name, port, path, scheme = normalize(value if "://" in value else "https://" + value)
        rule = Rule(host=name, ports=[port] if "://" in value else [80, 443],
                    schemes=[scheme] if "://" in value else ["http", "https"], paths=[path],
                    methods=["GET", "HEAD", "OPTIONS", "POST"] if deep else ["GET", "HEAD"])
    classes = ["surface", "headers", "dns", "passive_sources"]
    if deep:
        classes += ["ports", "scanners", "redirect", "cors", "reflection", "graphql", "authorization", "read_json", "differential"]
    scope = Scope(allow=[rule], max_requests=2000 if deep else 300,
                  min_request_interval=0.5, test_classes=classes,
                  post_paths=["/graphql", "/api/graphql"] if deep else [])
    return scope, name, wildcard, seed


def initialize_store():
    root = Path(settings().data_dir)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    master = Path(settings().master_key_file)
    if not master.exists():
        master.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(master, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(secrets.token_bytes(32))
    Base.metadata.create_all(engine())
    floor_path = installation_root() / "knowledge/BUDGET-FLOOR.json"
    with session() as db:
        if not db.get(Document, "token-budget-global") and floor_path.is_file():
            from .token_budget import COUNTERS
            floor = json.loads(floor_path.read_text())
            if set(floor["used"]) != set(COUNTERS) or not 0 <= floor["used"]["total_tokens"] <= floor["allocation"] <= floor["cap"] <= 50000000:
                raise ValueError("Invalid historical budget floor")
            document(db, "token_budget", "system", floor, "token-budget-global")
            db.commit()


def import_knowledge(filename=None):
    from .corpus_package import restore_package
    path = Path(filename) if filename else installation_root() / "knowledge/skunk-knowledge.zip"
    if not path.is_file():
        path = Path(settings().data_dir) / "knowledge/skunk-knowledge.zip"
    if not path.is_file():
        raise ValueError("Knowledge file missing. Use: skunk knowledge import /path/to/skunk-knowledge.zip")
    return restore_package(path, CORPUS_SHA256, actor="skunk-host")


class Controller:
    def __init__(self, scope_text, count, deep, instruction):
        self.scope, self.domain, self.wildcard, self.seed = parse_scope(scope_text, deep)
        self.scope_text, self.count, self.deep, self.instruction = scope_text, count, deep, instruction
        self.lock = threading.RLock()
        self.cancelled, self.paused, self.shutdown = threading.Event(), threading.Event(), threading.Event()
        self.phase, self.error = "initializing", None
        self.owner_id = self.campaign_id = None
        self.run_ids = []
        self.targets, self.pending, self.events = [], [], []
        self.pause_at = None
        self.started = time.time()
        self.finished = threading.Event()
        self.current_run = None
        self.partial = False
        self.failed_runs = 0
        self.successful_runs = 0
        self.exported = set()
        self.activity_cache = (None, 0, {})
        self.note("SKUNK controller starting; no live target work has begun")

    def note(self, text):
        from .vault import redact
        with self.lock:
            self.events.append({"time": now(), "type": "controller", "actor": "SKUNK", "text": redact(str(text))[:800]})
            self.events = self.events[-300:]

    def wait(self):
        while self.paused.is_set() and not self.cancelled.is_set():
            time.sleep(0.15)
        if self.cancelled.is_set():
            raise InterruptedError("Scan cancelled")

    def control(self, action):
        if action not in ("pause", "resume", "cancel"):
            raise ValueError("Unknown control")
        with self.lock:
            if self.finished.is_set():
                raise ValueError("Scan has finished")
            if action == "pause":
                if not self.paused.is_set():
                    self.pause_at = time.time()
                self.paused.set()
            elif action == "resume":
                if self.cancelled.is_set():
                    raise ValueError("A cancelled scan cannot be resumed")
                duration = max(0, time.time() - self.pause_at) if self.pause_at else 0
                self.pause_at = None
            else:
                self.cancelled.set()
            if self.owner_id:
                from .workflow import control
                with session() as db:
                    for identity in list(self.run_ids):
                        run = db.get(Document, identity)
                        if not run or run.owner != self.owner_id or run.value()["status"] in ("completed", "cancelled"):
                            continue
                        if action == "resume" and run.value()["status"] != "paused":
                            continue
                        control(db, run, action, "skunk-operator")
                        if action == "resume":
                            value = run.value()
                            value["deadline"] += duration
                            run.data = canonical(value)
                    db.commit()
            if action == "resume":
                self.paused.clear()
            self.note("Operator requested " + action)

    def setup(self):
        self.wait()
        initialize_store()
        self.phase = "loading knowledge"
        self.note("Loading the supplied records, vectors and pinned local model; no re-embedding")
        with session() as db:
            empty = db.query(Knowledge).count() == 0
        if empty:
            import_knowledge()
        from .embeddings import verify_model
        from .db import Chunk
        verify_model()
        with session() as db:
            self.note("Shared knowledge ready: " + str(db.query(Knowledge).count()) + " records / " + str(db.query(Chunk).count()) + " vectors")
        self.wait()
        from .provider_setup import local_owner
        from .skunk_models import configure
        key = os.environ.get("hacker-ai-token") or os.environ.get("HACKER_AI_TOKEN")
        if not key:
            token_path = Path(settings().data_dir) / "hacker-ai-token"
            key = token_path.read_text().strip() if token_path.is_file() else None
        if not key:
            raise ValueError("Set hacker-ai-token through env, export HACKER_AI_TOKEN, or run skunk token-set.")
        with session() as db:
            owner = local_owner(db, bootstrap=True)
            self.owner_id = owner.id
            configure(db, owner, key)
            from .skills import install_references
            install_references(db, owner.id)
            campaign = document(db, "campaign", owner.id, {
                "name": "SKUNK " + self.scope_text, "mode": "safe-active" if self.deep else "passive",
                "authorization_attested": True,
                "authorization_ref": "Host operator invoked skunk with this explicit scope",
                "assessment_profile": "standard", "engagement": True,
                "budget_limit": 100, "instructions": self.instruction,
            })
            policy = document(db, "policy", owner.id, {"campaign_id": campaign.id,
                "scope": self.scope.model_dump(), "hash": digest(canonical(self.scope.model_dump())),
                "approved_by": owner.id})
            value = campaign.value()
            value["policy_id"] = policy.id
            campaign.data = canonical(value)
            self.campaign_id = campaign.id
            db.commit()
        # A CLI restart must not implicitly resume old targets or spend.
        with session() as db:
            from .workflow import control
            for run in db.query(Document).filter_by(kind="run", owner=self.owner_id).all():
                if run.value().get("harness") == "skunk/1" and run.value().get("status") in ("queued", "running"):
                    control(db, run, "pause", "skunk-restart")
            db.commit()

    def new_run(self, target, discovery=False):
        from .scanner_runtime import pins
        from .scanner_templates import pins as template_pins
        from .swarm import initialize
        from .web_research import WebPlan
        from .skunk_usage import default_policy
        with self.lock, session() as db:
            campaign = db.get(Document, self.campaign_id)
            if target:
                campaign_value = campaign.value()
                campaign_value["target_url"] = target
                campaign.data = canonical(campaign_value)
            policy = db.get(Document, campaign.value()["policy_id"])
            models = {}
            for row in db.query(Document).filter_by(kind="alias", owner=self.owner_id):
                value = row.value()
                if value.get("alias") not in {"orchestrator", "recon", "classifier", "exploit", "report", "reasoning", "fast", "coding", "verifier", "deep_research"}:
                    continue
                provider = db.get(Document, value["provider_id"])
                model = db.get(Document, value["model_id"])
                models[value["alias"]] = {**value, "provider_version": provider.version, "model_version": model.version}
            plan = WebPlan(enabled=not discovery, max_pages=60 if self.deep else 12,
                           max_depth=4 if self.deep else 2, max_checks=50 if self.deep else 1,
                           scanner_tools=["httpx", "katana", "nuclei", "subfinder", "dnsx", "naabu", "gau", "ffuf"] if self.deep else ["subfinder", "dnsx", "gau"],
                           check_classes=["headers", "redirect", "cors", "reflection", "graphql", "authorization"] if self.deep else [])
            value = {"harness": "skunk/1", "execution_mode": "skunk-discovery" if discovery else "swarm",
                "campaign_id": campaign.id, "policy_id": policy.id, "policy_hash": policy.value()["hash"],
                "target_url": target, "agent_count": self.count, "model_mode": "capability",
                "models": models, "status": "paused" if self.paused.is_set() else "running",
                "state": "DISCOVERY" if discovery else "SWARM_RUNNING", "budget_limit": 100,
                "budget_used": 0, "max_model_calls": None,
                "max_tool_calls": None, "max_seconds": 7200 if self.deep else 1800,
                "deadline": time.time() + (7200 if self.deep else 1800), "started_at": now(),
                "instructions": self.instruction, "web": plan.model_dump(), "assessment_profile": "standard",
                "offline_execution_approved": False, "tool_pins": pins(db, self.owner_id),
                "scanner_template_pins": template_pins(db, self.owner_id), "target_identities": {},
                "integration_pins": {}, "skills": [], "specialist_roles": ["coding", "fast"],
                "workflow_version": "skunk-swarm/6", "usage_policy": default_policy(),
                "followup_policy": {"max_depth": 2, "max_tasks_per_role": 8, "coalesce_after_pending": 2},
                "retry_policy": {"max_attempts": 4, "retry_unknown_billing": True,
                    "authorization": "Host owner explicitly accepts separately billed retries; preserve prior reservations"}}
            run = document(db, "run", self.owner_id, value)
            if not discovery:
                initialize(db, run)
            append(db, run.id, "skunk", "run_created", {"target_url": target, "discovery": discovery}, campaign.id)
            self.run_ids.append(run.id)
            self.current_run = run.id
            db.commit()
            return run.id

    def discover(self):
        if not self.wildcard:
            return [self.seed]
        from .network_research import send
        self.phase = "enumerating wildcard"
        self.note("Wildcard subdomains are eligible; the apex is excluded. Querying public certificate and URL indexes.")
        run_id = self.new_run(None, discovery=True)
        urls = ["https://crt.sh/?q=" + quote("%." + self.domain) + "&output=json",
                "https://web.archive.org/cdx/search/cdx?url=" + quote("*." + self.domain + "/*") + "&output=json&fl=original&collapse=urlkey&filter=statuscode:200&limit=2000"]
        names, sources = set(), []
        for url in urls:
            source = {"index": urlsplit(url).hostname, "status": "unavailable", "attempts": 0}
            for attempt in range(3):
                self.wait()
                source["attempts"] += 1
                try:
                    with session() as db:
                        result = send(db, db.get(Document, run_id), {"kind": "metadata", "hostname": self.domain, "url": url})
                        db.commit()
                    status = result.get("status", 0)
                    source["http_status"] = status
                    if status != 200:
                        if status not in (408, 429, 500, 502, 503, 504):
                            break
                        raise OSError("Public index temporarily unavailable")
                    text = result.get("body", "")
                    # Retain usable hosts from bounded responses; record truncation.
                    for candidate in re.findall(r"[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+", text):
                        try:
                            candidate = host(candidate)
                        except ValueError:
                            continue
                        if candidate.endswith("." + self.domain) and candidate != self.domain:
                            names.add(candidate)
                    source["status"] = "incomplete" if result.get("body_truncated") or len(text) >= 65536 else "ok"
                    self.note("Public index returned " + str(len(names)) + " unique in-scope hostnames so far; wildcard inventory remains bounded")
                    break
                except (Denied, InterruptedError):
                    raise
                except Exception as error:
                    source["error_type"] = type(error).__name__
                    self.note("Public index " + source["index"] + " unavailable on attempt " + str(attempt + 1) + ": " + type(error).__name__)
                    if attempt < 2:
                        if self.cancelled.wait(2 ** (attempt + 1)):
                            self.wait()
            sources.append(source)
        with session() as db:
            run = db.get(Document, run_id)
            value = run.value()
            value["wildcard_discovery"] = {"sources": sources, "hostnames": len(names), "exhaustive": False}
            if value["status"] not in ("cancelled", "paused"):
                value.update(status="completed", state="COMPLETED", finished=now())
            run.data = canonical(value)
            db.commit()
        self.wait()
        if not names:
            raise ValueError("No subdomains were returned by the available indexes. Retry later or scan a known in-scope URL; no apex scan was substituted.")
        return ["https://" + name for name in sorted(names)]

    def worker(self):
        from .swarm import execute_one
        while not self.shutdown.is_set():
            if self.paused.is_set() or self.cancelled.is_set():
                self.shutdown.wait(0.2)
                continue
            try:
                with self.lock:
                    owned = list(self.run_ids)
                worked = execute_one("verify", owned) or execute_one("research", owned)
                if not worked:
                    self.shutdown.wait(0.2)
            except Exception as error:
                self.note("Worker deferred: " + type(error).__name__)
                self.shutdown.wait(0.5)

    def export(self):
        from .reporting import generate_report
        output = Path(settings().data_dir) / "reports" / self.campaign_id
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        exported = []
        with session() as db:
            for identity in list(self.run_ids):
                if identity in self.exported:
                    continue
                run = db.get(Document, identity)
                if run.value().get("execution_mode") != "swarm":
                    continue
                cycle = run.value().get("resume_cycle", 0)
                stem = identity + (".resume-" + str(cycle) if cycle else "")
                for extension, kind in (("md", "markdown"), ("html", "html"), ("json", "json")):
                    report = generate_report(db, run, kind)
                    (output / (stem + "." + extension)).write_text(report.value()["content"])
                exported.append(identity)
            db.commit()
        self.exported.update(exported)
        self.note("Reports saved in " + str(output))

    def run(self):
        pool = None
        try:
            self.setup()
            self.targets = self.discover()
            self.pending = list(self.targets)
            self.phase = "researching"
            pool = ThreadPoolExecutor(max_workers=self.count, thread_name_prefix="skunk-agent")
            for _ in range(self.count):
                pool.submit(self.worker)
            while self.pending:
                self.wait()
                target = self.pending.pop(0)
                self.note("Starting scoped assessment: " + target)
                identity = self.new_run(target)
                while not self.cancelled.is_set():
                    self.wait()
                    with session() as db:
                        run = db.get(Document, identity)
                        value = run.value()
                        if value["status"] in ("completed", "cancelled", "blocked"):
                            if value["status"] == "blocked":
                                self.failed_runs += 1
                            elif value["status"] == "completed":
                                self.successful_runs += 1
                            if value["status"] != "completed" or value.get("partial") or value.get("task_errors"):
                                self.partial = True
                            if value.get("blocked_reason"):
                                self.note(value["blocked_reason"])
                            break
                        if time.time() > value["deadline"]:
                            from .workflow import control
                            control(db, run, "cancel", "skunk-deadline")
                            db.commit()
                            self.note("Run reached its deadline; remaining work is incomplete")
                            self.partial = True
                            break
                    self.shutdown.wait(0.5)
                if self.wildcard and target.startswith("https://") and not self.cancelled.is_set():
                    fallback = "http://" + urlsplit(target).hostname
                    if any(match(rule, urlsplit(target).hostname, 80, "/", "http", "GET") for rule in self.scope.allow):
                        with session() as db:
                            rows = db.query(Document).filter_by(kind="http_observation", owner=self.owner_id).all()
                            captured = any(row.value().get("run_id") == identity and row.value().get("response") for row in rows)
                        if not captured and fallback not in self.targets:
                            self.targets.append(fallback)
                            self.pending.insert(0, fallback)
                            self.note("No HTTPS response was captured; scheduling the separately authorized HTTP origin")
                self.export()
            self.phase = "cancelled" if self.cancelled.is_set() else "failed" if self.failed_runs and not self.successful_runs else ("partial" if self.pending or self.partial else "completed")
            if self.phase == "failed":
                self.error = "The assessment failed. Inspect the task failure details or run skunk diagnose; no successful coverage is claimed."
        except InterruptedError:
            self.phase = "cancelled"
        except Exception as error:
            from .vault import redact
            self.error = redact(str(error))[:500]
            self.phase = "failed"
            self.note(type(error).__name__ + ": " + self.error)
        finally:
            self.shutdown.set()
            if pool:
                pool.shutdown(wait=True, cancel_futures=True)
            if self.campaign_id:
                try:
                    self.export()
                except Exception as error:
                    self.note("Report export incomplete: " + type(error).__name__)
            self.finished.set()

    def snapshot(self):
        with self.lock:
            phase = "cancelling" if self.cancelled.is_set() and not self.finished.is_set() else "paused" if self.paused.is_set() and not self.finished.is_set() else self.phase
            state = {"brand": "SKUNK", "phase": phase,
                     "scope": self.scope_text, "agents": self.count, "deep": self.deep, "models": MODELS,
                     "elapsed": round(time.time() - self.started), "error": self.error,
                     "targets": len(self.targets), "remaining": len(self.pending), "finished": self.finished.is_set(),
                     "events": list(self.events[-100:]), "tasks": [], "findings": [], "candidates": [], "observations": 0,
                     "model_calls": 0, "failed_tasks": 0, "completed_tasks": 0,
                     "coverage_notes": [],
                     "validation_activity": {},
                     "usage_policy": "tracking_only", "tokens_used": 0, "token_usage_estimated": False,
                     "retry_policy": {"max_attempts": 4, "retry_unknown_billing": True}}
            ids = list(self.run_ids)
        if not self.owner_id or not ids:
            return state
        with session() as db:
            if self.current_run:
                current = db.get(Document, self.current_run)
                if current and current.owner == self.owner_id and current.value().get("execution_mode") == "swarm":
                    cached_id, cached_at, activity = self.activity_cache
                    if cached_id != current.id or time.monotonic() - cached_at >= 5:
                        from .skunk_activity import collect
                        activity = collect(db, current)
                        with self.lock:
                            self.activity_cache = (current.id, time.monotonic(), activity)
                    state["validation_activity"] = activity
            tasks = db.query(SwarmTask).filter(SwarmTask.run_id.in_(ids)).order_by(SwarmTask.created_at.desc()).limit(100).all()
            state["tasks"] = [{"id": t.id, "role": t.role, "status": t.status, "attempts": t.attempts,
                "diagnostic": json.loads(t.result).get("diagnostic_code"),
                "retry_in_seconds": max(0, round(t.available_at - time.time())) if t.status == "queued" and t.attempts else 0} for t in tasks]
            state["failed_tasks"] = sum(t.status == "dead_letter" for t in tasks)
            state["completed_tasks"] = sum(t.status == "completed" for t in tasks)
            state["model_calls"] = sum(row.value().get("model_calls", 0) for identity in ids if (row := db.get(Document, identity)))
            from .skunk_evidence import leads, coverage_notes
            for identity in ids:
                run = db.get(Document, identity)
                if run and run.value().get("execution_mode") == "swarm":
                    state["candidates"].extend(leads(db, run))
                    state["coverage_notes"].extend(coverage_notes(db, run))
                    for alias, pin in run.value().get("models", {}).items():
                        model = db.get(Document, pin.get("model_id", ""))
                        if alias in MODELS and model:
                            state["models"] = {**state["models"], alias: model.value().get("model_id", "unknown")}
            state["coverage_notes"] = list(dict.fromkeys(state["coverage_notes"]))
            for item in db.query(Document).filter(Document.owner == self.owner_id, Document.kind.in_(["finding", "http_observation", "usage"])).all():
                value = item.value()
                if value.get("run_id") not in ids:
                    continue
                if item.kind == "finding":
                    state["findings"].append({"id": item.id, "title": value.get("title", "Finding"),
                        "status": value.get("status", "candidate"), "severity": value.get("severity", "unscored"),
                        "verification": value.get("verification", {}).get("status", "unverified")})
                elif item.kind == "http_observation":
                    state["observations"] += 1
                elif item.kind == "usage":
                    state["tokens_used"] += value.get("total_tokens", value.get("input_tokens", 0) + value.get("output_tokens", 0))
                    state["token_usage_estimated"] |= bool(value.get("token_usage_estimated"))
            journal = db.query(Journal).filter(Journal.stream == self.current_run).order_by(Journal.sequence.desc()).limit(100).all()
            entries = []
            for item in journal:
                value = json.loads(item.payload)
                payload = value.get("payload", {})
                entries.append({"time": value.get("timestamp", ""), "type": value.get("type", "event"),
                                "actor": value.get("actor", "swarm"), "text": canonical(payload)[:600]})
            state["events"] = sorted(state["events"] + entries, key=lambda item: item["time"])[-150:]
        return state
