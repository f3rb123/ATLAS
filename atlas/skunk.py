"""SKUNK public CLI. Import the engine only after selecting private runtime paths."""

import argparse
import fcntl
import getpass
import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path


def prepare_environment():
    root = Path(os.environ.get("SKUNK_DATA_DIR", Path.home() / ".local/share/atlas-skunk")).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    os.umask(0o077)
    os.environ.setdefault("ATLAS_DATA_DIR", str(root))
    os.environ.setdefault("ATLAS_DATABASE_URL", "sqlite:///" + str(root / "skunk.db"))
    os.environ.setdefault("ATLAS_MASTER_KEY_FILE", str(root / "master.key"))
    os.environ.setdefault("ATLAS_EMBEDDING_CACHE_DIR", str(root / "models"))
    install = Path(os.environ.get("SKUNK_INSTALL_ROOT", Path(__file__).resolve().parents[1]))
    if (install / "tools").is_dir():
        os.environ.setdefault("ATLAS_RESEARCH_TOOLS_DIR", str(install / "tools"))
    logging.basicConfig(filename=root / "skunk.log", level=logging.WARNING,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    return root


def knowledge_command(args):
    from .skunk_runtime import initialize_store, import_knowledge
    from .config import settings
    initialize_store()
    if len(args) >= 2 and args[0] == "import":
        result = import_knowledge(args[1])
        print(json.dumps(result, indent=2))
        return
    if len(args) >= 2 and args[0] == "add":
        from .provider_setup import local_owner
        from .db import session, Knowledge
        from .corpus import import_file
        source = Path(args[1]).expanduser().resolve()
        with session() as db:
            empty = db.query(Knowledge).count() == 0
        if empty:
            import_knowledge()
        allowed = {".txt", ".md", ".html", ".htm", ".pdf", ".docx", ".json", ".jsonl", ".csv", ".zip"}
        paths = [source] if source.is_file() else sorted(path for path in source.rglob("*") if path.is_file() and not path.is_symlink() and not any(part.startswith(".") for part in path.relative_to(source).parts))
        with session() as db:
            owner = local_owner(db, bootstrap=True)
            count = 0
            for path in paths:
                if path.suffix.lower() not in allowed or path.is_symlink():
                    continue
                totals = import_file(db, path, "Owner-supplied permitted local reference", path.as_uri(), owner=owner.id)
                db.commit()
                count += 1
                print(path.name + ": " + json.dumps(dict(totals)))
            print("Imported " + str(count) + " files. All model roles share this knowledge store.")
        return
    folder = Path(settings().data_dir) / "knowledge"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    print("Knowledge file folder: " + str(folder))
    print("Restore: skunk knowledge import /path/to/skunk-knowledge.zip")
    print("Add reports: skunk knowledge add /path/to/reports-folder")


def render(state, frame):
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from .skunk_art import terminal
    header = Text("  " + state["scope"] + "\n", style="bold")
    header.append("  " + state["phase"] + " · " + str(state["agents"]) + " slots · " + str(state["elapsed"]) + "s\n", style="cyan")
    header.append("  Dashboard  http://127.0.0.1:6777\n", style="dim")
    header.append("  " + str(state["observations"]) + " responses · " + str(state.get("model_calls", 0)) + " AI calls · " + ("~" if state.get("token_usage_estimated") else "") + str(state.get("tokens_used", 0)) + " tokens · " + str(len(state["findings"])) + " findings · " + str(len(state["candidates"])) + " candidates", style="dim")
    table = Table(expand=True, box=None, padding=(0, 1))
    table.add_column("Agent responsibility")
    table.add_column("State")
    table.add_column("Details")
    for item in state["tasks"][:10]:
        diagnostic = item.get("diagnostic") or {}
        detail = diagnostic.get("message", diagnostic.get("code", "")) if isinstance(diagnostic, dict) else str(diagnostic)
        if item.get("retry_in_seconds"):
            detail = "Retry in " + str(item["retry_in_seconds"]) + "s · " + detail
        table.add_row(Text(item["role"]), Text(item["status"] + " · " + str(item["attempts"]), style="green" if item["status"] == "completed" else "red" if item["status"] == "dead_letter" else "cyan"), Text(detail))
    events = Text()
    for event in state["events"][-6:]:
        events.append(str(event["time"])[11:19] + " " + event["actor"] + " · ", style="dim")
        events.append((event["type"] + " " + event["text"])[:180] + "\n")
    footer = Text("Ctrl+C cancels dispatch and closes this dashboard. In-flight requests may finish.", style="dim")
    return Group(terminal(frame), Panel(header, border_style="cyan"), Panel(table, title="Swarm", border_style="dim"), Panel(events, title="Live activity", border_style="dim"), footer)


def main():
    root = prepare_environment()
    args = sys.argv[1:]
    try:
        if args and args[0] == "budget":
            from .skunk_budget import main as budget
            budget(args[1:])
            return
        if args and args[0] == "diagnose":
            from .skunk_diagnose import diagnose
            try:
                result = diagnose()
                if "--provider" in args[1:]:
                    from .skunk_diagnose import provider_diagnosis
                    result["provider_metadata_check"] = provider_diagnosis()
            except Exception as error:
                from .skunk_failures import describe
                result = {"diagnostic": "Local preflight could not finish", "failure": describe(error),
                    "model_calls_performed": 0, "target_requests_performed": 0}
            print(json.dumps(result, indent=2))
            return
        if args and args[0] == "knowledge":
            knowledge_command(args[1:])
            return
        if args and args[0] == "token-set":
            token = getpass.getpass("HackerAI token (hidden): ").strip()
            if not token:
                raise ValueError("Empty token")
            path = root / "hacker-ai-token"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(token)
            print("Token saved privately. Environment values take precedence.")
            return
        parser = argparse.ArgumentParser(prog="skunk", description="SKUNK · ATLAS swarm research CLI")
        parser.add_argument("--agents", type=int, default=8, help="Concurrent specialist slots, 1–16 (default: 8)")
        parser.add_argument("--scope", required=True, help="One hostname, URL, IP or quoted wildcard such as '*.example.com'")
        parser.add_argument("--ra", action="store_true", help="Deep recon plus typed non-destructive validation")
        parser.add_argument("--prompt", default="Investigate the authorized surface and publish evidence-backed findings.", help="Additional research instructions; cannot override hard policy")
        values = parser.parse_args(args)
        if not 1 <= values.agents <= 16:
            parser.error("--agents must be between 1 and 16")
        if len(values.prompt) > 4000:
            parser.error("--prompt is limited to 4000 characters")
        lock = (root / "controller.lock").open("a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("A SKUNK controller already owns this runtime. Open its dashboard instead.")
        from .skunk_runtime import Controller
        from .skunk_dashboard import start
        controller = Controller(values.scope, values.agents, values.ra, values.prompt)
        # Bind first; an occupied port cannot leave an invisible scan behind.
        dashboard = start(controller, 6777)
        thread = threading.Thread(target=controller.run, name="skunk-controller", daemon=True)
        thread.start()
        def interrupt(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, interrupt)
        signal.signal(signal.SIGINT, interrupt)
        try:
            if sys.stdout.isatty() and not os.environ.get("NO_COLOR"):
                from rich.live import Live
                with Live(render(controller.snapshot(), 0), refresh_per_second=3, screen=False) as live:
                    frame = 0
                    while True:
                        live.update(render(controller.snapshot(), frame))
                        frame += 1
                        time.sleep(0.4)
            else:
                print("SKUNK dashboard: http://127.0.0.1:6777", flush=True)
                last = set()
                while True:
                    state = controller.snapshot()
                    for item in state["events"]:
                        identity = json.dumps(item, sort_keys=True)
                        if identity not in last:
                            print(item["time"] + " " + item["type"] + " " + item["text"], flush=True)
                            last.add(identity)
                    if len(last) > 2000:
                        last = {json.dumps(item, sort_keys=True) for item in state["events"]}
                    time.sleep(1)
        except KeyboardInterrupt:
            if not controller.finished.is_set():
                controller.control("cancel")
            controller.shutdown.set()
            thread.join(timeout=125)
        finally:
            dashboard.shutdown()
            dashboard.server_close()
            lock.close()
    except (ValueError, OSError) as error:
        print("SKUNK: " + str(error), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
