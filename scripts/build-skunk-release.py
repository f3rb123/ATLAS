#!/usr/bin/env python3
"""Build-only relocatable Python distribution. Never imports or runs the application."""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile


def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-runtime", required=True, type=Path)
    parser.add_argument("--site-packages", required=True, type=Path)
    parser.add_argument("--tools", required=True, type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    root = args.destination.resolve() / "skunk-linux-x86_64"
    if root.exists():
        raise SystemExit("Build destination must be fresh")
    root.mkdir(parents=True)
    if sha(args.corpus) != "e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025":
        raise SystemExit("Original corpus identity mismatch")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
    shutil.copytree(args.python_runtime, root / "runtime", symlinks=True, ignore=ignore)
    target = root / "runtime/lib/python3.12/site-packages"
    shutil.copytree(args.site_packages, target, dirs_exist_ok=True, symlinks=True, ignore=ignore)
    for name in ("_virtualenv.pth", "_virtualenv.py"):
        (target / name).unlink(missing_ok=True)
    # Source, migrations and administration capabilities remain inspectable.
    shutil.copytree(source / "atlas", target / "atlas", dirs_exist_ok=True, ignore=ignore)
    shutil.copytree(source / "atlas", root / "app/atlas", ignore=ignore)
    shutil.copytree(source / "migrations", root / "app/migrations", ignore=ignore)
    shutil.copy2(source / "alembic.ini", root / "app/alembic.ini")
    shutil.copy2(source / "pyproject.toml", root / "app/pyproject.toml")
    shutil.copy2(source / "requirements.lock", root / "app/requirements.lock")
    shutil.copytree(source / "infra/security", root / "app/security")
    shutil.copytree(args.tools, root / "tools", symlinks=False)
    knowledge = root / "knowledge"
    knowledge.mkdir()
    shutil.copy2(args.corpus, knowledge / "skunk-knowledge.zip")
    shutil.copy2(source / "atlas/data/skunk-budget-floor.json", knowledge / "BUDGET-FLOOR.json")
    shutil.copy2(source / "knowledge/corpus_inventory.json", knowledge / "corpus-inventory.json")
    (root / "bin").mkdir()
    launcher = '''#!/usr/bin/env bash
set -euo pipefail
entry="$(readlink -f -- "$0")"
root="$(cd -- "$(dirname -- "$entry")/.." && pwd)"
export SKUNK_INSTALL_ROOT="$root"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1
export PATH="$root/runtime/bin:$PATH"
exec "$root/runtime/bin/python3" -I -m atlas.skunk "$@"
'''
    (root / "bin/skunk").write_text(launcher)
    (root / "bin/skunk").chmod(0o755)
    admin = launcher.replace('-m atlas.skunk', '-m atlas.cli')
    (root / "bin/atlas-admin").write_text(admin)
    (root / "bin/atlas-admin").chmod(0o755)
    shutil.copy2(source / "scripts/skunk-install.sh", root / "install.sh")
    (root / "install.sh").chmod(0o755)
    shutil.copy2(source / "docs/SKUNK_CLI.md", root / "README.md")
    record = {
        "product": "SKUNK", "internal_package": "atlas", "version": "3.1.0rc1",
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip(),
        "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True).strip()),
        "original_release": "atlas-v3-prebuilt-20261110", "build_only": True,
        "tests_run": False, "application_started": False, "model_calls": 0, "target_requests": 0,
        "runtime_acceptance": "not performed at owner request",
        "records": 21012, "vectors": 34229, "vector_dimensions": 384,
        "default_agents": 8, "dashboard_port": 6777,
        "models": ast.literal_eval(next(node.value for node in ast.parse((source / "atlas/skunk_prompts.py").read_text()).body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "MODELS" for target in node.targets))),
        "new_run_usage_policy": {"mode": "tracking_only", "token_limits_enforced": False, "spending_limits_enforced": False, "model_call_limits_enforced": False, "tool_call_limits_enforced": False},
        "corpus_sha256": sha(args.corpus), "full_text_bounty_reports": 0,
        "host_requirements": ["Linux x86_64 with glibc", "Linux user namespaces", "bubblewrap for isolated scanners"],
        "token_included": False,
    }
    (root / "BUILD-RECORD.json").write_text(json.dumps(record, indent=2) + "\n")
    sums = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            sums.append(sha(path) + "  " + path.relative_to(root).as_posix())
    (root / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    archive = args.destination.resolve() / "skunk-linux-x86_64.tar.gz"
    with tarfile.open(archive, "w:gz", compresslevel=3) as output:
        output.add(root, arcname=root.name)
    (args.destination / "skunk-linux-x86_64.tar.gz.sha256").write_text(sha(archive) + "  " + archive.name + "\n")
    print(json.dumps({"archive": str(archive), "bytes": archive.stat().st_size, "sha256": sha(archive), "tests_run": False}, indent=2))


if __name__ == "__main__":
    main()
