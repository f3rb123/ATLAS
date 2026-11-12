"""Assemble the small source-only update. Does not start or test the application."""

import argparse
import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

FILES = ["atlas/gateway.py", "atlas/swarm.py", "atlas/workflow.py", "atlas/skunk.py",
    "atlas/skunk_runtime.py", "atlas/skunk_failures.py", "atlas/skunk_diagnose.py", "atlas/data/skunk/app.js"]
MOD_FILES = FILES + ["atlas/skunk_prompts.py", "atlas/token_budget.py", "atlas/skunk_usage.py", "atlas/skunk_budget.py"]
FLOW_FILES = MOD_FILES + ["atlas/tools.py", "atlas/gateway_service.py", "atlas/skunk_context.py", "atlas/skunk_scheduling.py"]
RESUME_FILES = FLOW_FILES + ["atlas/skunk_json.py", "atlas/skunk_resume.py", "atlas/skunk_evidence.py", "atlas/reporting.py", "atlas/network_research.py", "atlas/data/skunk/index.html"]
VALIDATE_FILES = RESUME_FILES + ["atlas/web_research.py", "atlas/skunk_activity.py"]
BASE = "44000e6f8a9ece1f27cf0b269a52b6015d92620c"
UPGRADE_BASES = [BASE, "4e9cf1d7564c9bc623321ac03953ccd140c6bcf5", "ec2f6474691cf6ea9712d1e725eb2cb3ff25ab74", "74e97c5170fdd289de463aebf2b00e5c0eb1abd4", "14c8c3a382f18c52ca030194d9541d33aec4553a", "721346d3c18d0d0cf6fd59c6bd8d380b19ed3d7d", "379c0df570774aa5c037b3e048da795f18a48596"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--hotfix", choices=("flow3", "resume4", "validate5"), default="validate5")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    output = args.destination.resolve()
    basename = "skunk-" + args.hotfix
    root = output / basename
    assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, text=True).strip(), "Commit the reviewed source before building"
    root.mkdir(parents=True, exist_ok=False)
    manifest = {"hotfix": args.hotfix, "internal_package": "atlas", "base_source_commit": BASE,
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
        "application_test_suites_run": False, "offline_diagnostics_run": True,
        "model_calls": 0, "target_requests": 0, "files": []}
    if args.hotfix in ("flow3", "resume4", "validate5"):
        assignments = ast.parse((repo / "atlas/skunk_prompts.py").read_text()).body
        models = next(node.value for node in assignments if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "MODELS" for target in node.targets))
        manifest["model_presets"] = ast.literal_eval(models)
        manifest["new_run_usage_policy"] = {"mode": "tracking_only", "token_limits_enforced": False, "spending_limits_enforced": False, "model_call_limits_enforced": False, "tool_call_limits_enforced": False}
    files = {"flow3": FLOW_FILES, "resume4": RESUME_FILES, "validate5": VALIDATE_FILES}[args.hotfix]
    for name in files:
        source = repo / name
        target = root / "files" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        original = subprocess.run(["git", "show", BASE + ":" + name], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        preimages = []
        for base in UPGRADE_BASES:
            prior = subprocess.run(["git", "show", base + ":" + name], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            value = hashlib.sha256(prior.stdout).hexdigest() if prior.returncode == 0 else None
            if value not in preimages:
                preimages.append(value)
        manifest["files"].append({"path": name, "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "base_sha256": hashlib.sha256(original.stdout).hexdigest() if original.returncode == 0 else None,
            "base_sha256s": preimages})
    (root / "HOTFIX.json").write_text(json.dumps(manifest, indent=2) + "\n")
    shutil.copy2(repo / "scripts/skunk-apply-hotfix.sh", root / "apply.sh")
    shutil.copy2(repo / "scripts/skunk-apply-hotfix.py", root / "apply.py")
    guide = {"flow3": "docs/SKUNK_FLOW_UPDATE.md", "resume4": "docs/SKUNK_RESUME_UPDATE.md", "validate5": "docs/SKUNK_VALIDATION_UPDATE.md"}[args.hotfix]
    shutil.copy2(repo / guide, root / "README.md")
    archive = output / (basename + ".tar.gz")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(root, arcname=root.name)
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / (archive.name + ".sha256")).write_text(sha + "  " + archive.name + "\n")
    shutil.copy2(root / "HOTFIX.json", output / "HOTFIX.json")
    print(json.dumps({"archive": str(archive), "bytes": archive.stat().st_size, "sha256": sha}, indent=2))


if __name__ == "__main__":
    main()
