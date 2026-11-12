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
BASE = "44000e6f8a9ece1f27cf0b269a52b6015d92620c"
UPGRADE_BASES = [BASE, "4e9cf1d7564c9bc623321ac03953ccd140c6bcf5", "ec2f6474691cf6ea9712d1e725eb2cb3ff25ab74", "74e97c5170fdd289de463aebf2b00e5c0eb1abd4"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--hotfix", choices=("retry1", "mod2"), default="mod2")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    output = args.destination.resolve()
    basename = "skunk-mod2" if args.hotfix == "mod2" else "skunk-retry-hotfix1"
    root = output / basename
    root.mkdir(parents=True, exist_ok=False)
    manifest = {"hotfix": args.hotfix, "internal_package": "atlas", "base_source_commit": BASE,
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
        "tests_run": False, "model_calls": 0, "target_requests": 0, "files": []}
    if args.hotfix == "mod2":
        assignments = ast.parse((repo / "atlas/skunk_prompts.py").read_text()).body
        models = next(node.value for node in assignments if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "MODELS" for target in node.targets))
        manifest["model_presets"] = ast.literal_eval(models)
        manifest["new_run_usage_policy"] = {"mode": "tracking_only", "token_limits_enforced": False, "spending_limits_enforced": False}
    assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, text=True).strip(), "Commit the reviewed source before building"
    for name in (MOD_FILES if args.hotfix == "mod2" else FILES):
        source = repo / name
        target = root / "files" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        original = subprocess.run(["git", "show", BASE + ":" + name], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        preimages = []
        for base in (UPGRADE_BASES if args.hotfix == "mod2" else [BASE]):
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
    shutil.copy2(repo / ("docs/SKUNK_MOD_UPDATE.md" if args.hotfix == "mod2" else "docs/SKUNK_RETRY_HOTFIX.md"), root / "README.md")
    archive = output / (basename + ".tar.gz")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(root, arcname=root.name)
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / (archive.name + ".sha256")).write_text(sha + "  " + archive.name + "\n")
    shutil.copy2(root / "HOTFIX.json", output / "HOTFIX.json")
    print(json.dumps({"archive": str(archive), "bytes": archive.stat().st_size, "sha256": sha}, indent=2))


if __name__ == "__main__":
    main()
