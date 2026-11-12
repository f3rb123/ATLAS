"""Assemble the small source-only update. Does not start or test the application."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

FILES = ["atlas/gateway.py", "atlas/swarm.py", "atlas/workflow.py", "atlas/skunk.py",
    "atlas/skunk_runtime.py", "atlas/skunk_failures.py", "atlas/skunk_diagnose.py", "atlas/data/skunk/app.js"]
BASE = "44000e6f8a9ece1f27cf0b269a52b6015d92620c"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    output = args.destination.resolve()
    root = output / "skunk-retry-hotfix1"
    root.mkdir(parents=True, exist_ok=False)
    manifest = {"hotfix": "retry1", "internal_package": "atlas", "base_source_commit": BASE,
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
        "tests_run": False, "model_calls": 0, "target_requests": 0, "files": []}
    assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, text=True).strip(), "Commit the reviewed source before building"
    for name in FILES:
        source = repo / name
        target = root / "files" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        original = subprocess.run(["git", "show", BASE + ":" + name], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        manifest["files"].append({"path": name, "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "base_sha256": hashlib.sha256(original.stdout).hexdigest() if original.returncode == 0 else None})
    (root / "HOTFIX.json").write_text(json.dumps(manifest, indent=2) + "\n")
    shutil.copy2(repo / "scripts/skunk-apply-hotfix.sh", root / "apply.sh")
    shutil.copy2(repo / "scripts/skunk-apply-hotfix.py", root / "apply.py")
    shutil.copy2(repo / "docs/SKUNK_RETRY_HOTFIX.md", root / "README.md")
    archive = output / "skunk-retry-hotfix1.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(root, arcname=root.name)
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / "skunk-retry-hotfix1.tar.gz.sha256").write_text(sha + "  " + archive.name + "\n")
    shutil.copy2(root / "HOTFIX.json", output / "HOTFIX.json")
    print(json.dumps({"archive": str(archive), "bytes": archive.stat().st_size, "sha256": sha}, indent=2))


if __name__ == "__main__":
    main()
