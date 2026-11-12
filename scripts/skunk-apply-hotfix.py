"""Apply the hash-pinned code update using the installed standalone Python."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from datetime import datetime, timezone


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".skunk-hotfix-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path)
    parser.add_argument("--package", required=True, type=Path)
    args = parser.parse_args()
    prefix, package = args.prefix.resolve(), args.package.resolve()
    manifest = json.loads((package / "HOTFIX.json").read_text())
    assert manifest["hotfix"] in ("retry1", "mod2", "flow3", "resume4", "validate5") and manifest["internal_package"] == "atlas", "Unexpected patch identity"
    hotfix = manifest["hotfix"]
    record_path = prefix / "BUILD-RECORD.json"
    record = json.loads(record_path.read_text())
    assert record["product"] == "SKUNK" and record["internal_package"] == "atlas", "SKUNK installation required"
    assert record["source_commit"] == manifest["base_source_commit"], "This update requires the original SKUNK rc1 bundle"
    runtime = Path(os.environ.get("SKUNK_DATA_DIR", Path.home() / ".local/share/atlas-skunk")).expanduser().resolve()
    runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = (runtime / "controller.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("Exit the SKUNK CLI with Ctrl+C before applying this update, then rerun this command.")
    changes = []
    for item in manifest["files"]:
        relative = Path(item["path"])
        assert relative.parts[0] == "atlas" and ".." not in relative.parts and relative.suffix in (".py", ".js", ".html"), "Unexpected patch path"
        source = package / "files" / relative
        assert not source.is_symlink() and sha(source) == item["sha256"], "Patch checksum mismatch: " + str(relative)
        for root in (prefix / "app", prefix / "runtime/lib/python3.12/site-packages"):
            target = root / relative
            assert target.resolve().is_relative_to(prefix) and not target.is_symlink(), "Unexpected installation path"
            current = sha(target) if target.exists() else None
            accepted = item.get("base_sha256s", [item["base_sha256"]])
            assert current in [*accepted, item["sha256"]], "Local code differs; preserve it and inspect before updating: " + str(relative)
            if current != item["sha256"]:
                changes.append((source, target, target.read_bytes() if target.exists() else None, target.stat().st_mode & 0o777 if target.exists() else 0o600))
    if not changes:
        print("The " + hotfix + " code update is already installed. Run: skunk diagnose")
        return
    backup = prefix / "hotfix-backups" / (hotfix + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    backup.mkdir(parents=True, mode=0o700)
    shutil.copy2(record_path, backup / "BUILD-RECORD.json")
    applied = []
    try:
        for source, target, previous, mode in changes:
            if previous is not None:
                saved = backup / target.relative_to(prefix)
                saved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                saved.write_bytes(previous)
            replace(target, source.read_bytes(), mode)
            applied.append((target, previous, mode))
        record["installed_hotfix"] = {"id": manifest["hotfix"], "source_commit": manifest["source_commit"],
            "applied_at": datetime.now(timezone.utc).isoformat(), "application_test_suites_run": False,
            "offline_diagnostics_run": manifest.get("offline_diagnostics_run", False)}
        if hotfix in ("mod2", "flow3", "resume4", "validate5"):
            record["installed_hotfix"].update(model_presets=manifest["model_presets"], usage_policy=manifest["new_run_usage_policy"])
        replace(record_path, (json.dumps(record, indent=2) + "\n").encode())
    except BaseException:
        for target, previous, mode in reversed(applied):
            if previous is None:
                target.unlink(missing_ok=True)
            else:
                replace(target, previous, mode)
        replace(record_path, (backup / "BUILD-RECORD.json").read_bytes())
        raise
    print("Installed " + hotfix + ". Existing database, knowledge, credentials and token holds were preserved.")
    if hotfix in ("mod2", "flow3", "resume4", "validate5"):
        print("New SKUNK runs use deepseek-v4-mod / glm-5.3-mod and track usage without local token or spending caps.")
    if hotfix == "flow3":
        print("Run-wide model/tool call caps are disabled; context packing and specialist coalescing are updated.")
    print("Inspect the previous run: skunk diagnose")
    if hotfix in ("resume4", "validate5"):
        print("Recover the latest saved assessment: skunk resume --latest")
        print("Only recoverable unfinished tasks retry. Completed tasks, frozen scope, old reports and billing history stay preserved.")
        if hotfix == "validate5":
            print("See actual validation progress: skunk diagnose --activity")
            print("A completed discovery task does not repeat on resume. A new --scope ... --ra run uses the repaired discovery/check planning.")
    else:
        print("Then start your chosen scope again; new runs have bounded automatic retries.")
    print("Code backup: " + str(backup))


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, KeyError) as error:
        raise SystemExit(str(error))
