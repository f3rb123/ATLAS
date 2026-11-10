#!/usr/bin/env python3
"""Install only release-pinned tools; verify archive and executable hashes."""

import argparse, hashlib, io, json, os, tarfile, urllib.request, zipfile
from pathlib import Path


def ensure_license(destination, info):
    expected = info.get("license_sha256")
    if not expected:
        raise SystemExit("Pinned upstream license metadata is required")
    target = destination / "UPSTREAM-LICENSE"
    if target.is_file():
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise SystemExit("Existing upstream license hash mismatch")
        return
    local = destination / info.get("license_file", "UPSTREAM-LICENSE")
    if local.is_file():
        content = local.read_bytes()
    elif info.get("license_url"):
        with urllib.request.urlopen(info["license_url"], timeout=30) as response:
            content = response.read(65536)
    else:
        raise SystemExit("Upstream license is unavailable")
    if hashlib.sha256(content).hexdigest() != expected:
        raise SystemExit("Upstream license integrity failure")
    with target.open("xb") as output:
        output.write(content)


def install(destination, selected=None):
    manifest = json.loads(
        (
            Path(__file__).resolve().parents[1] / "atlas/data/research_tools.json"
        ).read_text()
    )
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for name, info in manifest.items():
        if selected and name not in selected:
            continue
        if info.get("owner_managed"):
            print(name + ": owner-managed licensed executable required; not bundled")
            continue
        target = destination / name / name
        if (
            target.is_file()
            and hashlib.sha256(target.read_bytes()).hexdigest() == info["binary_sha256"]
        ):
            ensure_license(target.parent, info)
            print(name + ": verified existing pinned executable")
            continue
        if target.exists():
            raise SystemExit("Refusing to overwrite a mismatched tool: " + name)
        request = urllib.request.Request(
            info["url"], headers={"User-Agent": "ATLAS-pinned-tool-installer/1"}
        )
        with urllib.request.urlopen(request, timeout=90) as response:
            raw = response.read(250 * 1024 * 1024 + 1)
        if (
            len(raw) > 250 * 1024 * 1024
            or hashlib.sha256(raw).hexdigest() != info["archive_sha256"]
        ):
            raise SystemExit("Archive integrity failure: " + name)
        files = {}
        if info["url"].endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for item in archive.infolist():
                    filename = Path(item.filename).name
                    if not item.is_dir() and (
                        filename == name
                        or filename.lower().startswith(("license", "copying"))
                    ):
                        files[filename] = archive.read(item)
        else:
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                for item in archive.getmembers():
                    filename = Path(item.name).name
                    if item.isfile() and (
                        filename == name
                        or filename.lower().startswith(("license", "copying"))
                    ):
                        files[filename] = archive.extractfile(item).read()
        if (
            name not in files
            or hashlib.sha256(files[name]).hexdigest() != info["binary_sha256"]
        ):
            raise SystemExit("Executable integrity failure: " + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        for filename, content in files.items():
            path = target.parent / filename
            with path.open("xb") as output:
                output.write(content)
        target.chmod(0o755)
        ensure_license(target.parent, info)
        print(name + ": installed " + info["version"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", required=True)
    parser.add_argument("--tools", nargs="*")
    args = parser.parse_args()
    install(args.destination, args.tools)
