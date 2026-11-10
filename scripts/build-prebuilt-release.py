#!/usr/bin/env python3
"""Build-only GitHub publishing path. Never starts ATLAS or calls a provider."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

NAME = "atlas-v3-prebuilt-20261110"
CORPUS_SHA = "e8b8643ed98119b23dd3b20e314654d3dca721e5ab53888271687dbefcb71025"
CORPUS_URL = "https://github.com/f3rb123/ATLAS/releases/download/atlas-v3-corpus-review-2026-11-09/atlas-v3-public-corpus-review.zip"
DEPENDENCIES = {
    "postgres": "pgvector/pgvector@sha256:7d0a41464797aeb9862dfdc0bbf1526b82cfd324cdd8036df19e3545f4a9ccb8",
    "redis": "redis@sha256:c5d34a98396a4775e223c74e929162c35c5a2182901ba26b50ade939941ce14b",
    "proxy": "caddy@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d",
}


def run(*command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()


def build(source, output, budget):
    commit = git(source, "rev-parse", "HEAD")
    if commit != git(source, "rev-parse", NAME + "^{commit}"):
        raise SystemExit("Source does not match the published installation tag")
    package = output / NAME
    payload = package / "payload"
    payload.mkdir(parents=True)
    images = []
    for service in ("api", "web"):
        tag = "atlas-prebuilt/" + service + ":20261110"
        run(
            "docker",
            "build",
            "--secret",
            "id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt",
            "--label",
            "org.opencontainers.image.revision=" + commit,
            "--file",
            str(source / ("Dockerfile." + service)),
            "--tag",
            tag,
            str(source),
        )
    for service, reference in DEPENDENCIES.items():
        run("docker", "pull", "--platform", "linux/amd64", reference)
        run("docker", "tag", reference, "atlas-prebuilt/" + service + ":20261110")
    for service in ("api", "web", "postgres", "redis", "proxy"):
        tag = "atlas-prebuilt/" + service + ":20261110"
        identity = (
            subprocess.check_output(
                [
                    "docker",
                    "image",
                    "inspect",
                    tag,
                    "--format",
                    "{{.Id}} {{.Os}} {{.Architecture}}",
                ],
                text=True,
            )
            .strip()
            .split()
        )
        if identity[1:] != ["linux", "amd64"]:
            raise SystemExit("Prebuilt platform differs from Linux amd64")
        images.append(
            {
                "service": service,
                "tag": tag,
                "id": identity[0],
                "upstream_reference": DEPENDENCIES.get(service, "source:" + commit),
            }
        )
    run("docker", "builder", "prune", "--force")
    (payload / "IMAGES.json").write_text(
        json.dumps(
            {
                "platform": "linux/amd64",
                "application_revision": commit,
                "images": images,
            },
            indent=2,
        )
        + "\n"
    )
    with (payload / "container-images.tar.gz").open("wb") as target:
        save = subprocess.Popen(
            ["docker", "save", *[image["tag"] for image in images]],
            stdout=subprocess.PIPE,
        )
        compress = subprocess.Popen(["gzip", "-1"], stdin=save.stdout, stdout=target)
        save.stdout.close()
        compressed, saved = compress.wait(), save.wait()
        if compressed or saved:
            raise SystemExit("Image export failed")
    corpus = payload / "atlas-v3-public-corpus-review.zip"
    with (
        urllib.request.urlopen(CORPUS_URL, timeout=120) as response,
        corpus.open("wb") as target,
    ):
        shutil.copyfileobj(response, target)
    if sha(corpus) != CORPUS_SHA:
        raise SystemExit("Original corpus checksum mismatch")
    shutil.copyfile(budget, payload / "BUDGET-FLOOR.json")
    with tempfile.TemporaryFile() as stream:
        run(
            "git",
            "-C",
            str(source),
            "archive",
            "--format=tar",
            "--prefix=ATLAS/",
            commit,
            stdout=stream,
        )
        stream.seek(0)
        with tarfile.open(fileobj=stream) as archive:
            archive.extractall(package, filter="data")
    git(source, "update-ref", "refs/heads/work", commit)
    run(
        "git",
        "-C",
        str(source),
        "bundle",
        "create",
        str(package / "atlas-v3.bundle"),
        "refs/heads/work",
        "refs/tags/" + NAME,
    )
    run("git", "-C", str(source), "bundle", "verify", str(package / "atlas-v3.bundle"))
    (package / "INSTALL.sh").write_text(
        '#!/usr/bin/env bash\nset -euo pipefail\nexec bash "$(cd "$(dirname "$0")" && pwd)/ATLAS/scripts/install-prebuilt.sh" "$@"\n'
    )
    (package / "INSTALL.sh").chmod(0o755)
    shutil.copyfile(source / "docs/PREBUILT_INSTALL.md", package / "README-FIRST.md")
    record = {
        "source_commit": commit,
        "platform": "linux/amd64",
        "images": images,
        "corpus_included": True,
        "records": 21012,
        "vectors": 34229,
        "dimensions": 384,
        "full_text_bounty_reports": 0,
        "corpus_sha256": CORPUS_SHA,
        "model_assets_included": True,
        "server_compilation_required": False,
        "application_tests_run": False,
        "installer_executed": False,
        "candidate_containers_started": False,
        "provider_calls": 0,
        "target_requests": 0,
        "production_verified": False,
        "built_by": "GitHub Actions build-only publisher; workspace release upload credentials were rejected",
        "builder_commit": os.environ.get("GITHUB_SHA"),
    }
    (package / "BUILD-RECORD.json").write_text(json.dumps(record, indent=2) + "\n")
    notes = f"""# ATLAS V3 all-in-one prebuilt release candidate

One ZIP includes five complete Linux x86-64 images (API/workers, frontend,
PostgreSQL/pgvector, Redis and Caddy), eight pinned native tool binaries,
the original corpus, all **34,229 real 384-dimensional vectors**, and the pinned
MiniLM ONNX/tokenizer assets. Corpus identities: **21,012 advisory/reference
records**; full-text bounty report count: **zero**.

Extract the ZIP, enter `{NAME}`, then run `sudo bash INSTALL.sh`. Docker Engine,
Compose >=2.24.4, Python 3 and compatible Linux namespace support are prerequisites.
No ATLAS compilation, npm/pip install, image pull, model download or re-embedding
is required on the server. The installer restores the supplied knowledge
automatically before application startup. See README-FIRST.md.

The default endpoint is private `https://atlas.localhost:8443`, bound to loopback.
Create your owner account with the bootstrap command and configure provider/API
keys securely. Private credentials/accounts/databases are not distributed.
The historical budget floor preserves consumption and uncertain holds; run only
one spending instance. Waybackurls needs owner licensing/provenance, and raw
Amass/masscan engines remain external result imports.

**Prebuilt release candidate. No application tests were run.** This build-only
publisher does not start ATLAS or execute the installer. Runtime/production
acceptance remains deferred at the owner's request. Source: `{commit}`.
Corpus SHA256: `{CORPUS_SHA}`. Image identities and exact build scope are in
BUILD-RECORD.json; file checksums are in SHA256SUMS.
"""
    (package / "RELEASE-MANIFEST.md").write_text(notes)
    paths = sorted(path for path in package.rglob("*") if path.is_file())
    (package / "SHA256SUMS").write_text(
        "".join(
            sha(path) + "  " + path.relative_to(package).as_posix() + "\n"
            for path in paths
        )
    )
    destination = output / (NAME + ".zip")
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
        allowZip64=True,
    ) as archive:
        for path in sorted(package.rglob("*")):
            if path.is_file():
                archive.write(
                    path,
                    NAME + "/" + path.relative_to(package).as_posix(),
                    compress_type=zipfile.ZIP_STORED
                    if path.suffix in (".gz", ".zip")
                    else zipfile.ZIP_DEFLATED,
                )
    digest = sha(destination)
    destination.with_suffix(".zip.sha256").write_text(
        digest + "  " + destination.name + "\n"
    )
    (output / "GITHUB-NOTES.md").write_text(
        notes
        + f"\nZIP size: {destination.stat().st_size:,} bytes. SHA256: `{digest}`.\n"
    )


def verify_assets(output, metadata):
    archive = output / (NAME + ".zip")
    asset = next(
        item
        for item in json.loads(metadata.read_text())["assets"]
        if item["name"] == archive.name
    )
    if (
        asset["state"] != "uploaded"
        or asset["size"] != archive.stat().st_size
        or asset.get("digest") != "sha256:" + sha(archive)
    ):
        raise SystemExit("GitHub asset metadata does not match the local archive")
    print("GitHub archive size and SHA256 match; ready to publish.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--budget-floor", type=Path)
    parser.add_argument("--verify-assets", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.verify_assets:
        verify_assets(args.output.resolve(), args.verify_assets.resolve())
    else:
        build(args.source.resolve(), args.output.resolve(), args.budget_floor.resolve())
