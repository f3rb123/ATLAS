#!/usr/bin/env python3
"""Verify pinned config identities across classic and OCI Docker image stores."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile


def main():
    manifest = json.loads(Path(sys.argv[1]).read_text())
    environment = {
        k: v
        for k, v in os.environ.items()
        if k
        not in (
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        )
    }
    docker = ["docker", "--host=unix:///var/run/docker.sock"]
    pending = {}
    for image in manifest["images"]:
        inspected = json.loads(
            subprocess.check_output(
                docker + ["image", "inspect", image["tag"]], env=environment, text=True
            )
        )[0]
        if (inspected.get("Os"), inspected.get("Architecture")) != ("linux", "amd64"):
            raise SystemExit("Wrong loaded image platform: " + image["tag"])
        if inspected["Id"] == image["id"]:
            continue
        descriptor = inspected.get("Descriptor") or {}
        if descriptor.get("digest") != inspected["Id"] or descriptor.get(
            "mediaType"
        ) not in (
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ):
            raise SystemExit("Unrecognized image identity mismatch: " + image["tag"])
        pending[image["tag"]] = image["id"]
    if pending:
        print(
            "Checking exported image configuration digests for the OCI image store...",
            flush=True,
        )
        # Stream the selected local images without starting containers or writing layers.
        with tempfile_errors() as errors:
            process = subprocess.Popen(
                docker + ["image", "save", *pending],
                stdout=subprocess.PIPE,
                stderr=errors,
                env=environment,
            )
            configs = {}
            entries = None
            try:
                with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
                    for member in archive:
                        name = member.name.removeprefix("./")
                        if not member.isfile() or member.size > 2 * 1024 * 1024:
                            continue
                        if name != "manifest.json" and not (
                            name.endswith(".json") or name.startswith("blobs/sha256/")
                        ):
                            continue
                        data = archive.extractfile(member).read()
                        if name == "manifest.json":
                            entries = json.loads(data)
                        digest = "sha256:" + hashlib.sha256(data).hexdigest()
                        if digest in pending.values():
                            configs[name] = (digest, json.loads(data))
                if process.wait() != 0:
                    raise SystemExit(
                        "Docker could not export image metadata; integrity not established"
                    )
            finally:
                process.stdout.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait()
            if not isinstance(entries, list):
                raise SystemExit(
                    "Export has no Docker tag/config mapping; integrity not established"
                )
            for tag, expected in pending.items():
                matching = [
                    entry
                    for entry in entries
                    if tag
                    in [
                        value.removeprefix("docker.io/")
                        for value in (entry.get("RepoTags") or [])
                    ]
                ]
                if len(matching) != 1:
                    raise SystemExit("Exported tag mapping mismatch: " + tag)
                config = configs.get(matching[0].get("Config", "").removeprefix("./"))
                if (
                    not config
                    or config[0] != expected
                    or (config[1].get("os"), config[1].get("architecture"))
                    != ("linux", "amd64")
                ):
                    raise SystemExit(
                        "Loaded configuration digest does not match the release: " + tag
                    )
    print("All prebuilt image configuration identities match (Linux amd64).")


def tempfile_errors():
    import tempfile

    return tempfile.TemporaryFile()


if __name__ == "__main__":
    main()
