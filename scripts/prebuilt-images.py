#!/usr/bin/env python3
"""Verify all loaded image identities without starting application containers."""

import json
import os
from pathlib import Path
import subprocess
import sys

manifest = json.loads(Path(sys.argv[1]).read_text())
environment = {
    key: value
    for key, value in os.environ.items()
    if key
    not in (
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    )
}
for image in manifest["images"]:
    result = subprocess.run(
        [
            "docker",
            "--host=unix:///var/run/docker.sock",
            "image",
            "inspect",
            image["tag"],
            "--format",
            "{{.Id}} {{.Os}} {{.Architecture}}",
        ],
        capture_output=True,
        text=True,
        check=True,
        env=environment,
    )
    if result.stdout.strip() != image["id"] + " linux amd64":
        raise SystemExit(
            "Loaded image identity/platform differs from the release manifest: "
            + image["tag"]
        )
print("All five prebuilt image identities match the release manifest (Linux amd64).")
