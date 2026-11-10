#!/usr/bin/env python3
"""Add a corrected installer without altering checksum-protected bundle files."""

from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
subprocess.run(["sha256sum", "--check", "--quiet", "SHA256SUMS"], cwd=root, check=True)
script = root / "ATLAS/scripts/install-prebuilt.sh"
original = script.read_text()
needle = 'python3 "$app_dir/scripts/prebuilt-images.py" "$payload_dir/IMAGES.json"'
if original.count(needle) != 1:
    raise SystemExit("Unexpected original installer; no changes made")
fixed = original.replace(
    needle,
    'python3 "$app_dir/scripts/prebuilt-images-docker29.py" "$payload_dir/IMAGES.json"',
)
for target, data in (
    (
        script.parent / "prebuilt-images-docker29.py",
        Path(__file__).with_name("prebuilt-images.py").read_bytes(),
    ),
    (script.parent / "install-prebuilt-docker29.sh", fixed.encode()),
):
    if target.exists():
        if target.read_bytes() != data:
            raise SystemExit(
                "Existing repair file differs; refusing overwrite: " + target.name
            )
    else:
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(0o700)
print("Repair added. Original bundle, images, checksums and data are unchanged.")
