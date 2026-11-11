"""Read-only interpreter mount for the prebuilt CLI's existing isolated sandboxes."""

import os
import sys
from pathlib import Path


def interpreter():
    root = os.environ.get("SKUNK_INSTALL_ROOT")
    prefix = Path(sys.base_prefix).resolve()
    if root and prefix == (Path(root).resolve() / "runtime") and (prefix / "bin/python3").is_file():
        return "/runtime/bin/python3", [
            "--ro-bind", str(prefix), "/runtime",
            "--setenv", "PYTHONHOME", "/runtime",
            "--setenv", "LD_LIBRARY_PATH", "/runtime/lib",
            "--setenv", "PATH", "/runtime/bin:/usr/bin:/bin",
        ]
    return ("/usr/bin/python3" if Path("/usr/bin/python3").exists() else "/usr/local/bin/python3"), []
