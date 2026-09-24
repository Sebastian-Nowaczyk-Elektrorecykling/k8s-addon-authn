"""Wait for the projected revision, then snapshot configuration for this pod."""
import os
from pathlib import Path
import shutil
import time

expected = os.environ.get("EXPECTED_REVISION", "")
while True:
    # Resolve the atomic ConfigMap symlink once, so every file has the same version.
    snapshot = Path("/runtime/..data").resolve()
    try:
        revision = (snapshot / "revision").read_text()
        if not expected or revision == expected:
            for name in ("nginx.conf", "oauth2-proxy.cfg", "sites.json"):
                shutil.copyfile(snapshot / name, Path("/config") / name)
            break
    except FileNotFoundError:
        pass
    time.sleep(2)
