"""Build and run the embedded-host budget measurement on native runners."""
from pathlib import Path
import subprocess
import sys

subprocess.run(["cargo", "build", "--release", "--locked", "--jobs", "4", "-p", "se-host",
                "--features", "secode", "--example", "embedded_budget_probe"], check=True)
root = Path(__file__).resolve().parent.parent
suffix = ".exe" if sys.platform == "win32" else ""
probe = root / "target" / "release" / "examples" / ("embedded_budget_probe" + suffix)
subprocess.run([sys.executable, str(root / "probes/embedded-budget.py"), sys.argv[1], sys.argv[2], str(probe)], check=True)
