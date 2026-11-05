"""Owned Claude double with actual background work in its managed scope."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from mail_provider import main


def jobs():
    repo = Path.cwd()
    ready = repo / "provider-ready.json"
    until = time.monotonic() + 30
    while not ready.exists():
        if time.monotonic() > until:
            return
        time.sleep(.02)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(180)",
                              "takeover-owned-job"], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    birth = Path(f"/proc/{child.pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
    escaped = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(180)",
                                "takeover-escaped-job", str(repo)], start_new_session=True,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    escaped_birth = Path(f"/proc/{escaped.pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
    (repo / "takeover-job.json").write_text(json.dumps({"pid": child.pid, "birth": birth,
                                                        "session": os.environ["SE_SESSION"],
                                                        "escaped": {"pid": escaped.pid, "birth": escaped_birth}}))


if __name__ == "__main__":
    threading.Thread(target=jobs, daemon=True).start()
    main()
