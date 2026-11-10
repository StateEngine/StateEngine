"""Owned provider protocol double with one ordinary managed background job."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from mail_provider import main


def job():
    repo = Path.cwd()
    while not (repo / 'provider-ready.json').exists():
        time.sleep(.02)
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(180)', 'force-owned-child'],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (repo / 'force-job.json').write_text(json.dumps({'pids': [os.getppid(), os.getpid(), child.pid]}))


if __name__ == '__main__':
    threading.Thread(target=job, daemon=True).start()
    main()
