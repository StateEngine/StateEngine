"""Owned provider protocol double with one ordinary managed background job."""
import os
from pathlib import Path
import subprocess
import sys
import threading
from judge_records import wait_json, write_json
from mail_provider import main


def job():
    repo = Path.cwd()
    wait_json(repo / 'provider-ready.json', seconds=30)
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(180)', 'force-owned-child'],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    write_json(repo / 'force-job.json', {'pids': [os.getppid(), os.getpid(), child.pid]})


if __name__ == '__main__':
    threading.Thread(target=job, daemon=True).start()
    main()
