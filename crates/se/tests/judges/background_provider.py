"""Account-free Claude protocol double that completes every turn and, on
request, leaves a process running in its own scope.

Before answering a frame it obeys two control files in its working directory:
`spawn-background` starts a long-running child carrying a secret argument, and
`stop-background` stops that child; each is removed once obeyed.
"""
import json
from pathlib import Path
import subprocess
import sys

import burst_provider
import mail_provider

SECRET = "background-secret-7c1e9d"


def obey(repo, child):
    spawn, stop = repo / "spawn-background", repo / "stop-background"
    if spawn.exists() and child is None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)", SECRET],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        (repo / "background-pid").write_text(str(child.pid))
        spawn.unlink()
    if stop.exists() and child is not None:
        child.kill()
        child.wait(timeout=10)
        (repo / "background-pid").unlink()
        stop.unlink()
        child = None
    return child


def answer_with_background():
    repo = Path.cwd()
    conversation = json.loads((repo / "provider-ready.json").read_text())["conversation"]
    native = burst_provider.transcript(conversation)
    burst_provider.complete(conversation, native, 0, None)
    (repo / "launch-turn-complete").write_text("complete")
    child, turn = None, 0
    for line in sys.stdin:
        if not line.strip():
            continue
        turn += 1
        child = obey(repo, child)
        burst_provider.complete(conversation, native, turn, burst_provider.text_of(json.loads(line)))
    raise RuntimeError("stdin closed before public shutdown")


if __name__ == "__main__":
    mail_provider.main(answer_with_background)
