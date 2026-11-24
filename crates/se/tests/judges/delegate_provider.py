"""Claude protocol double for delegate_acceptance.py.

A task without a child marker behaves like mail_provider's held parent. A task
carrying `DELEGATE-CHILD:<mode>:<tag>` behaves like a headless one-shot child:
`complete` answers at once, `hold` answers only after `release-<tag>` appears,
`nest` first tries to delegate again over its own HTTP session, and `fail`
exits before it starts.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import traceback
import urllib.request

from judge_records import write_json
import mail_provider


class Replay:
    """Hands the already-read initial task back to mail_provider."""

    def __init__(self, line):
        self.line = line

    def readline(self):
        line, self.line = self.line, ""
        return line


def emit(frame):
    print(json.dumps(frame), flush=True)


def call_http(server, method, params, number):
    request = json.dumps({"jsonrpc": "2.0", "id": number, "method": method,
                          "params": params}).encode()
    call = urllib.request.Request(server["url"], data=request,
                                  headers={**server["headers"], "Content-Type": "application/json"})
    with urllib.request.urlopen(call, timeout=20) as response:
        return response.status, json.load(response)


def child(se, home, arguments, first, mode, tag):
    repo = Path.cwd()
    if mode == "fail":
        write_json(repo / f"child-{tag}-failed.json", {"pid": os.getpid()})
        sys.exit(3)
    conversation = arguments[arguments.index("--session-id") + 1]
    assert str(repo).isascii() and len(str(repo)) < 200
    slug = "".join(c if c.isalnum() else "-" for c in str(repo))
    transcript = Path(os.environ["HOME"]) / ".claude/projects" / slug / (conversation + ".jsonl")
    emit({"type": "system", "subtype": "init", "session_id": conversation})
    transcript.parent.mkdir(parents=True, exist_ok=True)
    with transcript.open("a") as output:
        output.write(json.dumps({"type": "user", "sessionId": conversation, "uuid": f"task-{tag}",
                                 "message": {"role": "user", "content": f"Delegated task {tag}"}}) + "\n")
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    ipc = subprocess.run([se, "--home", home, "mcp"], input=request + b"\n",
                         capture_output=True, timeout=20)
    assert ipc.returncode == 0, "child session discovery failed"
    server = json.loads(Path(arguments[arguments.index("--mcp-config") + 1]).read_text())["mcpServers"]["stateengine"]
    status, _ = call_http(server, "tools/list", {}, 2)
    assert status == 200, "child HTTP discovery failed"
    extra = repo / f"child-{tag}-input.jsonl"
    closed = threading.Event()

    def record_input():
        # Every later stdin line is recorded; a one-shot child must never get a turn 2.
        for line in sys.stdin:
            with extra.open("a") as log:
                log.write(line if line.endswith("\n") else line + "\n")
        closed.set()

    threading.Thread(target=record_input, daemon=True).start()
    write_json(repo / f"child-{tag}-ready.json", {"conversation": conversation,
                                                  "native_root_pid": os.getppid(),
                                                  "helper_pid": os.getpid()})
    if mode == "nest":
        # The session activates after this provider proves its transports.
        end = time.monotonic() + 30
        while True:
            status, reply = call_http(server, "tools/call", {"name": "stateengine_delegate", "arguments": {
                "task": "A grandchild must be refused", "idempotency_key": f"nested-{tag}"}}, 3)
            pending = "session-not-active" in json.dumps(reply)
            if not pending or time.monotonic() >= end:
                break
            time.sleep(0.2)
        write_json(repo / f"child-{tag}-nested.json", {"status": status, "reply": reply})
    if mode == "hold":
        while not (repo / f"release-{tag}").exists():
            time.sleep(0.05)
    answer = f"DELEGATE-ANSWER-{tag}"
    with transcript.open("a") as output:
        output.write(json.dumps({"type": "assistant", "sessionId": conversation, "uuid": f"answer-{tag}",
                                 "message": {"role": "assistant", "content": answer}}) + "\n")
        output.flush()
        os.fsync(output.fileno())
    emit({"type": "assistant", "session_id": conversation,
          "message": {"role": "assistant", "content": [{"type": "text", "text": answer}]}})
    emit({"type": "result", "subtype": "success", "is_error": False, "session_id": conversation,
          "result": answer})
    # Stay alive until the host stops this turn-1 child.
    while not closed.wait(1):
        pass


def main():
    se, home, *arguments = sys.argv[1:]
    first = sys.stdin.readline()
    assert first, "host did not deliver its initial task"
    marker = re.search(r"DELEGATE-CHILD:(complete|hold|nest|fail):([A-Za-z0-9-]+)", first)
    if marker is None:
        sys.stdin = Replay(first)
        mail_provider.main()
        return
    child(se, home, arguments, first, marker.group(1), marker.group(2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        with (Path.cwd() / f"delegate-provider-error-{os.getpid()}.txt").open("w") as log:
            traceback.print_exc(file=log)
        raise
