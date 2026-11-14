"""Owned Claude protocol process that finishes its native transcript after host exit."""
import json
import os
from pathlib import Path
import sys
import time
import subprocess
import urllib.request
from judge_records import write_json


def main():
    se, home, *arguments = sys.argv[1:]
    repo = Path.cwd()
    conversation = arguments[arguments.index("--session-id") + 1]
    slug = "".join(c if c.isascii() and c.isalnum() else "-" for c in str(repo))
    transcript = Path(os.environ["HOME"]) / ".claude/projects" / slug / (conversation + ".jsonl")
    transcript.parent.mkdir(parents=True, exist_ok=True)
    def append(role, text, identity, newline=True):
        row = {"type": role, "sessionId": conversation, "uuid": identity,
               "message": {"role": role, "content": text}}
        with transcript.open("a") as stream:
            stream.write(json.dumps(row) + ("\n" if newline else ""))
            stream.flush()
            os.fsync(stream.fileno())
        return row
    append("user", "Finish the original task after the release marker", "recovery-task")
    assert sys.stdin.readline(), "host did not deliver its task"
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    ipc = subprocess.run([se, '--home', home, 'mcp'], input=request + b'\n',
                         capture_output=True, timeout=15)
    def verified(reply):
        return 'result' in reply or reply.get('error', {}).get('message', '').startswith('session-not-active:')
    assert ipc.returncode == 0 and verified(json.loads(ipc.stdout)), 'issued IPC discovery failed'
    config = json.loads(Path(arguments[arguments.index('--mcp-config') + 1]).read_text())
    server = config['mcpServers']['stateengine']
    call = urllib.request.Request(server['url'], data=request,
                                  headers={**server['headers'], 'Content-Type': 'application/json'})
    with urllib.request.urlopen(call, timeout=15) as response:
        assert verified(json.load(response)), 'issued HTTP discovery failed'
    print(json.dumps({"type": "system", "subtype": "init", "session_id": conversation}), flush=True)
    first = append("assistant", "BEFORE_HOST_CRASH_REPLY", "before-host-crash")
    print(json.dumps(first), flush=True)
    print(json.dumps({"type": "result", "session_id": conversation}), flush=True)
    write_json(repo / "recovery-ready.json", {"helper_pid": os.getpid()})
    while not (repo / "work-release").exists():
        time.sleep(.02)
    (repo / "notes.md").write_text("The original task finished after its host exited.\n")
    late = append("assistant", "AFTER_HOST_CRASH_REPLY", "after-host-crash",
                  not (repo / "partial-tail").exists())
    # The old host's stdout reader is gone; this also exits the native wrapper.
    print(json.dumps(late), flush=True)


if __name__ == "__main__":
    main()
