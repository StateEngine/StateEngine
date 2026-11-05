"""Claude protocol double for mail_cli.py's authenticated recipient fixture."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
import urllib.request


def main():
    se, home, *arguments = sys.argv[1:]
    cwd = Path.cwd()
    (cwd / "provider-argv.txt").write_text("\n".join(arguments))
    flag = "--resume" if "--resume" in arguments else "--session-id"
    conversation = arguments[arguments.index(flag) + 1]
    # Claude's JS convention counts UTF-16 units, including surrogate pairs.
    encoded = str(cwd).encode("utf-16-le")
    units = [int.from_bytes(encoded[i:i + 2], "little") for i in range(0, len(encoded), 2)]
    slug = "".join(chr(u) if 48 <= u <= 57 or 65 <= u <= 90 or 97 <= u <= 122 else "-" for u in units)
    if len(slug) > 200:
        value = 0
        for unit in units:
            value = (31 * value + unit) & 0xffffffff
        value = abs(value if value < 0x80000000 else value - 0x100000000)
        suffix = ""
        while True:
            suffix = "0123456789abcdefghijklmnopqrstuvwxyz"[value % 36] + suffix
            value //= 36
            if not value:
                break
        slug = slug[:200] + "-" + suffix
    transcript = Path(os.environ["HOME"]) / ".claude/projects" / slug / (conversation + ".jsonl")
    if (cwd / "startup-stderr-burst").exists():
        # A full diagnostic pipe must not prevent the provider reaching init.
        sys.stderr.buffer.write(b"startup diagnostic\n" * 8192)
        sys.stderr.buffer.flush()
        (cwd / "startup-stderr-finished").write_text("drained")
    assert sys.stdin.readline(), "host did not deliver its initial task"
    print(json.dumps({"type": "system", "subtype": "init", "session_id": conversation}), flush=True)
    # Stock Claude echoes init before it creates the native transcript (FH09).
    # Keep the gap observable so eager source pinning fails this real CLI judge.
    time.sleep(0.25)
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(json.dumps({"type": "user", "sessionId": conversation,
                          "uuid": "native-judge-task", "message": {"role": "user",
                          "content": "Fresh launch judge"}}) + "\n")
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    # Both issued transports must verify possession before production C3. Their
    # secrets stay in the owner-only files and are never copied into judge logs.
    ipc = subprocess.run([se, "--home", home, "mcp"], input=request + b"\n",
                         capture_output=True, timeout=15)
    assert ipc.returncode == 0, "prepared session discovery failed"
    reply = json.loads(ipc.stdout)
    (cwd / "provider-ipc.json").write_text(json.dumps(reply))
    assert "result" in reply or reply.get("error", {}).get("message", "").startswith("session-not-active:"), "prepared session discovery was not verified"
    config = json.loads(Path(arguments[arguments.index("--mcp-config") + 1]).read_text())
    server = config["mcpServers"]["stateengine"]
    call = urllib.request.Request(server["url"], data=request,
                                  headers={**server["headers"], "Content-Type": "application/json"})
    with urllib.request.urlopen(call, timeout=15) as response:
        reply = json.load(response)
        assert response.status == 200 and ("result" in reply or
               reply.get("error", {}).get("message", "").startswith("session-not-active:")), "prepared HTTP discovery failed"
    (cwd / "provider-ready.json").write_text(json.dumps({"conversation": conversation,
                                                       "session_discovery": True, "http_discovery": True,
                                                       "native_root_pid": os.getppid(), "helper_pid": os.getpid()}))
    # Keep the actual native root alive until the caller observes running/C3.
    while True:
        time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        with (Path.cwd() / "provider-error.txt").open("w") as log:
            traceback.print_exc(file=log)
        raise
