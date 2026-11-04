"""Protects: each new input wakes a real protocol consumer without provider inbox polling."""
import json
import os
from pathlib import Path
import subprocess
import sys
import queue
import threading
import uuid
import re
import traceback
import urllib.request


def main():
    se, home, *arguments = sys.argv[1:]
    cwd = Path.cwd()
    (cwd / "provider-argv.txt").write_text("\n".join(arguments))
    flag = "--resume" if "--resume" in arguments else "--session-id"
    conversation = arguments[arguments.index(flag) + 1]
    slug = "".join(c if c.isascii() and c.isalnum() else "-" for c in str(cwd))
    transcript = Path(os.environ["HOME"]) / ".claude/projects" / slug / (conversation + ".jsonl")
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(json.dumps({"type": "user", "sessionId": conversation,
                          "uuid": "native-judge-task", "message": {"role": "user",
                          "content": "Fresh launch judge"}}) + "\n")
    initial = sys.stdin.readline()
    assert initial, "host did not deliver its initial task"
    print(json.dumps({"type": "system", "subtype": "init", "session_id": conversation}), flush=True)
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
    run_turns(initial, se, home, cwd, conversation, transcript)


def run_turns(initial, se, home, cwd, conversation, transcript):
    incoming = queue.Queue()
    lock = threading.Lock()
    sequence = 0

    def record(raw):
        value = json.loads(raw)
        assert value["type"] == "user", value
        with lock, (cwd / "provider-inputs.jsonl").open("a") as log:
            log.write(json.dumps(value) + "\n")
            log.flush()
            os.fsync(log.fileno())
        incoming.put(value)

    record(initial)

    def reader():
        for raw in sys.stdin:
            record(raw)
        incoming.put(None)

    threading.Thread(target=reader, daemon=True).start()

    def rpc(name, arguments):
        request = {"jsonrpc":"2.0", "id":str(uuid.uuid4()), "method":"tools/call", "params":{"name":name,"arguments":arguments}}
        result = subprocess.run([se, "--home", home, "mcp"], input=(json.dumps(request)+"\n").encode(), capture_output=True, timeout=30)
        assert result.returncode == 0, (name, result.stdout, result.stderr)
        reply = json.loads(result.stdout)["result"]
        with (cwd / "provider-rpc.jsonl").open("a") as log:
            log.write(json.dumps({"input_sequence":sequence,"name":name,"reply":reply})+"\n")
        assert not reply.get("isError", False), (name, reply)
        return reply["structuredContent"]

    def emit(value):
        print(json.dumps(value), flush=True)

    while True:
        frame = incoming.get()
        if frame is None:
            return
        sequence += 1
        # This is an actual echo of consumed input, with its original UUID.
        emit({**frame, "session_id":conversation})
        if sequence > 1:
            page = rpc("stateengine_msg_list", {"full":True})
            for row in page["items"]:
                read = rpc("stateengine_msg_read", {"msg_id":row["id"]})
                body = read["message"]["body"]
                assert body["complete"], body
                marker = re.search(r"wake-[0-9a-f-]{36}", body["text"])
                owner = re.search(r"Reply to owner (hu_[0-9a-f-]+)", body["text"])
                if not marker or not owner:
                    continue
                if "HOLD_BUSY" in body["text"]:
                    (cwd / "provider-busy.json").write_text(json.dumps({"sequence":sequence,"message_id":row["id"]}))
                    with (cwd / "busy-gate").open("rb", buffering=0) as gate:
                        assert gate.read(1) == b"!"
                rpc("stateengine_msg_send", {"to":owner.group(1),"body":marker.group(0),"kind":"done","reply_to":row["id"],"idempotency_key":str(uuid.uuid4())})
        assistant = {"type":"assistant","sessionId":conversation,"uuid":str(uuid.uuid4()),"message":{"role":"assistant","content":[{"type":"text","text":"Turn completed"}]}}
        with transcript.open("a") as stream:
            stream.write(json.dumps(assistant)+"\n")
            stream.flush()
        emit({**assistant,"session_id":conversation})
        emit({"type":"result","subtype":"success","is_error":False,"duration_ms":1,"duration_api_ms":1,"num_turns":1,"result":"Turn completed","session_id":conversation,"total_cost_usd":0,"usage":{},"uuid":str(uuid.uuid4())})
        (cwd / "provider-idle.json").write_text(json.dumps({"sequence":sequence}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        with (Path.cwd() / "provider-error.txt").open("w") as log:
            traceback.print_exc(file=log)
        raise
