"""Controlled native protocol source for the independent live-output judge."""
import json
from pathlib import Path
import sys
import threading
import time

import mail_provider


def ready():
    root = Path.cwd()
    conversation = json.loads((root / "provider-ready.json").read_text())["conversation"]
    matches = list((Path.home() / ".claude/projects").rglob(conversation + ".jsonl"))
    if len(matches) != 1:
        raise ValueError("one pinned native transcript is required")
    transcript = matches[0]

    def inputs():
        with (root / "received-input.jsonl").open("a", buffering=1) as log:
            for line in sys.stdin:
                value = json.loads(line)
                log.write(json.dumps(value) + "\n")
                content = value["message"]["content"]
                with transcript.open("a") as output:
                    output.write(json.dumps({"type": "user", "sessionId": conversation,
                        "uuid": "native-delivered-input", "message": {
                            "role": "user", "content": content}}) + "\n")

    threading.Thread(target=inputs, daemon=True).start()
    end = time.monotonic() + 60

    def wait(name):
        while not (root / name).exists():
            if time.monotonic() > end:
                raise TimeoutError("judge did not release " + name)
            time.sleep(.002)

    def append(marker):
        with transcript.open("a") as output:
            output.write(json.dumps({"type": "assistant", "sessionId": conversation,
                "uuid": marker, "message": {"role": "assistant", "content": marker}}) + "\n")
            output.flush()

    wait("begin-output")
    append("native-live-first")
    # A foreign observation must not publish a pending row from our transcript.
    print(json.dumps({"type": "assistant", "session_id": "foreign-conversation"}), flush=True)
    (root / "foreign-streamed").touch()
    wait("begin-partial")
    frame = json.dumps({"type": "assistant", "session_id": conversation,
                        "message": {"role": "assistant", "content": "UNTRUSTED_STREAM_TEXT"}})
    split = len(frame) // 2
    sys.stdout.write(frame[:split])
    sys.stdout.flush()
    (root / "partial-streamed").touch()
    wait("finish-partial")
    print(frame[split:], flush=True)
    wait("second-output")
    append("native-live-second")
    print(frame, flush=True)
    wait("finish-turn")
    print(json.dumps({"type": "result", "session_id": conversation, "is_error": False}), flush=True)
    (root / "result-streamed").touch()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    mail_provider.main(ready)
