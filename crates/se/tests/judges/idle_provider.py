"""Account-free provider that completes one turn and remains idle."""
import json
import os
from pathlib import Path
import socket

import mail_provider


def complete_then_park():
    repo = Path.cwd()
    endpoint = json.loads((repo / "idle-control.json").read_text())
    ready = json.loads((repo / "provider-ready.json").read_text())
    connection = socket.create_connection(("127.0.0.1", endpoint["port"]), timeout=30)
    connection.sendall((endpoint["nonce"] + "\n").encode())
    connection.settimeout(30)
    with connection, connection.makefile("rb") as control:
        if control.readline() != b"complete\n":
            raise RuntimeError("unexpected control request")
        candidates = list((Path(os.environ["HOME"]) / ".claude/projects").rglob(
            ready["conversation"] + ".jsonl"
        ))
        if len(candidates) != 1:
            raise RuntimeError("expected one native transcript")
        message = {"role": "assistant", "content": [{"type": "text", "text": "Done"}]}
        record = {"type": "assistant", "sessionId": ready["conversation"],
                  "uuid": "idle-turn", "message": message}
        with candidates[0].open("a") as transcript:
            transcript.write(json.dumps(record) + "\n")
        print(json.dumps({"type": "assistant", "session_id": ready["conversation"], "message": message}), flush=True)
        print(json.dumps({"type": "result", "session_id": ready["conversation"],
                          "result": "Done", "is_error": False}), flush=True)
        connection.sendall(b"completed\n")
        connection.settimeout(None)
        # No provider timer or transcript polling remains during idle.
        if control.readline():
            raise RuntimeError("unexpected second control request")
        raise RuntimeError("control closed before public shutdown")


if __name__ == "__main__":
    mail_provider.main(complete_then_park)
