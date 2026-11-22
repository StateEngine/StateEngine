"""Account-free Claude protocol double that completes a turn for every input.

It finishes the launch task, then answers each frame the host writes to stdin
with an assistant reply and a turn result, so the host sees the agent idle
again. Every frame is appended to captured-input.jsonl with its monotonic
arrival time; the frames are the wakes the host delivered.
"""
import json
import os
from pathlib import Path
import sys
import time

import mail_provider


def transcript(conversation):
    candidates = list((Path(os.environ["HOME"]) / ".claude/projects").rglob(conversation + ".jsonl"))
    if len(candidates) != 1:
        raise RuntimeError("expected one native transcript")
    return candidates[0]


def complete(conversation, path, turn, prompt):
    reply = {"role": "assistant", "content": [{"type": "text", "text": "Done"}]}
    with path.open("a") as native:
        if prompt is not None:
            native.write(json.dumps({"type": "user", "sessionId": conversation, "uuid": f"burst-user-{turn}",
                                     "message": {"role": "user", "content": prompt}}) + "\n")
        native.write(json.dumps({"type": "assistant", "sessionId": conversation, "uuid": f"burst-turn-{turn}",
                                 "message": reply}) + "\n")
    print(json.dumps({"type": "assistant", "session_id": conversation, "message": reply}), flush=True)
    print(json.dumps({"type": "result", "session_id": conversation, "result": "Done", "is_error": False}),
          flush=True)


def text_of(frame):
    content = (frame.get("message") or {}).get("content")
    if isinstance(content, str):
        return content
    return "".join(part.get("text", "") for part in content or [] if isinstance(part, dict))


def answer_every_frame():
    repo = Path.cwd()
    conversation = json.loads((repo / "provider-ready.json").read_text())["conversation"]
    native = transcript(conversation)
    complete(conversation, native, 0, None)
    (repo / "launch-turn-complete").write_text("complete")
    captured = repo / "captured-input.jsonl"
    turn = 0
    for line in sys.stdin:
        if not line.strip():
            continue
        turn += 1
        frame = json.loads(line)
        prompt = text_of(frame)
        with captured.open("a") as record:
            record.write(json.dumps({"turn": turn, "monotonic": time.monotonic(), "text": prompt}) + "\n")
        complete(conversation, native, turn, prompt)
    raise RuntimeError("stdin closed before public shutdown")


if __name__ == "__main__":
    mail_provider.main(answer_every_frame)
