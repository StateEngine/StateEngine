"""Real Codex takeover consumer using the existing owned loopback model.
No subscription, installation, external model request or other seat is used.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from codex_first_launch import Model
from mail_cli import Fixture
from takeover_cli import live


class TakeoverModel(Model):
    def respond(self, handler, request):
        # Stock builds advertise either the code tool or direct exec_command.
        # Follow the actual inventory instead of emitting an unsupported call.
        direct = any(t.get("name") == "exec_command" and t.get("type") == "function"
                     for t in request.get("tools", []))
        if not direct:
            return super().respond(handler, request)
        self.requests.append(request)
        (self.root / "model-requests.json").write_text(json.dumps(self.requests, indent=2))
        if not self.sent:
            self.sent = True
            command = "printf '5\\n' > sum.txt; printf SUM_READBACK:; cat sum.txt"
            item = {"id": "fc_" + uuid.uuid4().hex, "type": "function_call",
                    "call_id": "call_" + uuid.uuid4().hex, "name": "exec_command",
                    "arguments": json.dumps({"cmd": command, "workdir": str(self.repo), "max_output_tokens": 1000}),
                    "status": "completed"}
        else:
            self.readback = self.readback or any(x.get("type") == "function_call_output" and "SUM_READBACK:5" in str(x.get("output"))
                                                 for x in request.get("input", []) if isinstance(x, dict))
            item = {"id": "msg_" + uuid.uuid4().hex, "type": "message", "role": "assistant",
                    "status": "completed", "phase": "final_answer",
                    "content": [{"type": "output_text", "text": "SUM_DONE", "annotations": [], "logprobs": []}]}
        response = {"id": "resp_" + uuid.uuid4().hex, "object": "response", "created_at": int(time.time()),
                    "model": request.get("model", "offline"), "status": "in_progress", "output": []}
        events = [{"type": "response.created", "response": response},
                  {"type": "response.output_item.added", "output_index": 0, "item": {**item, "status": "in_progress"}},
                  {"type": "response.output_item.done", "output_index": 0, "item": item},
                  {"type": "response.completed", "response": {**response, "status": "completed", "output": [item],
                   "usage": {"input_tokens": 64, "output_tokens": 20, "total_tokens": 84, "output_tokens_details": {"reasoning_tokens": 0}}}}]
        body = ''.join('event: ' + e['type'] + '\ndata: ' + json.dumps({**e, "sequence_number": i}) + '\n\n'
                       for i, e in enumerate(events)).encode()
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--codex", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    f = Fixture(args.se, args.output / "fixture", log_directory="calls")
    model = TakeoverModel(args.output, f.repo)
    short = Path(tempfile.mkdtemp(prefix="se-takeover-codex-", dir="/tmp"))
    code_home = args.output / "owned-codex-home"
    code_home.mkdir(mode=0o700)
    f.env.update(CODEX_HOME=str(code_home), OPENAI_API_KEY="sk-owned-loopback-no-account",
                 XDG_RUNTIME_DIR=str(short), TMPDIR="/tmp")
    (code_home / "config.toml").write_text('model_provider = "offline-fixture"\n[model_providers.offline-fixture]\nname = "Owned loopback"\nbase_url = ' +
        json.dumps(f'http://127.0.0.1:{model.server.server_port}/v1') +
        '\nwire_api = "responses"\nrequires_openai_auth = false\n')
    login = subprocess.run([str(args.codex), "login", "--with-api-key"],
                           input=f.env["OPENAI_API_KEY"], text=True, env=f.env,
                           capture_output=True, timeout=20)
    assert login.returncode == 0, login.stderr
    config = f.home / "config.toml"
    config.write_text(config.read_text().replace("[providers.codex]", "[providers.codex]\ncommand = " + json.dumps(str(args.codex.resolve())), 1))
    f.agent = f.ok("--project", f.project, "agent", "add", "Takeover Codex", "--provider", "codex", "--model", "gpt-6.1-sol")["agent"]["id"]
    rows, failure = [], None
    try:
        first = f.ok("--project", f.project, "launch", f.agent, "--detach", "--task",
                     "Write sum.txt containing 5 followed by a newline, read it back and reply SUM_DONE.")
        root_pid = first["process"]["pid"]
        birth = Path(f"/proc/{root_pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
        root = {"pid": root_pid, "birth": birth}
        f.processes.append((root_pid, birth))
        until = time.monotonic() + 60
        while not ((f.repo / "sum.txt").exists() and model.readback):
            assert time.monotonic() < until, "real Codex work/readback incomplete"
            time.sleep(.1)
        assert (f.repo / "sum.txt").read_text() == "5\n"
        rows.append("real Codex launches and executes a tool through the owned model")

        refused = f.call("--project", f.project, "launch", f.agent, "--detach")
        assert refused.returncode != 0 and b"--force" in refused.stderr and live(root)
        rows.append("default real Codex relaunch refuses before stopping the exact native root")
        second = f.ok("--project", f.project, "--key", "codex-takeover", "launch", f.agent, "--detach", "--override-live")
        assert second["conversation_id"] == first["conversation_id"]
        assert second["takeover"]["previous_session"] == first["session_id"]
        assert "witnessed" in second["takeover"]["witness"] and not live(root)
        pid = second["process"]["pid"]
        born = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
        f.processes.append((pid, born))
        rows.append("real Codex takeover witnesses predecessor exit and resumes its original provider conversation")
        replay = f.ok("--project", f.project, "--key", "codex-takeover", "launch", f.agent, "--detach", "--override-live")
        assert replay["session_id"] == second["session_id"] and live({"pid": pid, "birth": born})
        rows.append("Codex takeover replay preserves the exact successor")
    except Exception as error:
        failure = repr(error)
    finally:
        try:
            f.close()
            model.close()
            child_directory = short / "stateengine"
            if child_directory.exists():
                child_directory.rmdir()
            short.rmdir()
        except Exception as error:
            failure = (failure or "") + "; public closure: " + repr(error)
    report = {"cases": rows, "failure": failure, "count": len(rows)}
    (args.output / "results.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report), flush=True)
    return 0 if failure is None and len(rows) == 4 else 1


if __name__ == "__main__":
    raise SystemExit(main())
