"""Protects: a 4 KiB resume returns useful, honest partial context over real MCP.
Only the native provider protocol is doubled; store, authentication and both
transports are real. Run --se EXACT_IMAGE --output NEW_OWNED_DIRECTORY.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
from fixture_paths import private_runtime_directory
import traceback
import urllib.request

from judge_records import wait_json
from mail_cli import Fixture


def commands(value):
    if isinstance(value, dict):
        argv = value.get("argv")
        if isinstance(argv, list) and argv and argv[0] == "se":
            yield argv
        for child in value.values():
            yield from commands(child)
    elif isinstance(value, list):
        for child in value:
            yield from commands(child)


def run(args):
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    helper = args.output / "provider.py"
    helper.write_text('''import json,runpy,sys
if "--safe-mode" in sys.argv[3:]:
 request=json.loads(sys.stdin.readline())
 assert request["request"]["subtype"]=="get_settings"
 print(json.dumps({"type":"control_response","response":{"request_id":request["request_id"],"subtype":"success","response":{"effective":{},"sources":[],"errors":[]}}}),flush=True)
else:
 runpy.run_path(TEMPLATE,run_name="__main__")
'''.replace("TEMPLATE", repr(str(Path(__file__).with_name("mail_provider.py").resolve()))))
    result = {"image_sha256": hashlib.sha256(args.se.read_bytes()).hexdigest(),
              "judge_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "checks": [], "failures": [], "responses": []}
    f = None
    rpc = None
    runtime = private_runtime_directory()
    result["runtime_directory"] = str(runtime)
    try:
        f = Fixture(args.se, args.output / 'owner home "quoted"', provider_helper=helper)
        f.env["XDG_RUNTIME_DIR"] = str(runtime)
        for name in ["CODEX_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"]:
            path = args.output / name.lower()
            path.mkdir()
            f.env[name] = str(path)
        for name in list(f.env):
            if name.startswith(("OPENAI", "ANTHROPIC")) or any(s in name for s in ("TOKEN", "SECRET", "API_KEY")):
                del f.env[name]
        f.ok("up")
        pid = f.ok("status")["runtime"]["process"]["pid"]
        f.processes.append((pid, Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]))
        f.launch()
        ready = wait_json(f.repo / "provider-ready.json")
        conversation = ready["conversation"]
        transcripts = list((f.root / "owner/.claude/projects").rglob(conversation + ".jsonl"))
        assert len(transcripts) == 1, transcripts
        tails = {f'Captured turn {n}: λ "quoted" \\ path\n' * 20 for n in range(8)}
        with transcripts[0].open("a") as stream:
            for n, tail in enumerate(sorted(tails)):
                stream.write(json.dumps({"type": "assistant", "sessionId": conversation,
                    "uuid": f"resume-wire-tail-{n}", "message": {"role": "assistant", "content": tail}}) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        stopped = f.ok("--project", f.project, "stop", f.agent)
        assert stopped["complete"], stopped
        history = f.ok("--project", f.project, "history", "--agent", f.agent,
                       "--kind", "session.turn", "--limit", "100")
        captured = {row["payload"]["body"]["text"] for row in history["items"]}
        assert tails <= captured, "native final capture did not retain the seeded conversation"
        # A fresh active session must see the earlier saved conversation too.
        launched = f.ok("--project", f.project, "launch", f.agent, "--new", "--detach",
                        "--task", "Resume with retained conversation context")
        f.session = launched["session_id"]
        ready = wait_json(f.repo / "provider-ready.json")
        for pid in (ready["native_root_pid"], ready["helper_pid"]):
            f.processes.append((pid, Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]))
        note = 'Resume the native wire task: λ "quoted" \\ path\n' * 60
        sent = {f.mail("send", f.agent, f'Unread {n}: λ "quoted" \\ path\n' * 20)["message_id"]
                for n in range(24)}

        def unread():
            page = f.mail("list", "--limit", "100", recipient=True)
            assert page["window"]["complete"], page
            return {row["id"] for row in page["items"]}

        assert unread() == sent
        argv = (f.repo / "provider-argv.txt").read_text().splitlines()
        server = json.loads(Path(argv[argv.index("--mcp-config") + 1]).read_text())["mcpServers"]["stateengine"]
        with (args.output / "mcp.stderr").open("wb") as stderr:
            rpc = subprocess.Popen([str(f.se), "--home", str(f.home), "mcp"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
                env={**f.env, "SE_SESSION": f.session})

            def exchange(door, identifier, arguments):
                frame = {"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                         "params": {"name": "stateengine_resume", "arguments": arguments}}
                encoded = json.dumps(frame).encode()
                if door == "stdio":
                    rpc.stdin.write(encoded + b"\n")
                    rpc.stdin.flush()
                    assert select.select([rpc.stdout], [], [], 45)[0], "MCP resume timed out"
                    wire = rpc.stdout.readline()
                    used = len(wire)
                else:
                    request = urllib.request.Request(server["url"], data=encoded,
                        headers={**server["headers"], "Content-Type": "application/json"})
                    with urllib.request.urlopen(request, timeout=45) as response:
                        wire = response.read()
                    # HTTP reserves the same line-ending byte as stdio.
                    used = len(wire) + 1
                (args.output / f"wire-{len(result['responses']):02d}-{door}.json").write_bytes(wire)
                response = json.loads(wire)
                result["responses"].append({"door": door, "bytes": used,
                                            "budget": arguments.get("byte_budget", 4096)})
                return response, used

            for phase in ("absent-notes", "saved-notes"):
                if phase == "saved-notes":
                    f.ok("--project", f.project, "working-state", "set", "--agent", f.agent,
                         "--expect", "absent", note)
                recovered = False
                for door in ("stdio", "http"):
                    for explicit in (False, True):
                        identifier = f'{door}-λ-"\\-frame'
                        response, used = exchange(door, identifier,
                                                 {"byte_budget": 4096} if explicit else {})
                        assert used <= 4096, ("complete wire exceeds 4 KiB", used)
                        assert response["id"] == identifier, response
                        assert "error" not in response and not response["result"].get("isError"), response
                        content = response["result"]["content"]
                        assert len(content) == 1 and content[0]["type"] == "text", response
                        body = json.loads(content[0]["text"])
                        assert body["budget"] == {"limit_bytes": 4096, "used_bytes": used}, body
                        assert body["principal"]["agent"]["id"] == f.agent, body
                        assert body["principal"]["project"]["id"] == f.project, body
                        assert body["principal"]["session_id"] == f.session, body
                        assert body["complete"] is False and body["resume_status"] == "needs_read", body
                        assert body["omissions"], "clipped resume hid its missing context"
                        working = body.get("working_state", {}).get("value", {}).get("text", "")
                        assert working or body["unread"]["items"] or body["recent_turns"], "empty success is not usable context"
                        next_reads = list(commands(body["omissions"]))
                        assert next_reads, "partial context has no executable read-next step"
                        assert unread() == sent, "resume or its fitting attempts acknowledged unread mail"
                        if not recovered:
                            next_argv = next_reads[0]
                            assert str(f.home) in next_argv and f.project in next_argv, next_argv
                            completed = subprocess.run([str(f.se), *next_argv[1:], "--json"],
                                env={**f.env, "SE_SESSION": f.session},
                                capture_output=True, timeout=45)
                            (args.output / "read-next.stdout").write_bytes(completed.stdout)
                            (args.output / "read-next.stderr").write_bytes(completed.stderr)
                            assert completed.returncode in (0, 2) and completed.stdout.strip(), completed.stderr
                            follow = json.loads(completed.stdout)
                            assert follow.get("schema") != "se.error/v1", follow
                            assert unread() == sent, "read-only recovery acknowledged unread mail"
                            recovered = True
                    result["checks"].append(f"{phase}/{door}: default and explicit 4 KiB fit complete wire with useful partial context and unchanged unread mail")
                result["checks"].append("advertised exact-home/project read-next argv executes and preserves unread state")
            response, used = exchange("stdio", "x" * 5000, {"byte_budget": 4096})
            assert used <= 4096 and response.get("error") and response["id"] is None, response
            result["checks"].append("an irreducible oversized request ID still refuses within the original wire budget")
            rpc.stdin.close()
            assert rpc.wait(timeout=10) == 0
            rpc = None
    except Exception:
        result["failures"].append(traceback.format_exc())
    finally:
        if rpc is not None:
            try:
                rpc.stdin.close()
                rpc.wait(timeout=10)
            except Exception:
                result["failures"].append("MCP child cleanup: " + traceback.format_exc())
        if f is not None:
            try:
                f.close()
                with (f.home / "runtime.lock").open("rb") as lease:
                    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result.update(endpoint_absent=True, lease_free=True, births=f.processes)
                result["checks"].append("native provider births closed, endpoint absent and lease free")
                shutil.rmtree(runtime)
            except Exception:
                result["failures"].append("native fixture cleanup: " + traceback.format_exc())
        else:
            runtime.rmdir()
        (args.output / "result.json").write_text(json.dumps(result, indent=2))
    for check in result["checks"]:
        print("ok - " + check, flush=True)
    assert not result["failures"], result["failures"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    run(parser.parse_args())
