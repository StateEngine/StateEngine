"""Protects: sibling native shutdown retains exact final conversations/capture and closes every tracked birth, endpoint and lease.
Run with an exact installed CLI image; only the owned provider protocol is doubled.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
from fixture_paths import private_runtime_directory
import traceback

from mail_cli import Fixture


def run(args):
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    helper = args.output / "provider.py"
    # Handle the legitimate no-conversation settings probe separately; use the
    # existing real-process/discovery double unchanged for actual sessions.
    helper.write_text('''import json,runpy,sys
if "--safe-mode" in sys.argv[3:]:
 request=json.loads(sys.stdin.readline())
 assert request["request"]["subtype"]=="get_settings"
 print(json.dumps({"type":"control_response","response":{"request_id":request["request_id"],"subtype":"success","response":{"effective":{},"sources":[],"errors":[]}}}),flush=True)
else:
 runpy.run_path(TEMPLATE,run_name="__main__")
'''.replace("TEMPLATE", repr(str(Path(__file__).with_name("mail_provider.py").resolve()))))
    f = Fixture(args.se, args.output / "case", provider_helper=helper)
    runtime = private_runtime_directory()
    f.env["XDG_RUNTIME_DIR"] = str(runtime)
    for name in ["CODEX_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"]:
        path = args.output / name.lower()
        path.mkdir()
        f.env[name] = str(path)
    for name in list(f.env):
        if name.startswith(("OPENAI", "ANTHROPIC")) or any(s in name for s in ("TOKEN", "SECRET", "API_KEY")):
            del f.env[name]
    result = dict(image_sha256=hashlib.sha256(args.se.read_bytes()).hexdigest(), checks=[], failures=[])
    launches = []
    try:
        f.ok("up")
        pid = f.ok("status")["runtime"]["process"]["pid"]
        birth = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
        f.processes.append((pid, birth))
        agents = [f.agent]
        for index in range(1, 8):
            agents.append(f.ok("--project", f.project, "agent", "add", f"Partner {index}",
                               "--provider", "claude", "--model", "claude-sonnet-5-5")["agent"]["id"])
        for index, agent in enumerate(agents):
            f.agent = agent
            f.launch()
            show = f.ok("--project", f.project, "agent", "show", agent)
            ready = json.loads((f.repo / "provider-ready.json").read_text())
            conversation = ready["conversation"]
            matches = list((f.root / "owner/.claude/projects").rglob(conversation + ".jsonl"))
            assert len(matches) == 1, matches
            text = f"final sibling reply {index}: λ"
            with matches[0].open("a") as transcript:
                transcript.write(json.dumps({"type":"assistant", "sessionId":conversation,
                    "uuid":f"last-reply-{index}", "message":{"role":"assistant","content":text}}) + "\n")
                transcript.flush()
                os.fsync(transcript.fileno())
            launches.append(dict(agent=agent, conversation=conversation, session=f.session, text=text))
        bindings = list((f.home / "transcripts").glob("*.json"))
        assert len(bindings) == 8, bindings
        result["launches"] = launches
        result["checks"].append("eight real native sessions, both discovery transports and final transcript tails")
        down = f.call("down")
        result["down"] = json.loads(down.stdout)
        result["down_exit"] = down.returncode
        assert down.returncode == 0 and result["down"]["complete"], result["down"]
        assert len(result["down"]["stops"]) == 8 and all(s["complete"] for s in result["down"]["stops"]), result["down"]
        assert not list((f.home / "transcripts").glob("*.json")), "terminal metadata remains after claimed complete shutdown"
        result["checks"].append("one down completes all siblings and retires their metadata without custody EAGAIN")
        for launched in launches:
            history = f.ok("--project", f.project, "history", "--agent", launched["agent"], "--limit", "100")
            assert history["window"]["complete"], history
            turns = [item for item in history["items"] if item["kind"] == "session.turn"
                     and item["payload"]["role"] == "assistant"]
            exact = [item for item in turns if item["payload"]["body"]["text"] == launched["text"]]
            assert len(exact) == 1, history
            assert launched["conversation"] in json.dumps(history), history
        result["checks"].append("outside CLI history preserves each final reply exactly once and the original conversation")
    except Exception:
        result["failures"].append(traceback.format_exc())
    finally:
        try:
            if result["failures"]:
                # A failed assertion never abandons the fixture's real scopes.
                f.ok("--project", f.project, "stop", "--all")
            f.close()
            with (f.home / "runtime.lock").open("rb") as lease:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result.update(endpoint_absent=True, lease_free=True, births=f.processes)
            result["checks"].append("all tracked native births nonexecuting, endpoint absent and native lease free")
            shutil.rmtree(runtime)
        except Exception:
            result["failures"].append("cleanup: " + traceback.format_exc())
        (args.output / "result.json").write_text(json.dumps(result, indent=2))
    for check in result["checks"]:
        print("ok - " + check, flush=True)
    assert not result["failures"], result["failures"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    run(parser.parse_args())
