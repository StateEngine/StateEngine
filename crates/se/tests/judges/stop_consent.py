"""Independent native protocol consumer: disabled capture and stale session fencing."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time
from mail_cli import Fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    f = Fixture(args.se, args.output / "fixture", log_directory="calls")
    rows = []
    failure = None
    try:
        config = f.home / "config.toml"
        text, count = re.subn(r"(\[capture\]\s*\nenabled\s*=\s*)true", r"\g<1>false", config.read_text())
        assert count == 1, "REFUSE: capture configuration anchor missing"
        config.write_text(text)
        f.launch()
        old_session = f.session
        # Observe admission closing before the predecessor exits. Keep stop in
        # its own public subprocess so concurrent CLI logs cannot collide.
        root_pid, root_birth = f.processes[0]
        stop_out = args.output / "stop.stdout"
        stop_err = args.output / "stop.stderr"
        with stop_out.open("wb") as stdout, stop_err.open("wb") as stderr:
            stop = subprocess.Popen([str(f.se), "--json", "--home", str(f.home), "--project", f.project, "stop", f.agent], env=f.env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            try:
                until=time.monotonic()+3
                while True:
                    revoked=f.call("--project",f.project,"resume",recipient=True)
                    if revoked.returncode not in (0,2): break
                    assert time.monotonic()<until,"old admission stayed open throughout graceful stop"
                    time.sleep(.05)
                fields=Path(f"/proc/{root_pid}/stat").read_text().rsplit(") ",1)[1].split()
                assert fields[19]==root_birth and fields[0]!="Z" and stop.poll() is None
                denied=f.rpc("stateengine_resume",{})
                assert denied.get("isError"),"old MCP admission survived stop hold"
                rows.append("CLI and MCP revoke while the exact predecessor root still lives")
            finally:
                assert stop.wait(timeout=30)==0,(stop_out.read_text(),stop_err.read_text())
        stopped=json.loads(stop_out.read_text())
        assert stopped["complete"] and stopped["witness"]["state"] == "witnessed"
        history = f.ok("--project", f.project, "history", "--agent", f.agent, "--kind", "session.turn")
        assert history["window"]["complete"] and history["items"] == []
        native = list((f.root / "owner/.claude/projects").glob("*/*.jsonl"))
        assert native and all(p.stat().st_size > 0 for p in native)
        rows.append("actual native transcript exists while owner-disabled engine capture stays empty")
        refused = f.call("--project", f.project, "resume", recipient=True)
        assert refused.returncode not in (0, 2), "stopped session recovered owner authority"
        rows.append("stopped session continuity refuses without owner fallback")
        f.launch()
        assert f.session != old_session
        new_session = f.session
        f.session = old_session
        denied = f.call("--project", f.project, "msg", "send", "owner", "STALE-SESSION-MUST-NOT-SEND", recipient=True)
        assert denied.returncode != 0
        f.session = new_session
        reply = f.rpc("stateengine_resume", {})
        assert not reply.get("isError"), reply
        current = json.loads(reply["content"][0]["text"])
        assert current["principal"]["session_id"] == new_session
        messages = f.mail("list", "--all", "--full")
        assert "STALE-SESSION-MUST-NOT-SEND" not in json.dumps(messages)
        rows.append("new binding works through actual MCP while predecessor cannot write mail")
    except Exception as error:
        failure = repr(error)
    finally:
        try:
            f.close()
        except Exception as error:
            failure = (failure or "") + "; public closure: " + repr(error)
        report = {"cases": rows, "failure": failure,
                  "closure": "public down and outside exact native PID birth checks"}
        (args.output / "results.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report), flush=True)
    return 0 if failure is None and len(rows) == 4 else 1


if __name__ == "__main__":
    raise SystemExit(main())
