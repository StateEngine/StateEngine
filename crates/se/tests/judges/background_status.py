"""Independent judge for an agent's background processes in status (#522).

The provider is a script, as an npm-installed Claude Code is, so StateEngine
runs it under its shell supervisor with the provider as that shell's child. An
idle agent with nothing left running counts no background processes and reads
idle; a process it leaves running is counted with state "background"; the count
drops back to zero once that process ends; and its arguments never appear.
Run: python3 background_status.py --se SE --output NEW_DIRECTORY
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time

from background_provider import SECRET
from mail_cli import Fixture


def row(fixture):
    status = fixture.ok("--project", fixture.project, "status")
    rows = [item for item in status["agents"]["items"] if item["id"] == fixture.agent]
    assert len(rows) == 1, status
    return rows[0], json.dumps(status)


def script_provider(fixture):
    """Replace the fixture's native launcher with an executable script, so the
    launch takes the script-provider path real npm installs take."""
    judges = Path(__file__).resolve().parent
    helper = judges / "background_provider.py"
    script = f"""#!{sys.executable}
import json, runpy, sys
a = sys.argv
if "--safe-mode" in a:
    sys.stdin.readline()
    print(json.dumps({{"type": "control_response", "response": {{"subtype": "success", "request_id": "settings",
          "response": {{"effective": {{}}, "sources": [], "errors": []}}}}}}))
    sys.exit(0)
if len(a) > 1 and a[1] == "--version":
    print("2.1.287 (Claude Code)")
    sys.exit(0)
if len(a) > 1 and a[1] == "auth":
    print(json.dumps({{"loggedIn": True}}))
    sys.exit(0)
sys.path.insert(0, {str(judges)!r})
sys.argv = [{str(helper)!r}, {str(fixture.se)!r}, {str(fixture.home)!r}, *a[1:]]
runpy.run_path(sys.argv[0], run_name="__main__")
"""
    executable = fixture.root / "provider"
    executable.write_text(script)
    os.chmod(executable, 0o755)


def processes(agent):
    """The counted background processes, or None while the read is unreadable.
    While the runtime holds the session, for example delivering a turn's mail,
    status omits the background read, so an unreadable moment means not yet."""
    background = agent.get("background") or {}
    if background.get("state") != "present":
        return None
    return background["value"]["processes"]


def snapshot(fixture, accept, seconds, what):
    """The first status read whose background count satisfies `accept`; every
    assertion after it runs against that same read."""
    end = time.monotonic() + seconds
    while True:
        agent, text = row(fixture)
        if accept(processes(agent)):
            return agent, text
        if time.monotonic() >= end:
            raise AssertionError(f"deadline waiting for {what}; last read {agent.get('background')}")
        time.sleep(0.2)


def until(predicate, seconds, what):
    end = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= end:
            raise AssertionError(f"deadline waiting for {what}")
        time.sleep(0.2)


def turn(fixture, control, body):
    (fixture.repo / control).write_text("go")
    fixture.mail("send", fixture.agent, body)
    until(lambda: not (fixture.repo / control).exists(), 30, f"the provider to obey {control}")


def run(fixture):
    script_provider(fixture)
    fixture.launch()
    until(lambda: (fixture.repo / "launch-turn-complete").exists(), 30, "the launch turn")
    # Right after launch the runtime may still hold the session for setup.
    agent, _ = snapshot(fixture, lambda n: n is not None, 30, "the agent's background to be readable")
    before = processes(agent)
    assert before == 0, f"an idle agent with nothing left running counts {before} background processes"
    assert agent["state"]["state"] == "idle", f"an idle agent reads {agent['state']}"
    print("ok 1 - an idle script-launched agent counts no background processes and reads idle", flush=True)

    turn(fixture, "spawn-background", "start a long job")
    agent, text = snapshot(fixture, lambda n: n == 1, 20, "the new background process to be counted")
    assert agent["state"]["state"] == "background", f"state is {agent['state']}"
    assert agent["state"]["since"], "a background state names when its oldest process started"
    oldest = agent["background"]["value"]["oldest"]
    assert oldest and " " not in oldest["command"] and "/" not in oldest["command"], oldest
    assert SECRET not in text, "a background process argument appeared in status"
    print("ok 2 - the job is counted, the agent reads background, and no argument is shown", flush=True)

    turn(fixture, "stop-background", "the job is done")
    snapshot(fixture, lambda n: n == 0, 20, "the background count to drop back to zero")
    print("ok 3 - the count drops back once the job ends", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Fixture(args.se, args.output, provider_helper=Path(__file__).with_name("background_provider.py"))
    print("1..4", flush=True)
    try:
        run(fixture)
    finally:
        fixture.close()
    print("ok 4 - witnessed shutdown and outside provider exit", flush=True)


if __name__ == "__main__":
    main()
