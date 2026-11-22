"""Independent judge: a forced relaunch refuses before stopping the live agent.

A running Claude agent's CLI starts reporting a version below the supported
floor. `se launch --force` must refuse with the provider's own fix,
and the original agent must still be running with the same session and live
provider process; nothing was stopped.
Run: python3 force_relaunch_qualify.py --se SE --output NEW_DIRECTORY
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from mail_cli import Fixture

SUPPORTED = "2.1.287 (Claude Code)"
TOO_OLD = "2.0.0 (Claude Code)"


def version_switch(fixture):
    """Rebuild the fixture launcher, before any launch, so its --version answer
    turns too old once a flag file exists; the executable itself never changes,
    so the live agent's process identity stays the same."""
    source = (fixture.root / "provider.rs").read_text()
    answer = f'println!("{SUPPORTED}");return;'
    assert answer in source, "the fixture launcher no longer reports the supported version"
    flag = fixture.root / "report-old-version"
    switched = source.replace(answer, "if std::path::Path::new(" + json.dumps(str(flag)) + ").exists()"
                              f'{{println!("{TOO_OLD}")}}else{{println!("{SUPPORTED}")}};return;', 1)
    (fixture.root / "provider.rs").write_text(switched)
    executable = fixture.root / ("provider.exe" if os.name == "nt" else "provider")
    subprocess.run(["rustc", "--edition=2024", str(fixture.root / "provider.rs"), "-o", str(executable)],
                   stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=60)
    return flag


def agent_row(fixture):
    status = fixture.ok("--project", fixture.project, "status")
    rows = [row for row in status["agents"]["items"] if row["id"] == fixture.agent]
    assert len(rows) == 1, status
    return rows[0]


def run(fixture):
    flag = version_switch(fixture)
    fixture.launch()
    before = agent_row(fixture)
    assert before["session"]["state"] == "running", before["session"]
    print("ok 1 - the agent is running", flush=True)

    flag.write_text("old")
    refused = fixture.call("--project", fixture.project, "launch", fixture.agent, "--detach", "--force")
    assert refused.returncode != 0, "the forced relaunch succeeded with a too-old provider CLI"
    error = json.loads(refused.stdout)
    text = json.dumps(error)
    assert "2.1.287" in text, f"the refusal does not name the provider's version fix: {text}"
    print("ok 2 - the forced relaunch refused with the provider's fix", flush=True)

    after = agent_row(fixture)
    assert after["session"]["state"] == "running", f"the original agent was stopped: {after['session']}"
    assert after["session"]["session_id"] == before["session"]["session_id"] == fixture.session, \
        "the running session was replaced"
    if sys.platform == "linux":
        for pid, birth in fixture.processes:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
            assert fields[19] == birth and fields[0] != "Z", f"original provider process {pid} was stopped"
    print("ok 3 - the original agent and its provider process are still running", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Fixture(args.se, args.output)
    print("1..4", flush=True)
    try:
        run(fixture)
    finally:
        fixture.close()
    print("ok 4 - witnessed shutdown and outside provider exit", flush=True)


if __name__ == "__main__":
    main()
