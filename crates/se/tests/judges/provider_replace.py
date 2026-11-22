"""Independent judge: an in-place update of a running provider keeps custody.

While an agent runs, its provider executable is updated the two common ways:
replaced at its path, and renamed aside with a new file put in its place. The
agent must stay running with its own process reported at the path it now has,
and `se down` must complete and stop the provider; nothing is orphaned.
Run: python3 provider_replace.py --se SE --output NEW_DIRECTORY
"""
import argparse
import os
from pathlib import Path
import shutil
import sys

from mail_cli import Fixture


def session(fixture):
    status = fixture.ok("--project", fixture.project, "status")
    rows = [row for row in status["agents"]["items"] if row["id"] == fixture.agent]
    assert len(rows) == 1, status
    return rows[0]["session"]


def assert_live(fixture, exe_suffix, what):
    state = session(fixture)
    assert state["state"] == "running", f"after {what} the agent is not running: {state}"
    assert state["liveness"].get("state") == "present", f"after {what} liveness is {state['liveness']}"
    exe = (state.get("process") or {}).get("exe", "")
    assert exe.endswith(exe_suffix), f"after {what} the process is reported at {exe!r}"


def run(fixture):
    executable = fixture.root / "provider"
    fixture.launch()
    assert_live(fixture, "provider", "launch")
    print("ok 1 - the agent is running", flush=True)

    aside = fixture.root / "provider.old"
    # Rename the running executable aside and put a fresh copy in its place.
    os.rename(executable, aside)
    shutil.copy2(aside, executable)
    assert_live(fixture, "provider.old", "renaming the running executable aside")
    print("ok 2 - renamed aside: still running, reported at the new name", flush=True)

    update = fixture.root / "provider-update"
    # Replace the running image's file at its path, as an atomic update does.
    shutil.copy2(aside, update)
    os.replace(update, aside)
    assert_live(fixture, "provider.old (deleted)", "replacing the running executable at its path")
    print("ok 3 - replaced in place: still running, reported as the deleted image", flush=True)

    down = fixture.ok("down")
    assert down["complete"], f"se down left work behind: {down}"
    for pid, birth in fixture.processes:
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
            assert fields[19] != birth or fields[0] == "Z", f"provider process {pid} survived se down"
        except FileNotFoundError:
            pass
    fixture.processes.clear()
    print("ok 4 - se down completed and stopped the provider", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        print("1..0 # SKIP the reported image path is a Linux /proc fact")
        return
    fixture = Fixture(args.se, args.output)
    print("1..4", flush=True)
    try:
        run(fixture)
    finally:
        fixture.ok("down")


if __name__ == "__main__":
    main()
