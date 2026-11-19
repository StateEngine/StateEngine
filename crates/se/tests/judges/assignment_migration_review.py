"""Use the public CLI on a fresh store and, with an older CLI, a real upgrade."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

MESSAGE = "mail retained by the assignment migration"
ASSIGNMENT = "verify the assignment floor record"


def use_cli(image, output, previous=None):
    output.mkdir(parents=True, exist_ok=False)
    report = {"os": os.name, "run_id": os.getenv("GITHUB_RUN_ID"), "cases": {}}
    env = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith(("SE_", "STATEENGINE_", "CLAUDE", "CODEX_", "OPENAI_", "ANTHROPIC_"))
    }

    with tempfile.TemporaryDirectory(prefix="assignment-review-") as scratch:
        root = Path(scratch)
        repo, store = root / "repo", root / "store"
        repo.mkdir()
        if os.name == "posix":
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)
            env["XDG_RUNTIME_DIR"] = str(runtime)

        def command(binary, *args):
            return [str(binary), "--json", "--home", str(store), *args]

        def cli(binary, *args):
            result = subprocess.run(command(binary, *args), cwd=repo, env=env,
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
            assert result.returncode == 0, (args, result.stdout, result.stderr)
            return json.loads(result.stdout)

        @contextmanager
        def host(binary, label):
            stdout_path = output / f"{label}-host.out"
            stderr_path = output / f"{label}-host.err"
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(command(binary, "up", "--foreground"), cwd=repo,
                                           env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            ready = False
            try:
                end = time.monotonic() + 35
                while time.monotonic() < end and process.poll() is None:
                    lines = stdout_path.read_bytes().splitlines()
                    if lines and lines[0].endswith(b"}"):
                        assert json.loads(lines[0])["process"]["pid"] == process.pid
                        ready = True
                        break
                    time.sleep(.05)
                assert ready, stderr_path.read_text(errors="replace")
                yield
            finally:
                try:
                    if ready:
                        stopped = cli(binary, "down")
                        assert stopped["complete"] and stopped["witness"]["state"] == "witnessed", stopped
                        assert process.wait(timeout=25) == 0
                        assert not (store / "endpoint.json").exists()
                        report["cases"][f"{label}_shutdown"] = True
                finally:
                    if process.poll() is None:
                        assert process.args == command(binary, "up", "--foreground")
                        process.terminate()
                        process.wait(timeout=10)

        def snapshot():
            uri = (store / "state.db").resolve(strict=True).as_uri() + "?mode=ro"
            with sqlite3.connect(uri, uri=True) as db:
                version = db.execute("PRAGMA user_version").fetchone()[0]
                objects = {name for name, in db.execute("SELECT name FROM sqlite_schema")}
                messages = db.execute("SELECT hex(message_id),recorded_at_us FROM messages ORDER BY sent_seq").fetchall()
                assert db.execute("PRAGMA foreign_key_check").fetchall() == []
                return version, objects, messages

        try:
            initial = previous or image
            identity = cli(initial, "init", "--repo", str(repo), "--name", "Assignment migration review")
            project, agent = identity["project"]["id"], identity["agent"]["id"]
            prefix = ("--project", project)
            if previous:
                with host(previous, "schema15"):
                    sent = cli(previous, *prefix, "msg", "send", agent, MESSAGE)
                    before, objects, previous_messages = snapshot()
                    assert before == 15 and "assignments" not in objects and "messages_pair_time" in objects
                    assert len(previous_messages) == 1 and previous_messages[0][1] > 0
                    report["cases"]["starting_schema"] = before

            with host(image, "schema16"):
                after, objects, messages = snapshot()
                assert after == 16 and {"assignments", "assignment_floor_events", "messages_pair_time"} <= objects
                report["cases"]["result_schema"] = after
                if previous:
                    assert messages == previous_messages
                    preserved = cli(image, *prefix, "msg", "read", sent["message_id"])
                    assert preserved["inspection"] and preserved["message"]["body"]["text"] == MESSAGE, preserved
                    report["cases"]["existing_mail_read_with_original_stamp"] = True
                cli(image, *prefix, "captain", "set", "me")
                opened = cli(image, *prefix, "assignment", "write", "--action", "open",
                             "--assignee", agent, "--body", ASSIGNMENT)
                assignment = opened["assignment"]
                assert opened["state"] == "open" and opened["commit"]["event_id"] == assignment, opened
                assignments = cli(image, *prefix, "assignment", "list")["items"]
                assert [(item["id"], item["state"]) for item in assignments] == [(assignment, "open")], assignments
                event = cli(image, *prefix, "history", "--event", assignment)
                assert event["event_id"] == assignment and event["kind"] == "message.work_sent", event
                assert event["payload"]["body"]["text"] == ASSIGNMENT and event["payload"]["body"]["complete"], event
                report["cases"]["assignment_and_history"] = True
                assert snapshot()[0] == 16
        finally:
            (output / "review.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    use_cli(Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2]).resolve(),
            Path(sys.argv[3]).resolve(strict=True) if len(sys.argv) > 3 else None)
