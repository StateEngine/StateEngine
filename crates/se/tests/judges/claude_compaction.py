"""Protects: metadata cannot strand a stopped Claude session or become recent chat.
Public CLI judge with a real native protocol double; no provider account or DB edits.
"""
import argparse
import json
from pathlib import Path
import sys
import time
from mail_cli import Fixture


def present(value):
    assert value["state"] == "present", value
    return value["value"]


def transcript(f):
    ready = json.loads((f.repo / "provider-ready.json").read_text())
    paths = list((f.root / "owner/.claude/projects").glob("*/" + ready["conversation"] + ".jsonl"))
    assert len(paths) == 1, paths
    return ready["conversation"], paths[0]


def outside(f):
    for pid, birth in f.processes:
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        except FileNotFoundError:
            continue
        assert fields[19] != birth or fields[0] in ("Z", "X"), ("owned provider still live", pid)


def window(session, expected):
    events = present(session["transcript_events"])
    assert len(events) == 20 and all(e["kind"] == "future-provider-record" for e in events), events
    assert present(session["transcript_events_omitted"]) == 6, session
    compact = present(session["last_compaction"])
    assert compact["kind"] == "system" and compact["subtype"] == "compact_boundary", compact
    assert compact["position"] == expected, (compact, expected)
    assert compact["event_id"] and compact["session_id"], compact
    assert "PRIVATE_PROVIDER_PAYLOAD" not in json.dumps(session), session
    return compact


def one(f, malformed):
    f.launch()
    old = f.session
    conversation, path = transcript(f)
    raw = Path(__file__).parents[3] / "se-host/tests/fixtures/claude-2.1.317-compact-boundary.jsonl"
    # The public CLI fixture owns a new native conversation. The separate host
    # judge consumes the exact unmodified stock line and verifies its digest.
    record = json.loads(raw.read_bytes())
    record["sessionId"] = conversation
    encoded = (json.dumps(record, separators=(",", ":")) + "\n").encode()
    offset = path.stat().st_size
    with path.open("ab") as stream:
        if malformed:
            stream.write((json.dumps({"type":"user","sessionId":conversation,"uuid":"broken-known","message":{"role":"user"}}) + "\n").encode())
        else:
            stream.write(encoded)
            for n in range(25):
                stream.write((json.dumps({"type":"future-provider-record","sessionId":conversation,"uuid":f"future-{n}","content":"PRIVATE_PROVIDER_PAYLOAD"}) + "\n").encode())
        stream.flush()
        import os
        os.fsync(stream.fileno())
    result = f.call("--project", f.project, "stop", f.agent)
    assert result.stdout.strip(), (result.returncode, result.stderr.decode())
    stopped = json.loads(result.stdout)
    (f.root / "stop.json").write_text(json.dumps(stopped, indent=2))
    outside(f)
    if malformed:
        assert not stopped["complete"], "malformed known chat was silently accepted"
    else:
        assert result.returncode == 0 and stopped["complete"], stopped
        shown = f.ok("--project", f.project, "agent", "show", f.agent)
        expected = {"offset": offset, "length": len(encoded)}
        compact = window(present(shown["agent"])["session"], expected)
        status = f.ok("--project", f.project, "status")
        row = next(row for row in status["agents"]["items"] if row["id"] == f.agent)
        assert window(row["session"], expected) == compact
        resumed = f.ok("--project", f.project, "resume", "--preview", f.agent)
        assert window(resumed, expected) == compact
        assert all(turn["role"] in ("user", "assistant") for turn in resumed["recent_turns"]), resumed
        assert all("PRIVATE_PROVIDER_PAYLOAD" not in turn["preview"] for turn in resumed["recent_turns"])
    # Native closure must permit a genuine fresh launch even if old capture
    # remains incomplete. A description of a hypothetical remedy is no pass.
    launched = f.ok("--project", f.project, "launch", f.agent, "--new", "--detach", "--task", "Fresh after capture")
    assert launched["state"] == "running" and launched["session_id"] != old, launched
    ready = json.loads((f.repo / "provider-ready.json").read_text())
    for pid in (ready["native_root_pid"], ready["helper_pid"]):
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        f.processes.append((pid, fields[19]))
    f.session = launched["session_id"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for name, malformed in (("compaction", False), ("malformed-known", True)):
        f = Fixture(args.se, args.output / name)
        error = None
        try:
            one(f, malformed)
        except Exception as caught:
            error = repr(caught)
        cleanup = None
        try:
            f.close()
        except Exception as caught:
            cleanup = repr(caught)
        results.append({"case": name, "failure": error, "cleanup_failure": cleanup})
        print(("ok" if not error and not cleanup else "not ok"), name, error, cleanup, flush=True)
    (args.output / "results.json").write_text(json.dumps(results, indent=2))
    return int(any(r["failure"] or r["cleanup_failure"] for r in results))


if __name__ == "__main__":
    sys.exit(main())
