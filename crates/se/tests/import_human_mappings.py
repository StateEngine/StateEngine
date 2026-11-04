"""Author consumer checks for explicit human correspondence; no provider account."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import traceback
import uuid
sys.path.insert(0, str(Path(__file__).parent / "judges"))
import history_import as fixture

HUMAN = "hum-abcd-1234-5678"
SECOND = "hum-dcba-4321-8765"
UNKNOWN = "hum-zzzz-zzzz-zzzz"


def source(f):
    fixture.agent_history(f)
    with (f.state / "humans.jsonl").open("a") as stream:
        for human, name in [(HUMAN, "Former Collaborator"), (SECOND, "Second Historical Person")]:
            stream.write(json.dumps(dict(schema_version=1, record_type="human-minted", human_id=human,
                display_name=name, created_at=fixture.TS)) + "\n")
    message = f.message(8, "MAPPED-HUMAN-MAIL")
    message.update(from_seat=HUMAN, to_seat=fixture.AGENT)
    fixture.write_row(f.messages, message)
    return ["import", "--from-node", str(f.source), "--source-owner", f.owner]


def witnesses(f, actor):
    events = f.history()
    messages = [row for row in events if row["kind"] == "message.sent"]
    assert len(messages) == 1 and messages[0]["actor"]["id"] == actor, messages
    rendered = json.dumps(events)
    assert "Former Collaborator" in rendered and HUMAN in rendered, "source name or exact source identity lost"
    assert "Second Historical Person" in rendered and SECOND in rendered
    with closing(sqlite3.connect(f"file:{f.home / 'state.db'}?mode=ro", uri=True)) as db:
        assert db.execute("select count(*) from owners").fetchone() == (1,), "import created a home owner"
        assert db.execute("select count(*) from credentials").fetchone() == (0,)
        assert db.execute("select count(*) from processes").fetchone() == (0,)


def preserve_names(f):
    args = source(f)
    before = f.snapshot_sources()
    assert f.ok(*args)["complete"]
    witnesses(f, HUMAN)
    assert f.snapshot_sources() == before


def explicit_correspondence_and_replay(f):
    args = source(f)
    before = f.snapshot_sources()
    maps = ["--map-human", f"{HUMAN}={f.owner}", "--map-human", f"{SECOND}={f.owner}"]
    key = str(uuid.uuid4())
    assert f.ok("--key", key, *args, *maps)["complete"]
    # Mapping order is not a different request or a new source incarnation.
    assert f.ok("--key", key, *args, *maps[2:], *maps[:2])["complete"]
    witnesses(f, f.owner)
    assert f.count("MAPPED-HUMAN-MAIL") == 1
    assert f.snapshot_sources() == before
    changed = f.call(*args)
    assert changed.returncode != 0, "an existing correspondence was silently rewritten"
    assert HUMAN in changed.stdout.decode() and f.owner in changed.stdout.decode(), "earlier correspondence was not named"
    changed = f.call("--key", str(uuid.uuid4()), *args)
    assert changed.returncode != 0 and HUMAN in changed.stdout.decode() and f.owner in changed.stdout.decode()
    witnesses(f, f.owner)


def bad_correspondence(f):
    args = source(f)
    for mapping in ["missing-equals", f"{UNKNOWN}={f.owner}", f"{UNKNOWN}={UNKNOWN}"]:
        refused = f.call(*args, "--map-human", mapping)
        assert refused.returncode != 0
    duplicate = f.call(*args, "--map-human", f"{HUMAN}={f.owner}", "--map-human", f"{HUMAN}={f.owner}")
    assert duplicate.returncode != 0, "ambiguous duplicate source correspondence accepted"
    missing_target = f.call(*args, "--map-human", f"{HUMAN}={UNKNOWN}")
    assert missing_target.returncode != 0
    refusal = json.loads(missing_target.stdout)
    assert refusal["schema"] == "se.error/v1" and HUMAN in refusal["message"] and UNKNOWN in refusal["message"]
    with closing(sqlite3.connect(f"file:{f.home / 'state.db'}?mode=ro", uri=True)) as db:
        assert db.execute("select count(*) from owners").fetchone() == (1,)
        assert db.execute("select count(*) from import_runs").fetchone() == (0,), "missing target adopted an import run"


def colliding_names_are_counted(f):
    args = source(f)
    path = f.state / "humans.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    for row in rows:
        if row["human_id"] in [HUMAN, SECOND]:
            row["display_name"] = "Same Historical Name" if row["human_id"] == HUMAN else "same historical name"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    before = f.snapshot_sources()
    first = f.ok(*args)
    assert first["complete"]
    owner = [r for r in first["families"] if r["family"] == "owners"][0]
    assert owner["notes"] == {"historical-human-name-disambiguated": 1}, owner
    events = f.history()
    rendered = json.dumps(events)
    assert "Same Historical Name" in rendered and "same historical name (historical " in rendered
    assert "imported_display_name" in rendered and HUMAN in rendered and SECOND in rendered
    assert f.ok(*args)["complete"]
    second = f.history()
    assert second == events and f.snapshot_sources() == before
    names = {e["payload"]["principal"]["id"]: e["payload"]["name"] for e in events
             if e["kind"] == "principal.registered" and e["payload"]["principal"]["id"] in [HUMAN, SECOND]}
    other = fixture.Fixture(f.se, f.root / "reversed-source")
    try:
        other_args = source(other)
        path = other.state / "humans.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        for row in rows:
            if row["human_id"] in [HUMAN, SECOND]:
                row["display_name"] = "Same Historical Name" if row["human_id"] == HUMAN else "same historical name"
        path.write_text("".join(json.dumps(row) + "\n" for row in reversed(rows)))
        assert other.ok(*other_args)["complete"]
        reversed_names = {e["payload"]["principal"]["id"]: e["payload"]["name"] for e in other.history()
            if e["kind"] == "principal.registered" and e["payload"]["principal"]["id"] in [HUMAN, SECOND]}
        assert reversed_names == names, "source order changed imported names"
    finally:
        other.close()


def missing_display_name_is_unreadable(f):
    args = source(f)
    path = f.state / "humans.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    for row in rows:
        if row["human_id"] == HUMAN:
            del row["display_name"]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    before = f.snapshot_sources()
    result = f.call(*args)
    assert result.returncode != 0
    receipt = json.loads(result.stdout)
    assert not receipt["complete"] and sum(r["unreadable"] for r in f.family(receipt, "owners")) == 1
    assert f.snapshot_sources() == before


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    cases = [preserve_names, explicit_correspondence_and_replay, bad_correspondence, colliding_names_are_counted, missing_display_name_is_unreadable]
    print(f"1..{len(cases)}", flush=True)
    failed = 0
    for number, case in enumerate(cases, 1):
        f = None
        try:
            f = fixture.Fixture(args.se.resolve(), args.output.resolve() / (case.__name__ + "-" + uuid.uuid4().hex[:6]))
            try:
                case(f)
            finally:
                f.close()
            print(f"ok {number} - {case.__name__}", flush=True)
        except Exception:
            failed += 1
            print(f"not ok {number} - {case.__name__}", flush=True)
            traceback.print_exc()
    print(f"# {len(cases)-failed} passed, {failed} failed", flush=True)
    raise SystemExit(bool(failed))

if __name__ == "__main__":
    main()
