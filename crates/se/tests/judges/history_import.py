"""Independent S15 consumer checks. Run with --se RELEASE_SE --output OWNED_LOG_DIR.

Only synthetic retained Node files are used. Every case gets its own owner home;
the source copy and all CLI replies remain in the output directory on failure.
The launch check uses a native Claude protocol double, not a provider account.
"""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import sys
import time
import traceback
import uuid

TS = "2026-10-15T12:00:00.000Z"
PROJECT = "import-judge"
AGENT = "agt-abcd-1234-5678"
NATIVE_SESSION = "5d8c5629-a272-493c-af79-c624ec0191e7"


def write_row(path, value, newline=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + ("\n" if newline else ""))


class Fixture:
    def __init__(self, se, root):
        self.se, self.root = se, root
        root.mkdir(parents=True, exist_ok=False)
        self.home, self.source = root / "state", root / "source"
        for leaf in ["owner", "repo", "historical-repo"]:
            (root / leaf).mkdir()
        self.environment = {k: v for k, v in os.environ.items()
                            if not k.startswith(("SE_", "STATEENGINE_", "CODEX_", "CLAUDE"))}
        self.environment.update(HOME=str(root / "owner"), USERPROFILE=str(root / "owner"))
        self.calls = 0
        self.native_processes = []
        init = self.ok("--key", str(uuid.uuid4()), "init", "--repo", str(root / "repo"), "--name", "Import Judge",
                       "--agent", "Seed", "--provider", "claude", "--model", "claude-sonnet-5-5")
        self.owner = init["owner"]["human_id"]
        # Concurrent fixtures must not reuse the OS owner's default listener
        # port between init's probe and the later detached-host startup.
        start = uuid.uuid4().int % 10000
        for offset in range(10000):
            port = 20000 + (start + offset) % 10000
            with socket.socket() as listener:
                try:
                    listener.bind(("127.0.0.1", port))
                    break
                except OSError:
                    continue
        else:
            raise RuntimeError("no free configured listener port in 20000..29999")
        config = self.home / "config.toml"
        config.write_text(config.read_text().replace(
            f'listen_port = {init["profile"]["native_server_port"]}', f"listen_port = {port}", 1))
        self.state = self.source / ".stateengine"
        slug = "-".join(filter(None, re.split("[^a-z0-9]", PROJECT.lower())))[:40]
        self.floor = self.state / (slug + "-" + hashlib.sha256(PROJECT.encode()).hexdigest()[:16])
        self.messages = self.floor / "seats/messages.jsonl"
        self.registration(self.owner)
        write_row(self.state / "humans.jsonl", dict(schema_version=1, record_type="human-minted",
                  human_id=self.owner, display_name="Recorded owner", created_at=TS))

    def registration(self, owner):
        write_row(self.state / "projects.jsonl", dict(schema_version=2,
                  record_type="project-registration", project_id=PROJECT, revision=1,
                  repo_root=str(self.root / "historical-repo"), owner_human_id=owner,
                  ts=TS, name="History"))

    def command(self, *arguments):
        return [str(self.se), "--json", "--home", str(self.home), *arguments]

    def call(self, *arguments):
        self.calls += 1
        result = subprocess.run(self.command(*arguments), env=self.environment,
                                capture_output=True, timeout=90)
        base = self.root / f"call-{self.calls:02}"
        base.with_suffix(".stdout").write_bytes(result.stdout)
        base.with_suffix(".stderr").write_bytes(result.stderr)
        return result

    def ok(self, *arguments):
        result = self.call(*arguments)
        until = time.monotonic() + 40
        while (result.returncode and "init" in arguments
               and b"installation record is busy" in result.stderr
               and time.monotonic() < until):
            # Shared native installation ownership is outside an isolated store.
            # Retain every refusal and retry exactly the same init request key.
            time.sleep(1)
            result = self.call(*arguments)
        assert result.returncode == 0, (arguments, result.stdout.decode(), result.stderr.decode())
        return json.loads(result.stdout)

    def import_history(self):
        return self.ok("import", "--from-node", str(self.source))

    def history(self):
        page = self.ok("--project", PROJECT, "history", "--limit", "100")
        assert page["window"]["complete"] and page["next"] is None, "judge must read every event"
        return page["items"]

    def message(self, number, body):
        return dict(record_type="message", msg_id=f"msg-{number:024x}", ts=TS,
                    from_seat=AGENT, to_seat="floor", kind="note", body=body, refs=[])

    def count(self, text):
        # Owned retained bodies have one public payload; aliases have no body.
        return sum(text in (event["payload"].get("body") or {}).get("text", "")
                   for event in self.history())

    def family(self, receipt, name):
        return [row for row in receipt["families"] if row["family"] == name]

    def snapshot_sources(self):
        return {str(p.relative_to(self.source)): p.read_bytes()
                for p in self.source.rglob("*") if p.is_file()}

    def close(self):
        result = self.ok("down")
        assert result["complete"] and result["witness"]["state"] == "witnessed", result
        assert not (self.home / "endpoint.json").exists(), "shutdown left its endpoint"
        observed = []
        for pid, birth in self.native_processes:
            try:
                fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
                assert fields[19] != birth or fields[0] == "Z", "owned provider remains live after down"
                observed.append({"pid": pid, "birth": birth, "state": fields[0], "current_birth": fields[19]})
            except FileNotFoundError:
                observed.append({"pid": pid, "birth": birth, "state": "absent"})
        if observed:
            (self.root / "outside-shutdown.json").write_text(json.dumps(observed, indent=2))


def retry(f):
    write_row(f.messages, f.message(1, "RETRY-UNIQUE-TEXT"))
    before = f.snapshot_sources()
    key = str(uuid.uuid4())
    arguments = ("--key", key, "import", "--from-node", str(f.source))
    first, second, third = f.ok(*arguments), f.ok(*arguments), f.import_history()
    assert first["complete"] and second["complete"] and third["complete"]
    assert f.count("RETRY-UNIQUE-TEXT") == 1, "retry duplicated or lost history"
    assert before == f.snapshot_sources(), "import modified retained originals"
    for row in second["families"]:
        assert row["read"] == sum(row[name] for name in
                                  ["imported", "duplicate", "unreadable", "dropped_by_policy"])


def growth_and_rewrite(f):
    write_row(f.messages, f.message(1, "PREFIX-ORIGINAL"))
    assert f.import_history()["complete"]
    prefix = f.messages.read_bytes()
    with f.messages.open("ab") as stream:
        stream.write((json.dumps(f.message(2, "APPENDED-SECOND")) + "\n").encode())
    assert f.import_history()["complete"]
    assert f.count("PREFIX-ORIGINAL") == f.count("APPENDED-SECOND") == 1
    original = f.messages.read_bytes()
    f.messages.write_bytes(original.replace(b"PREFIX-ORIGINAL", b"PREFIX-REWRITTEN", 1))
    result = f.call("import", "--from-node", str(f.source))
    output = result.stdout.decode() + result.stderr.decode()
    assert result.returncode != 0 or not json.loads(result.stdout)["complete"], "rewritten prefix accepted"
    assert any(word in output.lower() for word in ["prefix", "conflict", "changed", "rewrite"]), output
    assert f.count("PREFIX-REWRITTEN") == 0 and f.count("PREFIX-ORIGINAL") == 1
    f.messages.write_bytes(original)
    assert f.import_history()["complete"], "refusal damaged the last valid checkpoint"
    assert f.messages.read_bytes().startswith(prefix)


def torn_tail(f):
    write_row(f.messages, f.message(1, "TAIL-WITHOUT-NEWLINE"), newline=False)
    before = f.snapshot_sources()
    result = f.call("import", "--from-node", str(f.source))
    receipt = json.loads(result.stdout)
    assert receipt["schema"] == "se.import/v1", "torn row must have an import disposition"
    row, = f.family(receipt, "messages")
    assert row["read"] == 1 and row["imported"] + row["unreadable"] == 1, (
        "last source row must be imported or explicitly unreadable, not reported as zero", row)
    assert before == f.snapshot_sources()
    if row["imported"]:
        assert f.count("TAIL-WITHOUT-NEWLINE") == 1
    else:
        assert any(e["kind"] == "import.unreadable" for e in f.history()), "no durable unreadable disposition"


def owner_mismatch(f):
    other = "hu_019f26d7-4000-7000-8000-000000000001"
    f.registration(other)
    result = f.call("import", "--from-node", str(f.source))
    output = result.stdout.decode() + result.stderr.decode()
    assert result.returncode != 0, "source owner silently adopted without explicit mapping"
    assert "owner" in output.lower() and other in output, "refusal must name mismatched source owner"
    result = f.call("--project", PROJECT, "status")
    assert result.returncode != 0, "refused source was nevertheless registered"


def multiple_source_humans(f):
    other = "hu_019f26d7-4000-7000-8000-000000000002"
    with (f.state / "humans.jsonl").open("a") as stream:
        stream.write(json.dumps(dict(schema_version=1, record_type="human-minted",
                     human_id=other, display_name="Second recorded human", created_at=TS)) + "\n")
    result = f.call("import", "--from-node", str(f.source))
    output = result.stdout.decode() + result.stderr.decode()
    assert result.returncode != 0, "multiple source humans silently mapped to the current owner"
    assert other in output and "owner" in output.lower(), "refusal must name ambiguous source ownership"


def unresolved_row_is_deferred(f):
    message = f.message(1, "UNRESOLVED-HISTORY")
    message["to_seat"] = "agt-dcba-4321-8765"
    write_row(f.messages, message)
    result = f.call("import", "--from-node", str(f.source))
    receipt = json.loads(result.stdout)
    row, = f.family(receipt, "messages")
    assert not receipt["complete"] and row["read"] == row["deferred"] == 1, receipt
    assert row["imported"] == 0, "unresolved history was reported imported"
    assert f.count("UNRESOLVED-HISTORY") == 0, "source actor/recipient was invented"


def explicit_owner_mapping(f):
    other = "hu_019f26d7-4000-7000-8000-000000000003"
    f.registration(other)
    write_row(f.state / "humans.jsonl", dict(schema_version=1, record_type="human-minted",
              human_id=other, display_name="Source owner", created_at=TS))
    write_row(f.messages, f.message(1, "EXPLICIT-OWNER-MAPPING"))
    before = f.snapshot_sources()
    receipt = f.ok("import", "--from-node", str(f.source), "--source-owner", other)
    assert receipt["complete"] and f.count("EXPLICIT-OWNER-MAPPING") == 1
    assert before == f.snapshot_sources()


def policy_exclusion_has_no_custody(f):
    write_row(f.floor / "events.jsonl", dict(schema_version=1, seq=1, txn_id="excluded-custody",
              ts=TS, events=[dict(type="credential.created", secret="EXCLUDED-CREDENTIAL-NONCE",
              actor_type="human", actor_id=f.owner)]))
    receipt = f.import_history()
    row, = f.family(receipt, "agents")
    assert receipt["complete"] and row["read"] == row["dropped_by_policy"] == 1
    assert row["imported"] == row["deferred"] == 0
    assert f.count("EXCLUDED-CREDENTIAL-NONCE") == 0, "excluded authority bytes leaked into user history"
    with closing(sqlite3.connect(f"file:{f.home / 'state.db'}?mode=ro", uri=True)) as db:
        assert db.execute("select count(*) from credentials").fetchone() == (0,), "source credential acquired native custody"
        assert db.execute("select count(*) from processes").fetchone() == (0,), "import created a native process record"


def excluded_profile_rows_are_counted(f):
    write_row(f.source / "seats-config.json", {"seats": [
        dict(agent_id="agt-dcba-4321-8765", surface="claude"),
        dict(agent_id="agt-abcd-5678-4321", surface="codex")]})
    receipt = f.import_history()
    row, = f.family(receipt, "profiles")
    assert receipt["complete"] and row["read"] == row["dropped_by_policy"] == 2, row
    assert row["imported"] == row["deferred"] == row["unreadable"] == 0


def malformed_tail_is_accounted(f):
    f.messages.parent.mkdir(parents=True)
    f.messages.write_bytes(b'{"record_type":"message","body":"unfinished')
    receipt = json.loads(f.call("import", "--from-node", str(f.source)).stdout)
    row, = f.family(receipt, "messages")
    assert row["read"] == row["unreadable"] == 1 and row["imported"] == 0, row
    with closing(sqlite3.connect(f"file:{f.home / 'state.db'}?mode=ro", uri=True)) as db:
        assert db.execute("select count(*) from events where kind='import.unreadable'").fetchone() == (1,), "torn range has no durable disposition"


def unknown_ids_do_not_gain_authority(f):
    write_row(f.messages, f.message(1, "REGISTERED-HISTORY"))
    assert f.import_history()["complete"]
    for project in [PROJECT, "unregistered-project"]:
        result = f.call("--project", project, "launch", "unregistered-agent", "--detach")
        assert result.returncode != 0, "unknown project/agent acquired launch authority"
    # A canonical-looking but unissued capability must never become owner or
    # a registered imported agent merely because legacy decoding is supported.
    request = {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {"_meta": {
        "stateengine.session-capability-v1": "sec1.ses_019f26d7-4000-7000-8000-000000000099." + "A" * 43}}}
    reply = subprocess.run([str(f.se), "--home", str(f.home), "mcp"], input=json.dumps(request).encode() + b"\n",
                           env=f.environment, capture_output=True, timeout=30)
    (f.root / "unknown-capability.stdout").write_bytes(reply.stdout)
    (f.root / "unknown-capability.stderr").write_bytes(reply.stderr)
    refused = json.loads(reply.stdout)
    assert refused.get("id") == 7 and refused.get("error", {}).get("code") == -32001, "unissued capability gained session discovery"
    with closing(sqlite3.connect(f"file:{f.home / 'state.db'}?mode=ro", uri=True)) as db:
        assert db.execute("select count(*) from credentials").fetchone() == (0,)
        assert db.execute("select count(*) from processes").fetchone() == (0,)


def agent_history(f):
    write_row(f.floor / "events.jsonl", dict(schema_version=1, seq=1, txn_id="history-agent",
              ts=TS, events=[dict(type="agent.created", agent_id=AGENT, agent_name="Historical",
              agent_role="builder", owner_human_id=f.owner, actor_type="human", actor_id=f.owner)]))
    write_row(f.source / "seats-config.json", {"seats": [dict(agent_id=AGENT, surface="claude",
              model="claude-sonnet-5-5", sandbox="workspace-write")]})
    write_row(f.state / PROJECT / "RawLogs/history.jsonl", dict(schema_version=3,
              project_id=PROJECT, agent_id=AGENT, session_id=NATIVE_SESSION, turn_id="turn-1",
              source_cli="claude", ts=TS, attribution="explicit", session={"session_id": NATIVE_SESSION},
              user={"content": "HISTORICAL USER"}, assistant={"content": "HISTORICAL ASSISTANT"}))


def imported_agent_reader_failures(f):
    failures = []
    # Exercise all three consumers even when the first one fails, so the
    # retained replies distinguish project-wide failure from one missing row.
    for command in [("status",), ("agent", "list"), ("agent", "show", AGENT)]:
        result = f.call("--project", PROJECT, *command)
        try:
            assert result.returncode == 0, (result.returncode, result.stdout.decode(), result.stderr.decode())
            output = json.loads(result.stdout)
            if command[0] == "status":
                rows = output["agents"]["items"]
            elif command[1] == "list":
                rows = output["items"]
            else:
                assert output["agent"]["state"] == "present", output
                rows = [output["agent"]["value"]]
            row, = [row for row in rows if row["id"] == AGENT]
            assert row["name"] == "Historical" and row["role"] == "builder", row
            session = row["session"]
            assert session["state"] == "never-launched", "registration invented a launch"
            assert session["session_id"] is None and session["process"] is None, session
        except (AssertionError, KeyError, TypeError, ValueError) as error:
            failures.append((command, str(error)))
    return failures


def missing_profile_cannot_complete_with_broken_readers(f):
    # A recorded agent that never launched has no seats-config profile or
    # transcript. Registration history alone must not poison the whole project.
    agent_history(f)
    (f.source / "seats-config.json").unlink()
    (f.state / PROJECT / "RawLogs/history.jsonl").unlink()
    before = f.snapshot_sources()
    imported = f.call("import", "--from-node", str(f.source))
    receipt = json.loads(imported.stdout)
    assert receipt["schema"] == "se.import/v1" and isinstance(receipt["complete"], bool), receipt
    agents, = f.family(receipt, "agents")
    assert agents["read"] > 0, "judge did not reach the recorded agent"
    assert before == f.snapshot_sources(), "import changed retained registration history"
    failures = imported_agent_reader_failures(f)
    assert receipt["complete"] is True, ("valid missing-profile fixture did not complete", receipt)
    assert imported.returncode == 0, "complete import returned a failed command"
    assert not failures, ("complete import left unreadable or dishonest agent readers", failures)


def user_history_families(f):
    agent_history(f)
    ledger = f.floor / "events.jsonl"
    row = json.loads(ledger.read_text())
    decision = "1e64a975-d2c1-4c0b-aa9d-601717a82322"
    for kind in ["decision.proposed", "decision.ratified"]:
        row["events"].append(dict(type=kind, decision_id=decision, key="history-judge-decision",
                             statement="HISTORICAL DECISION", rationale="Recorded source rationale",
                             actor_type="human", actor_id=f.owner))
    write_row(ledger, row)
    message = f.message(1, "HISTORICAL DIRECT MAIL")
    message["to_seat"] = AGENT
    write_row(f.messages, message)
    write_row(f.floor / "working-state.json", dict(schema_version=1,
              author={"type": "agent", "id": AGENT}, updated_at=TS, text="HISTORICAL WORKING STATE"))
    before = f.snapshot_sources()
    assert f.import_history()["complete"]
    events = f.history()
    kinds = {event["kind"] for event in events}
    for kind in ["principal.registered", "profile.saved", "message.sent", "working_state.set",
                 "session.turn"]:
        assert kind in kinds, ("history family not available to real reader", kind, kinds)
    # Live decision operations are retired (9fbb20013, #104): the seeded decision
    # rows stay readable as retained source rows, not as decision families.
    assert any(e["kind"] == "legacy.retained" and decision in json.dumps(e["payload"])
               for e in events), ("retired decision rows are not retained", kinds)
    for text in ["HISTORICAL DIRECT MAIL", "HISTORICAL WORKING STATE", "HISTORICAL DECISION",
                 "HISTORICAL USER", "HISTORICAL ASSISTANT"]:
        assert any(text in json.dumps(event["payload"]) for event in events), text
    for event in events:
        if event["kind"] in ["message.sent", "working_state.set", "session.turn"]:
            assert event["actor"]["id"] == AGENT, "source agent attribution was invented"
            assert event["payload"]["occurred_at"].startswith("2026-10-15T12:00:00"), "historical time was replaced"
    assert before == f.snapshot_sources()
    with closing(sqlite3.connect(f"file:{f.home / 'state.db'}?mode=ro", uri=True)) as db:
        assert db.execute("select count(*) from credentials").fetchone() == (0,)
        assert db.execute("select count(*) from processes").fetchone() == (0,)


def imported_agent_launches_fresh(f):
    agent_history(f)
    receipt = f.import_history()
    assert receipt["complete"] and receipt["resume"], receipt
    assert any(e["kind"] == "session.turn" for e in f.history()), "conversation fixture was not imported"
    # Native protocol double records actual argv and echoes the selected session.
    provider = f.root / "provider.rs"
    helper = Path(__file__).with_name("history_import_provider.py").resolve()
    provider.write_text('''
fn main(){let a:Vec<String>=std::env::args().collect();
if a.get(1).map(String::as_str)==Some("--version"){println!("2.1.287 (Claude Code)");return;}
if a.get(1).map(String::as_str)==Some("auth") {println!(r#"{{"loggedIn":true}}"#);return;}
let result=std::process::Command::new(PYTHON).args([HELPER,SE,HOME]).args(&a[1..]).status().unwrap();
std::process::exit(result.code().unwrap_or(1));}
'''.replace("PYTHON", json.dumps(sys.executable)).replace("HELPER", json.dumps(str(helper)))
        .replace("SE,HOME", json.dumps(str(f.se)) + "," + json.dumps(str(f.home))))
    executable = f.root / ("provider.exe" if os.name == "nt" else "provider")
    subprocess.run(["rustc", "--edition=2024", str(provider), "-o", str(executable)], check=True,
                   capture_output=True, timeout=60)
    # The owner supplies the executable; source profile command/env are ignored.
    config = f.home / "config.toml"
    f.ok("down")
    text = config.read_text()
    assert "[providers.claude]" in text, "default provider section changed; inspect fixture"
    config.write_text(text.replace("[providers.claude]", "[providers.claude]\ncommand = " +
                                   json.dumps(str(executable)), 1))
    result = f.call("--project", PROJECT, "launch", AGENT, "--detach", "--task", "Fresh launch judge")
    argv_path = f.root / "historical-repo/provider-argv.txt"
    assert argv_path.is_file(), ("production launch never reached provider", result.stdout, result.stderr)
    argv = argv_path.read_text().splitlines()
    assert "--resume" not in argv and NATIVE_SESSION not in argv, "imported provider reference became launch authority"
    assert "--session-id" in argv, "fresh launch must select a new conversation"
    assert result.returncode == 0, (result.stdout, result.stderr)
    ready = json.loads((f.root / "historical-repo/provider-ready.json").read_text())
    assert ready["conversation"] != NATIVE_SESSION and ready["session_discovery"] and ready["http_discovery"]
    launched = json.loads(result.stdout)
    assert launched["state"] == "running" and launched["process"]["pid"] == ready["native_root_pid"]
    if sys.platform == "linux":
        for pid in [ready["native_root_pid"], ready["helper_pid"]]:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
            f.native_processes.append((pid, fields[19]))


CASES = {function.__name__: function for function in
         [retry, growth_and_rewrite, torn_tail, owner_mismatch, multiple_source_humans,
          unresolved_row_is_deferred, explicit_owner_mapping, policy_exclusion_has_no_custody,
          excluded_profile_rows_are_counted, malformed_tail_is_accounted,
          unknown_ids_do_not_gain_authority, missing_profile_cannot_complete_with_broken_readers,
          user_history_families, imported_agent_launches_fresh]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=CASES)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    cases = {args.case: CASES[args.case]} if args.case else CASES
    failures = 0
    print(f"1..{len(cases)}", flush=True)
    for number, (name, function) in enumerate(cases.items(), 1):
        fixture = None
        try:
            fixture = Fixture(args.se.resolve(), args.output.resolve() / (name + "-" + uuid.uuid4().hex[:8]))
            try:
                function(fixture)
            finally:
                fixture.close()
            print(f"ok {number} - {name}", flush=True)
        except Exception:
            failures += 1
            print(f"not ok {number} - {name}", flush=True)
            traceback.print_exc()
    print(f"# {len(cases)-failures} passed, {failures} failed", flush=True)
    raise SystemExit(bool(failures))


if __name__ == "__main__":
    main()
