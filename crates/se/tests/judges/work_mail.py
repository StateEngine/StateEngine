"""Exercise shared work mail through the public CLI, stdio and HTTP doors.

Run with --se EXACT_CANDIDATE --output NEW_OWNED_DIRECTORY. An optional
--legacy-se SCHEMA_2_BINARY also exercises native migration of direct messages
and an existing read marker. Every run creates its own owner home and protocol
providers; no account, shared fixture or database mutation is used.
"""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import traceback
import urllib.error
import urllib.request
import uuid

from judge_records import wait_json
from mail_cli import Fixture


class Reader:
    def __init__(self, fixture, output):
        self.fixture = fixture
        self.output = output

    def call(self, session, transport, tool, arguments):
        f = self.fixture
        f.calls += 1
        request = {"jsonrpc": "2.0", "id": f.calls, "method": "tools/call",
                   "params": {"name": tool, "arguments": arguments}}
        if transport == "stdio":
            result = subprocess.run(
                [str(f.se), "--home", str(f.home), "mcp"],
                input=(json.dumps(request) + "\n").encode(),
                env={**f.env, "SE_SESSION": session["session_id"]},
                capture_output=True, timeout=40)
            (self.output / f"rpc-{f.calls:03d}.stderr").write_bytes(result.stderr)
            assert result.returncode == 0, result.stderr
            reply = json.loads(result.stdout)
        else:
            server = session["http"]
            request = urllib.request.Request(
                server["url"], data=json.dumps(request).encode(),
                headers={**server["headers"], "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(request, timeout=40) as response:
                    reply = json.load(response)
            except urllib.error.HTTPError as error:
                reply = json.load(error)
        (self.output / f"rpc-{f.calls:03d}.json").write_text(json.dumps(reply))
        return reply.get("result", reply)

    def good(self, session, transport, tool, arguments):
        reply = self.call(session, transport, tool, arguments)
        assert "error" not in reply and not reply.get("isError"), reply
        if "structuredContent" in reply:
            return reply["structuredContent"]
        # Resume deliberately renders one JSON text block on current main.
        content = reply.get("content")
        assert tool == "stateengine_resume" and isinstance(content, list), reply
        assert len(content) == 1 and content[0]["type"] == "text", reply
        value = json.loads(content[0]["text"])
        assert isinstance(value, dict), reply
        return value

    def bad(self, session, transport, tool, arguments):
        reply = self.call(session, transport, tool, arguments)
        assert "error" in reply or reply.get("isError"), reply
        return reply

    def inbox(self, session, transport="stdio"):
        page = self.good(session, transport, "stateengine_msg_list",
                         {"full": True, "limit": 100})
        assert page["window"]["complete"], page
        return page["items"]

    def unread(self, session, message):
        return any(row["id"] == message for row in self.inbox(session))


def prepare(options, output):
    initial = options.legacy_se or options.se
    f = Fixture(initial, output / "owner", log_directory="calls")
    try:
        # Retain both unread and read direct deliveries before changing binaries.
        f.launch()
        f.mail("send", f.agent, "retained unread direct message")
        marked = f.mail("send", f.agent, "retained read direct message")
        assert f.mail("read", marked["message_id"], recipient=True)["marked_read"]
        f.close()
        f.session = None
        f.se = options.se
        # The existing native wrapper must call the candidate's session-bound door.
        source = f.root / "provider.rs"
        source.write_text(source.read_text().replace(json.dumps(str(initial)),
                                                   json.dumps(str(options.se))))
        executable = f.root / ("provider.exe" if os.name == "nt" else "provider")
        subprocess.run(["rustc", "--edition=2024", str(source), "-o", str(executable)],
                       capture_output=True, check=True, timeout=60)
        return f
    except BaseException as error:
        try:
            f.close()
        except BaseException as cleanup:
            error.add_note("Preparation cleanup also failed: " + repr(cleanup))
        raise


def run(options):
    output = options.output
    output.mkdir(parents=True, exist_ok=False)
    checks, sessions = [], []
    failure = cleanup_failure = None
    f = None

    def check(name):
        checks.append(name)
        print(f"ok {len(checks)} - {name}", flush=True)

    try:
        f = prepare(options, output)
        db = sqlite3.connect(f"file:{f.home / 'state.db'}?mode=ro", uri=True)
        try:
            seed_schema = db.execute("PRAGMA user_version").fetchone()[0]
            direct_count = db.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            assert direct_count >= 2
            if options.legacy_se:
                assert seed_schema == 2, "--legacy-se must create schema 2"
        finally:
            db.close()
        f.ok("up")
        db = sqlite3.connect(f"file:{f.home / 'state.db'}?mode=ro", uri=True)
        try:
            assert db.execute("PRAGMA user_version").fetchone()[0] == 3
            assert db.execute("SELECT COUNT(*) FROM message_deliveries WHERE is_floor=0").fetchone()[0] == direct_count
            assert db.execute("SELECT COUNT(*) FROM (SELECT d.message_id,d.recipient_id,m.read_seq,m.dismissed_seq FROM messages d JOIN marks m ON m.message_seq=d.sent_seq EXCEPT SELECT message_id,recipient_id,read_seq,dismissed_seq FROM message_deliveries WHERE is_floor=0)").fetchone()[0] == 0
        finally:
            db.close()
        check("native host preserves seeded direct deliveries and read markers")
        reader = Reader(f, output)
        for name in ("Work Sender", "Work Recipient", "Work Outsider"):
            agent = f.ok("--project", f.project, "agent", "add", name,
                         "--provider", "claude", "--model", "claude-sonnet-5-5")["agent"]["id"]
            launch = f.ok("--project", f.project, "launch", agent,
                          "--detach", "--task", "Exercise public work mail")
            argv = (f.repo / "provider-argv.txt").read_text().splitlines()
            config = json.loads(Path(argv[argv.index("--mcp-config") + 1]).read_text())
            launch.update(agent=agent, http=config["mcpServers"]["stateengine"])
            sessions.append(launch)
            if sys.platform == "linux":
                ready = wait_json(f.repo / "provider-ready.json")
                for pid in (launch["process"]["pid"], ready["helper_pid"]):
                    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
                    f.processes.append((pid, fields[19]))
        sender, recipient, outsider = sessions
        for session in sessions:
            for door in ("stdio", "http"):
                status = reader.good(session, door, "stateengine_status", {})
                assert session["agent"] in json.dumps(status)
                reader.good(session, door, "stateengine_resume", {"limit": 5, "byte_budget": 8192})
        check("three bound sessions consume status and resume through both doors")

        payload = {"to": "floor", "body": "one canonical body " + uuid.uuid4().hex,
                   "kind": "finding", "work": {"action": "finding",
                   "addressees": [sender["agent"], recipient["agent"]]},
                   "idempotency_key": str(uuid.uuid4())}
        sent = reader.good(sender, "stdio", "stateengine_msg_send", payload)
        message = sent["message_id"]
        assert sent["to"]["kind"] == "floor" and sent["work"] == payload["work"]
        assert sent["from"]["id"] == sender["agent"]
        replay = reader.good(sender, "http", "stateengine_msg_send", payload)
        assert replay["event_id"] == sent["event_id"] and replay["message_id"] == message
        assert replay["state"] == "replayed"
        reader.bad(sender, "http", "stateengine_msg_send", {**payload, "body": "changed intent"})
        db = sqlite3.connect(f"file:{f.home / 'state.db'}?mode=ro", uri=True)
        try:
            rows = db.execute("SELECT DISTINCT sent_seq FROM message_deliveries WHERE is_floor=1 AND message_kind='finding'").fetchall()
            assert len(rows) == 1
            assert db.execute("SELECT COUNT(*) FROM message_deliveries WHERE sent_seq=?", rows[0]).fetchone()[0] == 2
            assert db.execute("SELECT COUNT(*) FROM payloads WHERE event_seq=? AND field='body'", rows[0]).fetchone()[0] == 1
        finally:
            db.close()
        check("one canonical payload, cross-door keyed replay and changed-intent refusal")

        for session in (sender, recipient):
            for door in ("stdio", "http"):
                row = next(row for row in reader.inbox(session, door) if row["id"] == message)
                assert row["body"]["text"] == payload["body"] and row["work"] == payload["work"]
                assert row["to"]["kind"] == "floor" and row["for_recipient"]["id"] == session["agent"]
            assert reader.unread(session, message)
        check("complete lists preserve each recipient's unread state")
        for session in (sender, recipient):
            for door in ("stdio", "http"):
                resumed = reader.good(session, door, "stateengine_resume", {"byte_budget": 16384, "limit": 10})
                row = next(row for row in resumed["unread"]["items"] if row["id"] == message)
                assert row["work"] == payload["work"] and row["for_recipient"]["id"] == session["agent"]
                assert reader.unread(session, message)
        check("resume carries addressing and recipient disposition without marking")

        read = reader.good(sender, "stdio", "stateengine_msg_read", {"msg_id": message})
        assert read["marked_read"] and not reader.unread(sender, message) and reader.unread(recipient, message)
        again = reader.good(sender, "http", "stateengine_msg_read", {"msg_id": message})
        assert again["event_id"] == read["event_id"] and again["marker"] == "already"
        check("by-ID read marks only its recipient and preserves the replay receipt")
        for session, was_read in ((sender, True), (recipient, False)):
            listing = f.ok("--project", f.project, "msg", "list", "--to", session["agent"], "--all", "--full")
            row = next(row for row in listing["items"] if row["id"] == message)
            assert row["for_recipient"]["id"] == session["agent"]
            assert (row["disposition"]["state"] == "read") == was_read
        listing = f.ok("--project", f.project, "msg", "list", "--full")
        row = next(row for row in listing["items"] if row["id"] == message)
        assert row["for_recipient"]["id"] == recipient["agent"] and row["disposition"]["state"] == "unread"
        check("owner inspection preserves selected and unfiltered recipient state")
        for door in ("stdio", "http"):
            for tool in ("stateengine_msg_read", "stateengine_msg_ack", "stateengine_msg_dismiss"):
                denied = reader.bad(outsider, door, tool, {"msg_id": message})
                assert payload["body"] not in json.dumps(denied)
        check("unaddressed sessions cannot read, acknowledge or dismiss through either door")
        dismissed = reader.good(recipient, "http", "stateengine_msg_dismiss", {"msg_id": message})
        assert dismissed["marker"] == "new" and not reader.unread(recipient, message)
        again = reader.good(recipient, "stdio", "stateengine_msg_dismiss", {"msg_id": message})
        assert again["event_id"] == dismissed["event_id"] and again["marker"] == "already"
        check("dismiss is independent and naturally idempotent across doors")

        returned = reader.good(sender, "http", "stateengine_msg_send", {
            "to": "floor", "body": "Correct this consumer", "kind": "question",
            "work": {"action": "return", "addressees": [recipient["agent"]]},
            "refs": [sent["event_id"]], "reply_to": message, "idempotency_key": str(uuid.uuid4())})
        row = next(row for row in reader.inbox(recipient, "http") if row["id"] == returned["message_id"])
        assert row["work"]["action"] == "return" and row["refs"] == [sent["event_id"]] and row["reply_to"] == message
        check("floor returns retain explicit action, event references and reply identity")
        for alteration in ({"idempotency_key": None},
                           {"work": {"action": "finding", "addressees": []}},
                           {"work": {"action": "finding", "addressees": [recipient["agent"]] * 2}},
                           {"work": {"action": "finding", "addressees": [recipient["agent"]] * 21}},
                           {"kind": "question"}, {"agent_id": outsider["agent"]},
                           {"project_id": "foreign-project"}):
            attempt = {**payload, "idempotency_key": str(uuid.uuid4()), **alteration}
            reader.bad(sender, "stdio", "stateengine_msg_send", attempt)
        check("missing key, invalid recipients, finding mismatch and identity overrides refuse")
        large = reader.good(sender, "stdio", "stateengine_msg_send", {
            "to": "floor", "body": "bounded floor body " + "z" * 30000, "kind": "question",
            "work": {"action": "question", "addressees": [recipient["agent"]]},
            "idempotency_key": str(uuid.uuid4())})["message_id"]
        for door in ("stdio", "http"):
            reader.bad(recipient, door, "stateengine_msg_read", {"msg_id": large, "budget": 512})
            rows = reader.good(recipient, door, "stateengine_msg_list", {"limit": 100})["items"]
            assert any(row["id"] == large for row in rows)
        reader.good(recipient, "http", "stateengine_msg_ack", {"msg_id": large})
        check("read-budget refusal precedes marking and explicit body-free ack works")
        f.session = sender["session_id"]
        cli = f.ok("--project", f.project, "--key", str(uuid.uuid4()), "msg", "send", "floor",
                   "CLI shared return", "--kind", "question", "--work-action", "return",
                   "--addressee", recipient["agent"], "--ref", sent["event_id"], recipient=True)
        row = next(row for row in reader.inbox(recipient, "http") if row["id"] == cli["message_id"])
        assert row["work"]["action"] == "return" and row["body"]["text"] == "CLI shared return"
        f.session = recipient["session_id"]
        assert f.ok("--project", f.project, "msg", "read", cli["message_id"], recipient=True)["marked_read"]
        assert not reader.unread(recipient, cli["message_id"])
        check("CLI send/read shares canonical messages and recipient marks with HTTP")
    except BaseException:
        failure = traceback.format_exc()
        raise
    finally:
        try:
            if f is not None:
                f.close()
                check("public down closes native roots/helpers and retires the endpoint")
        except BaseException:
            cleanup_failure = traceback.format_exc()
            raise
        finally:
            (output / "results.json").write_text(json.dumps({
                "checks": checks, "count": len(checks), "failure": failure,
                "cleanup_failure": cleanup_failure, "real_account_used": False,
                "legacy_binary": str(options.legacy_se) if options.legacy_se else None,
                "outside_pid_checks": sys.platform == "linux"}, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", required=True, type=lambda value: Path(value).resolve(strict=True))
    parser.add_argument("--legacy-se", type=lambda value: Path(value).resolve(strict=True))
    parser.add_argument("--output", required=True, type=Path)
    run(parser.parse_args())
