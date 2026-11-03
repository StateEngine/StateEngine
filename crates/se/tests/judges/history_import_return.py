"""Independent public-consumer checks for the S15 Opus return.
Run with --se RELEASE_SE --output OWNED_LOG_DIRECTORY.
"""
import argparse
import json
from pathlib import Path
import uuid

from history_import import Fixture, AGENT, PROJECT, TS, agent_history, write_row


def registration_only(f):
    agent_history(f)
    (f.source / "seats-config.json").unlink()
    (f.state / PROJECT / "RawLogs/history.jsonl").unlink()


def safe_owner_default_and_existing_profile(f):
    registration_only(f)
    config = f.home / "config.toml"
    text = config.read_text().replace('sandbox = "workspace-write"', 'sandbox = "read-only"')
    text = text.replace('provider = "claude"', 'provider = "codex"', 1)
    config.write_text(text)
    first = f.import_history()
    assert first["complete"], first
    shown = f.ok("--project", PROJECT, "agent", "show", AGENT)["agent"]["value"]
    (f.root / "agent.json").write_text(json.dumps(shown, indent=2))
    assert shown["provider"] == "codex" and shown["profile"] == "default", shown
    assert shown["session"]["state"] == "never-launched", shown
    saved = [e for e in f.history() if e["kind"] == "profile.saved"]
    assert len(saved) == 1, saved
    profile = saved[0]["payload"]["profile"]
    assert profile["permission"] == "ReadOnly" and profile["provider"] == "Codex", profile
    # Adopted profiles must survive a later owner-default policy change.
    f.ok("down")
    config.write_text(text.replace('sandbox = "read-only"', 'sandbox = "workspace-write"'))
    again = f.import_history()
    assert again["complete"], again
    saved_again = [e for e in f.history() if e["kind"] == "profile.saved"]
    assert saved_again == saved, "retry silently broadened an already adopted profile"


def committed_row_rejection_is_durable_and_later_rows_import(f):
    huge = f.message(1, "ROW-REJECT-")
    # Source framing accepts this complete row (including its newline). The
    # retained decoded descriptor adds provenance and exceeds the store's
    # 1 MiB payload limit, forcing the actual writer-validation path.
    huge["body"] += "x" * (1024 * 1024 - 1 - len(json.dumps(huge, separators=(",", ":")).encode()))
    later = f.message(2, "VALID-AFTER-REJECT")
    f.messages.parent.mkdir(parents=True, exist_ok=True)
    first_line = json.dumps(huge, separators=(",", ":")) + "\n"
    assert len(first_line.encode()) == 1024 * 1024
    f.messages.write_text(first_line + json.dumps(later) + "\n")
    original = f.snapshot_sources()
    def partial():
        result = f.call("import", "--from-node", str(f.source))
        receipt = json.loads(result.stdout)
        assert result.returncode != 0 and receipt["schema"] == "se.import/v1" and not receipt["complete"], receipt
        return receipt

    first = partial()
    family, = f.family(first, "messages")
    assert not first["complete"] and family["read"] == 2 and family["unreadable"] == 1, first
    assert family["deferred"] == 0 and family["imported"] == 1, family
    history = f.history()
    rejected_page = f.ok("--project", PROJECT, "history", "--kind", "import.unreadable", "--limit", "100")
    assert rejected_page["window"]["complete"] and rejected_page["next"] is None, rejected_page
    rejected = rejected_page["items"]
    assert len(rejected) == 1 and rejected[0]["payload"]["reason"] == "source-commit-invalid", rejected
    assert rejected[0]["payload"]["source_range"]["length"] == len(first_line.encode()), rejected
    assert f.count("VALID-AFTER-REJECT") == 1 and f.count("ROW-REJECT-") == 0
    again = partial()
    retried, = f.family(again, "messages")
    for name in ["read", "imported", "duplicate", "unreadable", "dropped_by_policy", "deferred"]:
        assert retried[name] == family[name], (family, retried)
    repeated = f.ok("--project", PROJECT, "history", "--kind", "import.unreadable", "--limit", "100")
    assert repeated["items"] == rejected, "retry duplicated its durable unreadable disposition"
    progress = f.ok("--project", PROJECT, "history", "--kind", "import.progress", "--limit", "100")
    final = [e for e in progress["items"] if e["payload"]["family"] == "messages"][-1]["payload"]
    assert final["source_rows"] == 2 and final["counts"]["unreadable"] == 1, final
    assert f.history() == history, "retry appended another failure, payload or checkpoint"
    assert f.snapshot_sources() == original, "import rewrote retained input"


def floor_and_unmapped_human_mail_keep_recorded_attribution(f):
    registration_only(f)
    missing_human = "hum-abcd-1234-5678"
    rows = []
    for number, sender in enumerate(["floor", missing_human], 1):
        row = f.message(number, "RECORDED-SENDER-" + sender)
        row.update(from_seat=sender, to_seat=AGENT)
        rows += [row, dict(record_type="read-marker", msg_id=row["msg_id"], seat=AGENT, ts=TS),
                 dict(record_type="dismiss", msg_id=row["msg_id"], seat=AGENT, ts=TS)]
    f.messages.parent.mkdir(parents=True, exist_ok=True)
    f.messages.write_text("".join(json.dumps(row) + "\n" for row in rows))
    imported = f.import_history()
    assert imported["complete"], imported
    family, = f.family(imported, "messages")
    assert family["read"] == 6 and family["imported"] == 6 and family["deferred"] == 0, family
    history = f.history()
    assert not any(e["kind"] in ["message.sent", "message.read", "message.dismissed"] for e in history), history
    assert not any(missing_human in json.dumps(e["payload"]) for e in history if e["kind"] == "principal.registered"), history
    for sender in ["floor", missing_human]:
        assert f.count("RECORDED-SENDER-" + sender) == 1, "recorded sender or body lost"
    assert f.import_history()["complete"] and f.history() == history, "retry duplicated retained source mail"


CASES = [safe_owner_default_and_existing_profile,
         committed_row_rejection_is_durable_and_later_rows_import,
         floor_and_unmapped_human_mail_keep_recorded_attribution]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=[case.__name__ for case in CASES])
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    cases = [case for case in CASES if not args.case or case.__name__ == args.case]
    print(f"1..{len(cases)}", flush=True)
    for number, case in enumerate(cases, 1):
        f = Fixture(args.se.resolve(), args.output.resolve() / (case.__name__ + "-" + uuid.uuid4().hex[:8]))
        try:
            case(f)
        finally:
            f.close()
        print(f"ok {number} - {case.__name__}", flush=True)


if __name__ == "__main__":
    main()
