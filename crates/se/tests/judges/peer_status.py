"""Independent judge for peer summaries in agent status (#522 Option B).

Over the real MCP door, an agent's status lists every other agent in its own
project with only the summary fields: id, name, role, provider, derived state
and working note. Nothing from a peer's session, resume, provider activity,
unread mail or codex login appears, no agent from another project appears, and
the owner's status carries no peer list.
Run: python3 peer_status.py --se SE --output NEW_DIRECTORY
"""
import argparse
import json
from pathlib import Path
import uuid

from mail_cli import Fixture

PEER_FIELDS = {"id", "name", "role", "provider", "state", "working_note"}
FORBIDDEN = ("session", "resume", "provider_activity", "unread", "conversation", "codex_login",
             "last_activity_at", "harness", "provider_settings", "process")
NOTE = "Reviewing the parser change"


def key():
    return str(uuid.uuid4())


def run(fixture):
    peer = fixture.ok("--key", key(), "--project", fixture.project, "agent", "add", "Reviewer",
                      "--provider", "claude", "--model", "claude-sonnet-5-5")["agent"]
    fixture.ok("--key", key(), "--project", fixture.project, "working-state", "set",
               NOTE + "\nsecond line stays private to the full note", "--expect", "absent",
               "--agent", peer["id"])
    other_repo = fixture.root / "other-repo"
    other_repo.mkdir()
    # The protocol double does not answer `claude mcp get`, so init reports that
    # step after saving the registration; only that refusal is accepted.
    made = fixture.call("--key", key(), "init", "--repo", str(other_repo), "--name", "Other Project",
                        "--agent", "Outsider", "--provider", "claude", "--model", "claude-sonnet-5-5")
    assert made.returncode == 0 or b"Project registration was saved" in made.stdout, made.stdout
    projects = fixture.ok("status", "--all")["projects"]["items"]
    other = [row for row in projects if row["name"] == "Other Project"]
    assert len(other) == 1, projects
    agents = fixture.ok("--project", other[0]["id"], "agent", "list", "--limit", "100")
    outsider = [row for row in agents["items"] if row["name"] == "Outsider"]
    if not outsider:
        outsider = [fixture.ok("--key", key(), "--project", other[0]["id"], "agent", "add", "Outsider",
                               "--provider", "claude", "--model", "claude-sonnet-5-5")["agent"]]
    outsider = {"agent": outsider[0], "project": other[0]}
    print("ok 1 - a peer with a note and an agent in another project exist", flush=True)

    fixture.launch()
    reply = fixture.rpc("stateengine_status", {})
    status = reply["structuredContent"]
    text = json.dumps(status)
    peers = status.get("peers")
    assert isinstance(peers, dict) and peers.get("state") == "present", f"agent status carries no peer list: {peers}"
    rows = peers["value"]
    assert [row["id"] for row in rows] == [peer["id"]], f"peers are not exactly the project's other agent: {rows}"
    row = rows[0]
    assert set(row) <= PEER_FIELDS, f"a peer row carries more than the summary fields: {sorted(row)}"
    assert row["name"] == "Reviewer"
    for field in FORBIDDEN:
        assert field not in json.dumps(rows), f"peer rows expose {field}"
    assert row["working_note"]["state"] == "present", row
    note = row["working_note"]["value"]
    assert note["text"] == NOTE and note["truncated"], f"the peer note is not its first line only: {note}"
    assert "second line stays private" not in text, "the full working note leaked"
    for foreign in (outsider["agent"]["id"], outsider["project"]["id"], "Outsider", "Other Project"):
        assert foreign not in text, f"agent status leaked another project's {foreign}"
    own = [agent["id"] for agent in (status.get("agents") or {}).get("items", [])]
    assert own == [fixture.agent], f"an agent caller sees other agents' full rows: {own}"
    print("ok 2 - the agent sees its peer's summary only, and nothing from the other project", flush=True)

    owner = fixture.ok("--project", fixture.project, "status")
    assert "peers" not in owner, "the owner status carries a peer list"
    print("ok 3 - the owner status has no peer list", flush=True)


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
