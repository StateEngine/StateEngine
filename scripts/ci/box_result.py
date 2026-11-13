"""Shared, bounded wire contract for the trusted box and hosted reader."""
import json
import re

NAME = "StateEngine box Linux"
SCHEMA = "stateengine-box-linux/v2"
STAGES = {"fmt", "clippy", "archive", "test-1", "test-2", "windows-clippy"}
SHA = re.compile(r"[a-f0-9]{40}")
DIGEST = re.compile(r"[a-f0-9]{64}")
# A failing stage names itself to every reader through the check-run summary.
# Only the failing test identities and their first assertion lines leave the
# container: the stage log stays private and is never published whole.
FAIL_BYTES = 4000
FAIL_TESTS = 20
ASSERT_BYTES = 300
FAIL_LINE = re.compile(r"^\s*FAIL \[[^\]]*\] \([^)]*\) (\S+) (\S+)\s*$")
# nextest prints `FAIL [ duration ] (n/m) <binary> <test>` and, somewhere in the
# same log, `thread '<test>' (<pid>) panicked at <location>:`. The two are not
# always adjacent (the progress renderer repaints), so the test name, not
# adjacency, is what pairs a message with its test.
PANIC_LINE = re.compile(r"^\s*thread '([^']*)'(?: \([^)]*\))? panicked at ([^:]+:\d+:\d+):\s*$")


def binding(repository, run, attempt, checkout, head):
    if (any(type(n) is not int or n <= 0 for n in (repository, run, attempt)) or
            not SHA.fullmatch(checkout) or not SHA.fullmatch(head)):
        raise ValueError("exact repository/run/attempt and complete SHAs required")
    return dict(repository=repository, run=run, attempt=attempt, checkout=checkout, head=head)


def external_id(value):
    return json.dumps({"schema": SCHEMA, **value}, sort_keys=True, separators=(",", ":"))


def select(checks, app_id, identity):
    # An exact duplicate is ambiguity, including a completed old offer.
    rows = [r for r in checks if r.get("name") == NAME and r.get("app", {}).get("id") == app_id
            and r.get("head_sha") == identity["checkout"]
            and r.get("external_id") == external_id(identity)]
    if len(rows) != 1 or type(rows[0].get("id")) is not int:
        return None
    return rows[0]


def report(identity, check_id, image, policy, status, stages=None, failed=None):
    value = dict(schema=SCHEMA, binding=identity, check_id=check_id, image=image,
                 policy=policy, status=status, stages=stages or {})
    if failed:
        value["failures"] = failed[:FAIL_TESTS]
    validate(value, identity, check_id)
    return value


def validate(value, identity, check_id):
    if (not isinstance(value, dict) or set(value) not in (
            {"schema", "binding", "check_id", "image", "policy", "status", "stages"},
            {"schema", "binding", "check_id", "image", "policy", "status", "stages", "failures"}) or
            value["schema"] != SCHEMA or value["binding"] != identity or
            type(value["check_id"]) is not int or value["check_id"] != check_id or
            not re.fullmatch(r"sha256:[a-f0-9]{64}", value["image"]) or
            not DIGEST.fullmatch(value["policy"]) or
            value["status"] not in ("passed", "failed", "unavailable") or
            not isinstance(value["stages"], dict)):
        raise ValueError("box report identity or schema differs")
    stages = value["stages"]
    if not set(stages).issubset(STAGES):
        raise ValueError("unknown box stage")
    for name, row in stages.items():
        if (not isinstance(row, dict) or set(row) != {"exit", "tests", "custom", "docs", "checks"} or
                any(type(n) is not int or n < 0 for n in row.values())):
            raise ValueError("missing or invalid stage outcome/count")
    if value["status"] == "passed":
        if (set(stages) != STAGES or any(row["exit"] != 0 for row in stages.values()) or
                any(stages[n]["tests"] <= 0 for n in ("test-1", "test-2")) or
                stages["test-1"]["custom"] != 9 or stages["archive"]["docs"] <= 0 or
                stages["fmt"]["checks"] <= 0):
            raise ValueError("box success lacks every required stage and nonzero counts")
    if value["status"] == "failed" and not any(row["exit"] != 0 for row in stages.values()):
        raise ValueError("box failure lacks an observed failed stage")
    if value["status"] == "unavailable" and any(row["exit"] != 0 for row in stages.values()):
        raise ValueError("observed box failure cannot become infrastructure fallback")
    details = value.get("failures", [])
    if (not isinstance(details, list) or len(details) > FAIL_TESTS or
            len(json.dumps(details).encode()) > FAIL_BYTES or
            any(not isinstance(item, str) or "\n" in item or len(item) > ASSERT_BYTES
                for item in details)):
        raise ValueError("box failure detail exceeds its bound")
    return value["status"]


def details(text):
    """Name the failing tests and where each one panicked, bounded.

    nextest prints one `FAIL [ duration ] (n/m) <binary> <test>` line per
    failure and, elsewhere in the same log, `thread '<test>' (<pid>) panicked
    at <file>:<line>:<col>:`. Pairing is by test name because the progress
    renderer can separate the two. Only those identities and locations leave
    this function; the rest of the stage log stays private, and a bound that
    cuts failures short says so instead of dropping them silently.
    """
    text = re.sub(r"\x1b\[[0-9?]*[ -/]*[@-~]", "", text)
    order, seen = [], set()
    for line in text.splitlines():
        match = FAIL_LINE.match(line)
        if match:
            name = f"{match.group(1)} {match.group(2)}"
            if name not in seen:
                seen.add(name)
                order.append(name)
    where, message = {}, {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = PANIC_LINE.match(line)
        if not match:
            continue
        for name in order:
            # A panic names its bare test; match it inside the recorded identity.
            if name.endswith(" " + match.group(1)) or name == match.group(1):
                where.setdefault(name, match.group(2))
                for follow in lines[index + 1:index + 4]:
                    if follow.strip():
                        message.setdefault(name, follow.strip())
                        break
                break
    kept, size = [], 0
    for name in order[:FAIL_TESTS]:
        item = name
        if name in where:
            item += " at " + where[name]
        if name in message:
            item += ": " + message[name][:ASSERT_BYTES]
        added = len(json.dumps(item).encode())
        if size + added > FAIL_BYTES or len(kept) == FAIL_TESTS - 1 and len(order) > FAIL_TESTS:
            kept.append("(further failures omitted)")
            break
        kept.append(item)
        size += added
    return kept


def failures(checks, app_id, identity):
    for row in checks:
        if (row.get("name") == NAME and row.get("app", {}).get("id") == app_id and
                row.get("head_sha") == identity["checkout"] and
                row.get("external_id") == external_id(identity)):
            try:
                if outcome(row, identity) == "failed":
                    return True
            except (ValueError, KeyError, TypeError):
                pass
    return False


def text(payload):
    """The reader contract, then the failing tests in plain lines.

    The first line is the machine-read result the hosted reader parses
    (outcome below); a reader that takes the first line keeps working. The
    lines under it are what a human or a seat needs in order to know which
    test failed without reading a root-only controller log.
    """
    machine = json.dumps(payload, separators=(",", ":"))
    if not payload.get("failures"):
        return machine
    return machine + "\n\nFailing tests:\n" + "\n".join(
        "- " + item for item in payload["failures"])


def outcome(row, identity):
    if row["status"] != "completed":
        return None
    raw = row.get("output", {}).get("summary", "")
    if not isinstance(raw, str):
        raise ValueError("bounded box result missing")
    # The result line comes first; anything after it is the human-readable
    # failure detail the box adds, never part of the machine contract.
    line = raw.split("\n", 1)[0]
    if len(line.encode()) > 16000:
        raise ValueError("bounded box result missing")
    result = json.loads(line)
    status = validate(result, identity, row["id"])
    expected = {"passed": "success", "failed": "failure", "unavailable": "neutral"}[status]
    if row.get("conclusion") != expected:
        raise ValueError("check conclusion and typed result disagree")
    return status
