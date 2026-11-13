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
LOCATE_BYTES = 200
# nextest's coloured FAIL line is `\x1b[31;1m ...`, and its reset is `\x1b[0m`;
# a strip without `;` leaves the colouring in place and no test is ever named.
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
FAIL_LINE = re.compile(r"^\s*FAIL \[[^\]]*\] \([^)]*\) (\S+) (\S+)\s*$")
# nextest prints `FAIL [ duration ] (n/m) <binary> <test>` and, somewhere in the
# same log, `thread '<test>' (<pid>) panicked at <location>:`. The two are not
# always adjacent (the progress renderer repaints), so the test name, not
# adjacency, is what pairs a message with its test.
PANIC_LINE = re.compile(r"^\s*thread '([^']*)'(?: \([^)]*\))? panicked at ([^:]+:\d+:\d+):\s*$")
# Published text leaves the machine, and this repository is public. A failing
# test's own message can carry machine identity, boot ids, temp roots and
# fixture output, so only the test name and its source location are published.
NO_ID = [
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "<id>"),
    (re.compile(r"\bboot_id: \[[^\]]*\]"), "boot_id <id>"),
    (re.compile(r"MachineId\([^)]*\)"), "MachineId(<id>)"),
    (re.compile(r"(?<![\w.])/(?:tmp|var/tmp|dev/shm)/\S+"), "<path>"),
    (re.compile(r"[A-Za-z]:\\\\[^\s\"']+"), "<path>"),
]


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
    # Shards are capped one at a time and concatenated here, so the cap that
    # counts is this one. The outcome outranks its decoration: if the detail
    # cannot be bounded, it is dropped and the status still publishes.
    if failed:
        try:
            value["failures"] = bounded([scrub(str(item)) for item in failed])
        except Exception:
            value["failures"] = ["(failure detail unavailable)"]
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
            any(not isinstance(item, str) or "\n" in item or len(item.encode()) > LOCATE_BYTES
                for item in details)):
        raise ValueError("box failure detail exceeds its bound")
    return value["status"]


def details(text):
    """Name the failing tests, where each panicked, and what it said, bounded.

    nextest prints one `FAIL [ duration ] (n/m) <binary> <test>` line per
    failure and, elsewhere in the same log, `thread '<test>' (<pid>) panicked
    at <file>:<line>:<col>:`. Pairing is by test name because the progress
    renderer can separate the two.

    The first message line is kept because it is what tells a reader what
    broke, but it is scrubbed of machine identity and temp paths first: this
    repository is public.
    """
    text = ANSI.sub("", text)
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
                        message.setdefault(name, scrub(follow.strip()))
                        break
                break
    return bounded([
        name + (" at " + where[name] if name in where else "") +
        (": " + message[name] if name in message else "")
        for name in order
    ])


def bounded(items):
    """Keep the published list inside its bounds, and say when it stopped.

    A cap that silently drops the tail would report a smaller failure than the
    one that happened, so the cut carries its own marker. Nothing here raises:
    a report that cannot be bounded must still publish the outcome.
    """
    kept = []
    for index, item in enumerate(items):
        # One entry is one line: a newline in the source would break the shape
        # the reader and the human both rely on.
        item = " ".join(str(item).split())
        if len(item.encode()) > LOCATE_BYTES:
            item = item.encode()[:LOCATE_BYTES].decode("utf-8", "replace")
        if len(kept) >= FAIL_TESTS - 1 or index >= FAIL_TESTS:
            kept.append("(further failures omitted)")
            break
        try:
            size = len(json.dumps(kept + [item]).encode())
        except (TypeError, ValueError):
            break
        if size > FAIL_BYTES:
            kept.append("(further failures omitted)")
            break
        kept.append(item)
    return kept


def scrub(item):
    """Strip machine identity from anything about to be published."""
    for pattern, replacement in NO_ID:
        item = pattern.sub(replacement, item)
    return item


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
