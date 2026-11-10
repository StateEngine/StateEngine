"""Shared, bounded wire contract for the trusted box and hosted reader."""
import json
import re

NAME = "StateEngine box Linux"
SCHEMA = "stateengine-box-linux/v2"
STAGES = {"fmt", "clippy", "archive", "test-1", "test-2", "windows-clippy"}
SHA = re.compile(r"[a-f0-9]{40}")
DIGEST = re.compile(r"[a-f0-9]{64}")


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


def report(identity, check_id, image, policy, status, stages=None):
    value = dict(schema=SCHEMA, binding=identity, check_id=check_id, image=image,
                 policy=policy, status=status, stages=stages or {})
    validate(value, identity, check_id)
    return value


def validate(value, identity, check_id):
    if (not isinstance(value, dict) or set(value) !=
            {"schema", "binding", "check_id", "image", "policy", "status", "stages"} or
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
    return value["status"]


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


def outcome(row, identity):
    if row["status"] != "completed":
        return None
    raw = row.get("output", {}).get("summary", "")
    if not isinstance(raw, str) or len(raw.encode()) > 16000:
        raise ValueError("bounded box result missing")
    result = json.loads(raw)
    status = validate(result, identity, row["id"])
    expected = {"passed": "success", "failed": "failure", "unavailable": "neutral"}[status]
    if row.get("conclusion") != expected:
        raise ValueError("check conclusion and typed result disagree")
    return status
