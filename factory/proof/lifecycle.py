"""Retain attempt identity before work and publish interruptions as current."""
from datetime import datetime, timezone
import json
import os
import re
from pathlib import Path

from report import publish, read


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def plan(config):
    rows = []
    for index, (surface, selection) in enumerate(config["probes"]):
        rows.append({"platform": "linux", "surface": surface, "selection": selection,
                     "output": f"{index + 1}-{surface}-{selection}", "exit": None, "state": "planned"})
    return rows


def latest(state, directory, record, status):
    previous, _ = read(state / "latest.json")
    # A late finalizer must not replace a newer attempt's pointer.
    if previous and isinstance(previous.get("started_at"), str) and previous["started_at"] > record["started_at"]:
        return
    save(state / "latest.json", {"directory": str(directory), "started_at": record["started_at"],
        "grid": str(directory / "grid.md"), "budgets": str(directory / "budgets.json"), "status": status})


def checkpoint(state, directory, record):
    save(directory / "run.json", record)
    unavailable = {"state": "partial", "complete": False, "outcome": "UNKNOWN", "producer_state": record["state"]}
    # Point at this attempt before any reporting or product operation can fail.
    # Even an unwritable report is unavailable tonight, never yesterday's pass.
    latest(state, directory, record, unavailable)
    try:
        report = publish(directory)
    except Exception as error:
        unavailable["errors"] = ["report publication failed: " + str(error)]
        latest(state, directory, record, unavailable)
        raise
    latest(state, directory, record, report["status"])
    return report


def begin(config, activate=True):
    state = Path(config["state"])
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%S%fZ")
    directory = state / stamp[:8] / stamp
    directory.mkdir(parents=True, mode=0o700)
    record = {"started_at": now.isoformat(), "state": "running", "invocations": plan(config), "errors": [],
              "service_invocation_id": os.environ.get("INVOCATION_ID")}
    pointer = {"directory": str(directory), "service_invocation_id": record["service_invocation_id"]}
    identity = record["service_invocation_id"]
    if identity:
        if not re.fullmatch(r"[a-f0-9]{32}", identity):
            raise RuntimeError("invalid service invocation identity")
        services = state / "services"
        services.mkdir(exist_ok=True, mode=0o700)
        save(services / (identity + ".json"), pointer)
    if activate:
        save(state / "current.json", pointer)
    checkpoint(state, directory, record)
    return state, directory, record


def service_exit(config):
    identity = os.environ.get("INVOCATION_ID")
    if not identity or "SERVICE_RESULT" not in os.environ:
        raise RuntimeError("service finalization requires the service manager's invocation identity and result")
    state = Path(config["state"])
    if not re.fullmatch(r"[a-f0-9]{32}", identity):
        raise RuntimeError("invalid service invocation identity")
    current, error = read(state / "services" / (identity + ".json"))
    directory = None
    if current and isinstance(current.get("directory"), str) and current.get("service_invocation_id") == identity:
        candidate = Path(current["directory"])
        if candidate.is_relative_to(state):
            directory = candidate
        else:
            error = "attempt mapping is outside its configured spool"
    record, record_error = read(directory / "run.json") if directory else (None, error or "invalid attempt mapping")
    if record is None or record.get("service_invocation_id") != identity:
        # This service died before binding an attempt, or its record became
        # unreadable. Publish its own failure without mutating another run.
        state, directory, record = begin(config, activate=False)
        record["errors"].append("service ended before a readable owned attempt record: " + str(record_error))
    result = os.environ["SERVICE_RESULT"]
    if result != "success" or record.get("state") != "finished":
        record["state"] = "interrupted"
        record["errors"].append("service=" + result + " exit=" + os.environ.get("EXIT_CODE", "unknown") +
                                ":" + os.environ.get("EXIT_STATUS", "unknown"))
    checkpoint(state, directory, record)
    return 0
