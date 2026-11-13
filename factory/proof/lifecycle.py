"""Retain attempt identity before work and publish interruptions as current."""
from datetime import datetime, timezone
import json
import os
import re
from pathlib import Path

from report import exit_status, publish, read, summarize
from matrix_adapter import plan as matrix_plan


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
    if not config.get("native_only"):
        remote = config.get("remote", {})
        if not isinstance(remote, dict):
            remote = {}
        rows.append({"platform": "linux", "surface": remote.get("surface", "claude"),
                     "selection": "remote", "output": "remote-journey", "exit": None,
                     "state": "planned", "remote_probe": True})
    for probe in config.get("native_receipts", []):
        if probe.get("platform") not in {"win32", "darwin"} or probe.get("surface") != "claude" or probe.get("selection") != "wave-2":
            raise ValueError("native receipts require a native platform and Claude wave-2 scope")
        rows.append({key: probe[key] for key in ("platform", "surface", "selection")})
        rows[-1].update(output=f"{len(rows)}-native-{probe['platform']}-claude-wave-2", exit=None,
                        state="planned", native_receipt=True)
    return rows


def latest(state, directory, record, status):
    if record.get("publish_latest") is False:
        return
    previous, _ = read(state / "latest.json")
    # A late finalizer must not replace a newer attempt's pointer.
    if previous and isinstance(previous.get("started_at"), str) and previous["started_at"] > record["started_at"]:
        return
    save(state / "latest.json", {"directory": str(directory), "started_at": record["started_at"],
        "grid": str(directory / "grid.md"), "budgets": str(directory / "budgets.json"),
        "service_invocation_id": record.get("service_invocation_id"), "status": status})


def checkpoint(state, directory, record, config=None):
    save(directory / "run.json", record)
    interrupted = record["state"] == "interrupted"
    unavailable = {"state": "interrupted" if interrupted else "partial", "complete": False,
                   "outcome": "INTERRUPTED" if interrupted else "UNKNOWN", "producer_state": record["state"]}
    # Point at this attempt before any reporting or product operation can fail.
    # Even an unwritable report is unavailable tonight, never yesterday's pass.
    latest(state, directory, record, unavailable)
    try:
        report = publish(directory)
    except Exception as error:
        unavailable["errors"] = ["report publication failed: " + str(error)]
        latest(state, directory, record, unavailable)
        if config:
            from night_status import record_status
            record_status(config, directory, record, None, unavailable["errors"])
        raise
    latest(state, directory, record, report["status"])
    if config and (record["state"] in {"finished", "interrupted"}
                   or report["status"]["outcome"] == "FAIL"):
        from night_status import record_status
        record_status(config, directory, record, report)
    return report


def begin(config, activate=True, bind_service=True):
    state = Path(config["state"])
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%S%fZ")
    directory = state / stamp[:8] / stamp
    directory.mkdir(parents=True, mode=0o700)
    record = {"started_at": now.isoformat(), "state": "running", "invocations": plan(config), "errors": [],
              "service_invocation_id": os.environ.get("INVOCATION_ID"), "publish_latest": activate}
    if 'harness_matrix' in config:
        record['harness_matrix'] = matrix_plan(config)
    pointer = {"directory": str(directory), "started_at": record["started_at"],
               "service_invocation_id": record["service_invocation_id"]}
    identity = record["service_invocation_id"]
    if identity and not re.fullmatch(r"[a-f0-9]{32}", identity):
        raise RuntimeError("invalid service invocation identity")
    if identity and bind_service:
        services = state / "services"
        services.mkdir(exist_ok=True, mode=0o700)
        save(services / (identity + ".json"), pointer)
    if activate:
        save(state / "current.json", pointer)
    checkpoint(state, directory, record, config)
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
        # A corrupt old record must not turn its late finalizer into a new
        # attempt. Recover its original ordering from the separate mapping or
        # its own latest pointer. Without either, retain a detached failure.
        previous, previous_error = read(state / "latest.json")
        owns_latest = previous and (previous.get("service_invocation_id") == identity or
                                   directory and previous.get("directory") == str(directory))
        origin = current.get("started_at") if directory and current else None
        if origin is None and owns_latest:
            origin = previous.get("started_at")
        try:
            comparable = isinstance(origin, str) and datetime.fromisoformat(origin).tzinfo is not None
        except ValueError:
            comparable = False
        original_directory = str(directory) if directory else None
        state, directory, record = begin(config, activate=False, bind_service=False)
        record["original_attempt_directory"] = original_directory
        record["publish_latest"] = comparable or previous_error == "absent"
        if comparable:
            record["started_at"] = datetime.fromisoformat(origin).astimezone(timezone.utc).isoformat()
        record["errors"].append("service ended before a readable owned attempt record: " + str(record_error))
    result = os.environ["SERVICE_RESULT"]
    code, status = os.environ.get("EXIT_CODE", "unknown"), os.environ.get("EXIT_STATUS", "unknown")
    record["service_exit"] = {"result": result, "code": code, "status": status}
    expected = exit_status(summarize(record, directory))
    completed = (record.get("state") == "finished" and code == "exited" and status == str(expected)
                 and result == ("success" if expected == 0 else "exit-code"))
    if not completed:
        record["state"] = "interrupted"
        record["errors"].append("service=" + result + " exit=" + code + ":" + status)
    checkpoint(state, directory, record, config)
    return 0
