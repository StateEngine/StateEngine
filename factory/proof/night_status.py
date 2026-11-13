#!/usr/bin/env python3
"""Independently expose a failed or missing night's first-hour proof."""
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import tempfile


def read(path):
    try:
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise ValueError("expected an object")
        return value, None
    except FileNotFoundError:
        return None, "absent"
    except (OSError, ValueError, UnicodeError) as error:
        return None, str(error)


def planned(config):
    # Keep the observer's coverage independent of a producer dropping a row.
    first = ("Install", "Adopt", "Work", "Restart and recall", "Remove")
    stock = ("Install", "Adopt", "Come back", "Two agents", "Remove")
    scopes = {"first-hour": list(enumerate(first, 1)),
              "wave-2": [(n, stock[n - 1]) for n in (1, 2, 3, 5)],
              "4": [(4, stock[3])],
              "remote": [(1, "Connect, launch, live output, message, reconnect")]}
    probes = [("linux", surface, selection) for surface, selection in config["probes"]]
    if not config.get("native_only"):
        remote = config.get("remote", {})
        remote = remote if isinstance(remote, dict) else {}
        probes.append(("linux", remote.get("surface", "claude"), "remote"))
    probes += [(p["platform"], p["surface"], p["selection"])
               for p in config.get("native_receipts", [])]
    return [(key, scopes[key[2]]) for key in probes]


def labels(config):
    return [f"{platform}/{surface}/{selection}: {name}"
            for (platform, surface, selection), rows in planned(config) for _, name in rows]


def assess(config, directory, record, report, night, now):
    value = {"schema": "se.nightly-proof-status/v1", "night": night,
             "checked_at": now.isoformat(), "state": "red", "run_id": directory.name,
             "run_directory": str(directory), "run_started_at": record.get("started_at"),
             "service_invocation_id": record.get("service_invocation_id"),
             "missing_journeys": [], "errors": []}
    try:
        # Re-read every original receipt. A cached green report cannot cover a
        # subsequently missing result or an omitted configured invocation.
        from report import summarize
        expected = planned(config)
        entries = list(record.get("invocations", []))
        required = [key for key, _ in expected]
        actual = [(r.get("platform"), r.get("surface"), r.get("selection")) for r in entries]
        if sorted(actual) != sorted(required):
            value["errors"].append("recorded journey plan differs from configuration")
        for index, (key, _) in enumerate(expected):
            if key not in actual:
                entries.append({"platform": key[0], "surface": key[1], "selection": key[2],
                                "output": f"unavailable-{index}", "state": "planned", "exit": None,
                                "remote_probe": key[2] == "remote"})
        checked = summarize({**record, "invocations": entries}, directory)
        for key, rows in expected:
            matches = [r for r in checked["invocations"]
                       if (r.get("platform"), r.get("surface"), r.get("selection")) == key]
            for number, name in rows:
                if not matches or any(r["journeys"].get(str(number)) not in {"PASS", "FAIL"}
                                      for r in matches):
                    value["missing_journeys"].append("/".join(key) + ": " + name)
        status = checked["status"]
        value["errors"].extend(status.get("errors", []))
        if (report is None or report.get("schema") != checked["schema"]
                or report.get("started_at") != record.get("started_at")
                or report.get("status") != status):
            value["errors"].append("report.json is absent, unreadable or differs from the original receipts")
        if config.get("harness_matrix") and checked.get("harness_matrix") is None:
            value["errors"].append("configured harness matrix is absent")
        if (record.get("state") == "finished" and status["complete"]
                and status["outcome"] == "PASS" and not value["errors"]
                and not value["missing_journeys"]):
            value["state"] = "green"
    except Exception as error:
        value["errors"].append("cannot verify nightly receipts: " + str(error))
        value["missing_journeys"] = labels(config)
    return value


def store(config, value, preserve_newer=False):
    root = Path(config["night_status_directory"])
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = root / (value["night"] + ".json")
    with (root / "status.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous, _ = read(destination)
        if preserve_newer and previous and value.get("run_started_at"):
            try:
                old = datetime.fromisoformat(previous["run_started_at"])
                new = datetime.fromisoformat(value["run_started_at"])
                if old.tzinfo and new.tzinfo and old > new:
                    return previous
            except (KeyError, TypeError, ValueError):
                pass
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", dir=root, delete=False) as output:
                temporary = Path(output.name)
                json.dump(value, output, indent=2, allow_nan=False)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            temporary.replace(destination)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return value


def record_status(config, directory, record, report, errors=()):
    if not config.get("night_status_directory") or config.get("native_only"):
        return
    started = datetime.fromisoformat(record["started_at"]).astimezone()
    value = assess(config, directory, record, report, started.date().isoformat(),
                   datetime.now(timezone.utc))
    value["errors"].extend(errors)
    if errors:
        value["state"] = "red"
    store(config, value, preserve_newer=True)


def check(config, now=None):
    now = now or datetime.now().astimezone()
    # A persistent timer catching up before today's deadline checks yesterday,
    # rather than declaring today's still-pending scheduled run missing.
    date = now.date() - timedelta(days=now.hour < 11)
    night = date.isoformat()
    value = {"schema": "se.nightly-proof-status/v1", "night": night,
             "checked_at": now.isoformat(), "state": "missing", "run_id": None,
             "run_directory": None, "run_started_at": None,
             "service_invocation_id": None,
             "missing_journeys": labels(config), "errors": []}
    try:
        state = Path(config["state"]).resolve(strict=True)
        pointer, error = read(state / "latest.json")
        if error:
            raise ValueError("latest.json: " + error)
        if not error:
            started = datetime.fromisoformat(pointer["started_at"])
            if started.tzinfo and started.astimezone(now.tzinfo).date() != date:
                previous, _ = read(Path(config["night_status_directory"]) / (night + ".json"))
                if previous and previous.get("run_directory"):
                    pointer = {"directory": previous["run_directory"]}
        directory = Path(pointer["directory"]).resolve(strict=True)
        if not directory.is_relative_to(state):
            raise ValueError("latest attempt is outside its configured spool")
        record, error = read(directory / "run.json")
        if error:
            raise ValueError("run.json: " + error)
        started = datetime.fromisoformat(record["started_at"])
        if started.tzinfo is None or started.astimezone(now.tzinfo).date() != date:
            raise ValueError("latest attempt is not from this local night")
        if started > now:
            raise ValueError("latest attempt starts in the future")
        report, _ = read(directory / "report.json")
        value = assess(config, directory, record, report, night, now)
    except Exception as error:
        value["errors"].append(str(error))
    return store(config, value)


def configure(config):
    config.setdefault("night_status_directory", str(Path.home() / ".local/state/stateengine-rust-proof"))
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    value = check(configure(json.loads(args.config.read_text())))
    print(json.dumps(value, allow_nan=False))
    return 0 if value["state"] == "green" else 1


if __name__ == "__main__":
    raise SystemExit(main())
