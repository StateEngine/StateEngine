#!/usr/bin/env python3
"""Publish a portable journey scoreboard without private receipt details."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import tempfile

from night_status import SCHEDULE_ZONE, assess, configure, planned, read, scheduled_night
from report import FIRST_HOUR, NAMES, summarize

PROVIDERS = {"claude": "Claude Code", "codex": "Codex", "secode": "SE Code",
             "acp": "ACP", "qwen": "Qwen Code", "goose": "Goose"}
PLATFORMS = {"linux": "Linux", "win32": "Windows", "darwin": "macOS"}
SCOPES = {"first-hour": ("First hour", list(enumerate(FIRST_HOUR, 1))),
          "wave-2": ("Stock journeys", [(n, NAMES[n - 1]) for n in (1, 2, 3, 5)]),
          "4": ("Two agents", [(4, NAMES[3])]),
          "remote": ("Remote", [(1, "Connect, launch, live output, message, reconnect")])}
CAUSES = {None: "Verified", "absent": "Evidence absent", "unreadable": "Evidence unreadable",
          "stale": "Evidence from an earlier night", "future": "Evidence starts in the future",
          "incomplete": "Evidence incomplete", "failed": "Observed failure",
          "interrupted": "Run interrupted", "publication-failed": "Publication failed"}


def snapshot(config, now):
    root = Path(config["night_status_directory"])
    today = now.date()
    date = scheduled_night(now)
    # An already-observed failure tonight remains visible before the deadline.
    _, error = read(root / (today.isoformat() + ".json"))
    if error != "absent":
        date = today
    night = date.isoformat()
    try:
        return load_snapshot(config, now, night)
    except FileNotFoundError:
        return night, None, "MISSING", None
    except Exception:
        return night, None, "UNREADABLE", None


def load_snapshot(config, now, night):
    root = Path(config["night_status_directory"])
    status, error = read(root / (night + ".json"))
    if error:
        return night, None, "MISSING" if error == "absent" else "UNREADABLE", None
    if (status.get("schema") != "se.nightly-proof-status/v1" or status.get("night") != night
            or status.get("state") not in {"green", "red", "missing"}
            or status.get("cause") not in CAUSES):
        return night, None, "UNREADABLE", None
    checked = datetime.fromisoformat(status["checked_at"])
    if checked.tzinfo is None or checked > now:
        return night, None, "UNREADABLE", None
    if not status.get("run_directory"):
        return night, status, "MISSING", None
    directory = Path(status["run_directory"]).resolve(strict=True)
    if not directory.is_relative_to(Path(config["state"]).resolve(strict=True)):
        return night, status, "UNREADABLE", None
    record, error = read(directory / "run.json")
    if error:
        return night, status, "MISSING" if error == "absent" else "UNREADABLE", None
    started = datetime.fromisoformat(record["started_at"])
    if (started.tzinfo is None or started.astimezone(SCHEDULE_ZONE).date().isoformat() != night
            or record["started_at"] != status.get("run_started_at")
            or directory.name != status.get("run_id")):
        return night, status, "UNREADABLE", None
    report, error = read(directory / "report.json")
    verified = assess(config, directory, record, report, night, now, report_error=error)
    if any(verified[key] != status.get(key) for key in ("state", "cause", "missing_journeys", "errors")):
        return night, status, "UNREADABLE", None
    return night, status, None, (directory, summarize(record, directory))


def cell(entry, directory, number):
    observed = entry["journeys"].get(str(number))
    if observed in {"PASS", "FAIL"}:
        return observed
    filename = "remote.json" if entry.get("remote_probe") else "results.json"
    _, error = read(directory / entry["output"] / filename)
    if error == "absent":
        return "MISSING"
    return "UNREADABLE"


def render(config, now=None):
    now = (now or datetime.now(timezone.utc)).astimezone(SCHEDULE_ZONE)
    # Every emitted label is a literal or a validated date. Raw diagnostics,
    # output paths, custom provider names and receipt content never enter Markdown.
    try:
        night, status, unavailable, evidence = snapshot(config, now)
    except Exception:
        night = scheduled_night(now).isoformat()
        status, unavailable, evidence = None, "UNREADABLE", None
    state = unavailable or status["state"].upper()
    lines = ["# Journey scoreboard", "", f"Night: {night} (America/New_York)",
             f"Generated: {now.isoformat(timespec='seconds')}", f"Nightly status: **{state}**"]
    if status:
        checked = datetime.fromisoformat(status["checked_at"])
        lines.append("Checked: " + checked.isoformat(timespec="seconds"))
        reason = CAUSES[status.get("cause")]
        if unavailable:
            reason = "Evidence absent" if unavailable == "MISSING" else "Evidence unreadable"
        lines.append("Reason: " + reason)
    lines += ["", "PASS describes witnessed journey behavior and cleanup; nightly status also includes required budgets.",
              "FAIL = observed failure; MISSING = planned evidence absent; UNREADABLE = evidence cannot be verified; NOT RUN = no planned observation."]
    expected = {}
    unsupported = False
    try:
        for (platform, provider, selection), rows in planned(config):
            if platform not in PLATFORMS or provider not in PROVIDERS or selection not in SCOPES:
                unsupported = True
                continue
            for number, _ in rows:
                expected[(selection, provider, number, platform)] = unavailable or "MISSING"
    except Exception:
        unsupported = True
    entries = evidence[1]["invocations"] if evidence else []
    for selection, (scope, rows) in SCOPES.items():
        providers = list(PROVIDERS) if selection == "first-hour" else [provider for provider in PROVIDERS
            if any(key[0] == selection and key[1] == provider for key in expected)]
        if not providers:
            continue
        lines += ["", "## " + scope, "", "| Journey | Provider | Linux | Windows | macOS |",
                  "| --- | --- | --- | --- | --- |"]
        for number, name in rows:
            for provider in providers:
                values = []
                for platform in PLATFORMS:
                    key = (selection, provider, number, platform)
                    matched = [entry for entry in entries if key in expected
                               and entry.get("selection") == selection and entry.get("surface") == provider
                               and entry.get("platform") == platform]
                    samples = [cell(entry, evidence[0], number) for entry in matched] if evidence else []
                    value = next((state for state in ("FAIL", "UNREADABLE", "MISSING")
                                  if state in samples), "PASS" if samples else expected.get(key, "NOT RUN"))
                    values.append(value)
                lines.append("| " + " | ".join([name, PROVIDERS[provider], *values]) + " |")
    if unsupported:
        lines += ["", "Unsupported coverage labels were withheld; this scoreboard is incomplete."]
    lines += ["", "This is one night's evidence. NOT RUN cells and older results do not establish platform support.", ""]
    return "\n".join(lines)


def publish(config):
    root = Path(config["night_status_directory"])
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (root / "scoreboard.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        text = render(config)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", dir=root, delete=False) as output:
                temporary = Path(output.name)
                output.write(text)
                output.flush()
                os.fsync(output.fileno())
            temporary.replace(root / "scoreboard.md")
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            if temporary:
                temporary.unlink(missing_ok=True)
    return root / "scoreboard.md"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    print(publish(configure(json.loads(args.config.read_text()))))


if __name__ == "__main__":
    main()
