"""Summarize independent receipts; incomplete evidence never becomes a pass."""
import json
import math
from pathlib import Path
from native import validate as validate_native

PLATFORMS = ("linux", "win32", "darwin")
NAMES = ("Install", "Adopt", "Come back", "Two agents", "Remove")
FIRST_HOUR = ("Install", "Adopt", "Work", "Restart and recall", "Remove")
FIRST_HOUR_PROBES = frozenset((
    "CLI --version", "CLI contextual read verbs", "CLI writes through running host",
    "standalone persistent processes", "idle no session", "standalone RSS no session",
    "persistent processes after 1 seat(s)", "standalone RSS one session", "idle one session"))
SELECTIONS = {"first-hour": ("first-hour", {1, 2, 3, 4, 5}),
              "wave-2": ("rust-wave-2", {1, 2, 3, 5}),
              "4": ("selected", {4})}
LABELS = {
    "B1": ("embedded A/B",), "B2": ("embedded A/B",),
    "B3": ("standalone persistent processes", "persistent processes after 1 seat(s)",
           "persistent processes after 2 seat(s)", "embedded A/B"),
    "B4": ("standalone RSS no session", "standalone RSS one session", "W5 post-task RSS journey 2",
           "W5 post-task RSS journey 3", "W5 post-task RSS journey 5"),
    "B5": ("idle no session", "idle one session"),
    "B6": ("idle no session", "idle one session"),
    "B7": ("CLI --version", "CLI contextual read verbs"),
    "B8": ("host restart re-adoption",),
    "B9": ("CLI writes through running host", "in-session kept-open writes",
           "Claude stop hook through running host"), "FULL": (),
}


def read(path):
    try:
        value = json.loads(Path(path).read_text())
        if not isinstance(value, dict):
            raise ValueError("receipt must be an object")
        return value, None
    except FileNotFoundError:
        return None, "absent"
    except OSError as error:
        return None, f"unreadable: {error}"
    except (ValueError, UnicodeError) as error:
        return None, f"invalid: {error}"


def numbers(value, prefix=""):
    if type(value) in (int, float):
        return {prefix: value} if math.isfinite(value) else {}
    if isinstance(value, list):
        return {key: number for i, item in enumerate(value)
                for key, number in numbers(item, f"{prefix}[{i}]").items()}
    if isinstance(value, dict):
        return {key: number for name, item in value.items()
                if name not in {"processes", "added", "before", "after", "pid", "parent", "birth",
                                "samples", "rows", "agent", "event", "arguments", "receipt"}
                for key, number in numbers(item, f"{prefix}.{name}" if prefix else name).items()}
    return {}


def budget_numbers(budget, row):
    selectors = {
        "B1": ("rss_bytes",), "B2": ("startup_ms", "first_request", "bound_ms"),
        "B3": ("count", "added_processes"), "B4": ("rss_bytes",),
        "B5": ("cpu_percent_one_core",), "B6": ("wakeups",),
        "B7": ("reads",), "B8": ("readoption", "readopt", "cutover", "elapsed_ms"),
        "B9": ("writes", "samples", "p95", "ceiling_ms"), "FULL": (),
    }
    return {path: value for path, value in numbers(row).items()
            if any(part in path for part in selectors[budget])
            and (budget not in {"B2", "B7", "B9"} or path.endswith(("_ms", ".ms")) or ".p95_ms." in path)}



def probe_result(budget, row, limits, numeric):
    if not numeric or row.get("state") == "unavailable":
        return "NOT MEASURED"
    if budget not in {"B5", "B6"}:
        return "PASS" if row.get("passed") is True else "MISS" if row.get("passed") is False else "NOT MEASURED"
    if not isinstance(limits, dict):
        return "NOT MEASURED"
    if budget == "B5":
        value = row.get("cpu_percent_one_core")
        ceiling = limits.get("idle_cpu_percent_exclusive")
    else:
        wakeups = row.get("wakeups")
        if not isinstance(wakeups, dict) or wakeups.get("state") != "measured":
            return "NOT MEASURED"
        value = wakeups.get("absolute_rate_for_budget")
        if value is None:
            value = wakeups.get("per_second")
        ceiling = limits.get("idle_one_session_wakeups_per_second" if row["label"] == "idle one session"
                             else "idle_no_session_wakeups_per_second")
    if any(type(x) not in (int, float) or not math.isfinite(x) or x < 0 for x in (value, ceiling)):
        return "NOT MEASURED"
    cleanup = row.get("cleanup_errors", [])
    if not isinstance(cleanup, list):
        return "NOT MEASURED"
    within_limit = value < ceiling if budget == "B5" else value <= ceiling
    return "PASS" if within_limit and not cleanup else "MISS"


def finite_nonnegative(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def first_hour_probe_result(budget, row, limits):
    """Validate current first-hour measurements without changing legacy receipts."""
    state = row.get("state")
    if (not isinstance(limits, dict) or state is not None and not isinstance(state, str)
            or state in ("unavailable", "not measured", "unreadable", "absent", "not reached")):
        return "NOT MEASURED"
    if budget in {"B5", "B6"}:
        return probe_result(budget, row, limits, budget_numbers(budget, row))
    label = row.get("label")
    if budget in {"B7", "B9"}:
        read = budget == "B7"
        samples = row.get("reads" if read else "writes")
        if not isinstance(samples, list) or not samples or any(not isinstance(s, dict) for s in samples):
            return "NOT MEASURED"
        expected = ({"--version"} if label == "CLI --version" else
                    {"status", "agent list", "msg inbox", "msg list"}) if read else {1, 8}
        found = [s.get("verb" if read else "clients") for s in samples]
        if (len(found) != len(expected) or not all(
                isinstance(value, str) if read else type(value) is int for value in found)
                or any(value not in expected for value in found) or len(set(found)) != len(expected)):
            return "NOT MEASURED"
        for sample in samples:
            key = ("cli_status_p95_ms_exclusive" if sample.get("verb") == "status" else
                   "cli_p95_ms_exclusive") if read else ("cli_write_eight_p95_ms_inclusive"
                   if sample["clients"] == 8 else "cli_write_p95_ms_inclusive")
            value, ceiling = sample.get("p95_ms"), limits.get(key)
            raw = sample.get("samples")
            count = 30 if read else 30 * sample["clients"]
            if (not finite_nonnegative(value) or not finite_nonnegative(ceiling)
                    or not isinstance(raw, list) or len(raw) != count
                    or any(not isinstance(s, dict) or type(s.get("code")) is not int
                           or s["code"] != 0 or s.get("error")
                           or not finite_nonnegative(s.get("ms")) for s in raw)):
                return "NOT MEASURED"
            if value != sorted(s["ms"] for s in raw)[math.ceil(count * 0.95) - 1]:
                return "NOT MEASURED"
            if (sample.get("passed") is not True or not (value < ceiling if read else value <= ceiling)
                    or any(s.get("routing_error") for s in raw)):
                return "MISS"
    else:
        key = {"standalone persistent processes": "standalone_processes",
               "persistent processes after 1 seat(s)": "processes_added_per_seat",
               "standalone RSS no session": "standalone_idle_rss_bytes",
               "standalone RSS one session": "standalone_rss_bytes"}.get(label)
        value = row.get("count" if budget == "B3" else "rss_bytes")
        ceiling = limits.get(key)
        if not finite_nonnegative(value) or not finite_nonnegative(ceiling):
            return "NOT MEASURED"
        if not (value == ceiling if budget == "B3" else value <= ceiling):
            return "MISS"
    cleanup = row.get("cleanup_errors", [])
    if not isinstance(cleanup, list):
        return "NOT MEASURED"
    return "PASS" if row.get("passed") is True and not cleanup else "MISS"


def invocation(inv, directory, run=None):
    mode, expected = SELECTIONS.get(inv.get("selection"), ("unsupported", set(range(1, 6))))
    entry = {**inv, "mode": mode, "expected": sorted(expected), "results": [],
             "receipt_complete": False, "journeys": {}, "outcome": "UNKNOWN", "problems": [],
             "judge_outcome": "FAIL" if type(inv.get("exit")) is int and inv["exit"] != 0
                              else "PASS" if type(inv.get("exit")) is int and inv["exit"] == 0 else "UNKNOWN"}
    if inv.get("native_receipt"):
        try:
            native = validate_native(inv, directory, run or {})
            if native["exit"] != inv.get("exit") or inv.get("state") != "finished":
                raise ValueError("native invocation differs from its observer receipt")
        except (OSError, ValueError, TypeError) as error:
            entry["problems"].append(str(error))
            entry["judge_outcome"] = "UNKNOWN"
            return entry
    receipt, error = read(directory / inv["output"] / "results.json")
    if error:
        entry["problems"].append("results.json: " + error)
        return entry
    scope = receipt.get("scope")
    selected = scope.get("selected") if isinstance(scope, dict) else None
    rows = receipt.get("results")
    if (receipt.get("platform") != inv.get("platform") or receipt.get("implementation") != "rust"
            or receipt.get("surface") != inv.get("surface")
            or not isinstance(scope, dict) or scope.get("mode") != mode or mode == "unsupported"
            or not isinstance(selected, list) or any(type(number) is not int for number in selected)
            or len(selected) != len(expected) or set(selected) != expected):
        entry["problems"].append("identity, selection or scope mismatch")
        return entry
    if (not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
            or any(type(row.get("journey")) is not int or row.get("result") not in ("PASS", "FAIL") for row in rows)
            or {row["journey"] for row in rows} != expected or len(rows) != len(expected)):
        entry["problems"].append("incomplete or invalid journey rows")
        return entry
    cleanup = receipt.get("cleanup") if mode == "first-hour" else [row.get("cleanup") for row in rows]
    cleanup_known = isinstance(cleanup, list) and (mode == "first-hour" or all(isinstance(x, list) for x in cleanup))
    cleanup_failed = bool(cleanup) if mode == "first-hour" else any(cleanup) if cleanup_known else False
    qualification = receipt.get("qualification")
    budget = receipt.get("budgets")
    behavior_only = (mode == "first-hour" and isinstance(budget, dict) and (
        budget.get("state") == "not run: first-hour behavior scope" or
        budget.get("state") is None and isinstance(qualification, str)
        and qualification.startswith("Five behavior checks only;")))
    qualified = (isinstance(qualification, str) and isinstance(budget, dict)
                 and (behavior_only or qualification == "see journey scope and required budgets"
                      and (mode != "first-hour" or budget.get("state") == "assessed")))
    budget_artifact, budget_error = read(directory / inv["output"] / "budgets.json") if not behavior_only else ({}, None)
    if not behavior_only and (budget_error or budget_artifact.get("profile") != "rust"
                                or not isinstance(budget_artifact.get("measurements"), list)
                                or any(not isinstance(row, dict) or not isinstance(row.get("label"), str)
                                       or type(row.get("passed")) is not bool for row in budget_artifact["measurements"])):
        entry["problems"].append("budget artifact unavailable or invalid: " + str(budget_error))
        budget_error = budget_error or "invalid budget artifact"
    if not behavior_only and not budget_error:
        required = budget.get("required") if isinstance(budget, dict) else None
        labels = {row["label"] for row in budget_artifact["measurements"]}
        if (not isinstance(required, list) or not required or any(not isinstance(label, str) for label in required)
                or not set(required).issubset(labels)
                or budget.get("passed") is True and any(row["passed"] is not True for row in budget_artifact["measurements"])):
            budget_error = "required measurement coverage or verdict differs from the receipt"
            entry["problems"].append(budget_error)
        if mode == "first-hour":
            if (not isinstance(required, list) or len(required) != len(FIRST_HOUR_PROBES)
                    or any(not isinstance(label, str) for label in required)
                    or set(required) != FIRST_HOUR_PROBES):
                budget_error = "first-hour required probes differ from the reporter contract"
                entry["problems"].append(budget_error)
            if isinstance(budget, dict) and budget.get("passed") is True and any(
                    first_hour_probe_result(key, row, budget_artifact.get("limits")) != "PASS"
                    for row in budget_artifact["measurements"] if row["label"] in FIRST_HOUR_PROBES
                    for key, expected_labels in LABELS.items() if row["label"] in expected_labels):
                budget_error = "required first-hour probe is missing a passing measurement"
                entry["problems"].append(budget_error)
    entry.update(results=rows, scope=scope, cleanup=cleanup, qualification=qualification, behavior_only=behavior_only,
                 receipt_complete=budget_error is None and cleanup_known and qualified)
    code = inv.get("exit")
    # Judge exit 1 includes budget misses. Journey verdicts depend only on
    # witnessed behavior and their own cleanup, with receipt identity intact.
    if (cleanup_known and qualified and inv.get("state") == "finished"
            and type(code) is int and code in (0, 1) and not inv.get("error")):
        entry["journeys"] = {str(row["journey"]): "FAIL" if row["result"] == "FAIL" or
            (bool(cleanup) if mode == "first-hour" else bool(row["cleanup"])) else "PASS" for row in rows}
    if type(code) is not int or inv.get("error") or inv.get("state") in {"planned", "running", "timed-out"}:
        entry["problems"].append(inv.get("error", "judge exit not witnessed"))
    elif code != 0 or cleanup_failed or any(row["result"] == "FAIL" for row in rows):
        entry["outcome"] = "FAIL"
        entry["problems"].append(f"judge exit={code}; cleanup_failed={cleanup_failed}; failed_rows=" +
                                 str([row["journey"] for row in rows if row["result"] == "FAIL"]))
    elif not cleanup_known or not qualified or budget_error:
        entry["problems"].append("cleanup or qualification unavailable")
    elif not behavior_only and budget.get("passed") is not True:
        entry["outcome"] = "FAIL"
        entry["problems"].append("required budgets did not pass")
    else:
        entry["outcome"] = "PASS"
    return entry


def summarize(run, directory):
    entries = [invocation(inv, directory, run) for inv in run.get("invocations", [])]
    errors = list(run.get("errors", []))
    errors += [f"{entry['output']}: {problem}" for entry in entries for problem in entry["problems"]]
    terminal = all(entry["receipt_complete"] and entry["outcome"] != "UNKNOWN" for entry in entries)
    complete = bool(entries) and terminal and run.get("state") == "finished" and not run.get("errors")
    outcome = "FAIL" if run.get("errors") or any(entry["judge_outcome"] == "FAIL" or entry["outcome"] == "FAIL" for entry in entries) else "UNKNOWN"
    if complete and all(entry["outcome"] == "PASS" for entry in entries):
        outcome = "PASS"
    interrupted = run.get("state") == "interrupted"
    if interrupted:
        outcome = "INTERRUPTED"
    status = {"state": "interrupted" if interrupted else "complete" if complete else "partial", "complete": complete, "outcome": outcome,
              "producer_state": run.get("state", "unavailable"), "errors": errors, "notes": run.get("annotations", [])}
    tables = []
    for mode in sorted({entry["mode"] for entry in entries} or {"unavailable"}):
        rows = []
        for number, name in enumerate(FIRST_HOUR if mode == "first-hour" else NAMES, 1):
            cells = {}
            for platform in PLATFORMS:
                expected = [entry for entry in entries if entry.get("platform") == platform
                            and entry["mode"] == mode and number in entry["expected"]]
                # A missing/crashed surface remains in its planned mode. It can
                # never disappear behind another surface's passing rows.
                evidence = [{"surface": entry["surface"], "output": entry["output"],
                    "invocation_outcome": entry["outcome"], "exit": entry.get("exit"),
                    "problems": entry["problems"], "row": next((row for row in entry["results"]
                        if row["journey"] == number), None)} for entry in expected]
                values = [entry["journeys"].get(str(number), "INTERRUPTED" if interrupted or
                          entry.get("state") == "timed-out" else "UNKNOWN") for entry in expected]
                state = "NOT RUN" if not expected else "FAIL" if "FAIL" in values else "UNKNOWN"
                if "FAIL" not in values and "INTERRUPTED" in values:
                    state = "INTERRUPTED"
                if expected and all(value == "PASS" for value in values):
                    state = "PASS"
                cells[platform] = {"state": state, "evidence": evidence}
            rows.append({"journey": number, "name": name, "platforms": cells})
        tables.append({"mode": mode, "rows": rows})
    slots = {key: [] for key in LABELS}
    for entry in entries:
        if not entry["receipt_complete"]:
            continue
        measured, error = read(directory / entry["output"] / "budgets.json")
        if error == "absent":
            continue
        if error or measured.get("profile") != "rust" or not isinstance(measured.get("measurements"), list):
            errors.append(entry["output"] + "/budgets.json: " + (error or "invalid profile/measurements"))
            status.update(state="partial", complete=False, outcome="UNKNOWN" if outcome == "PASS" else outcome)
            continue
        for budget, labels in LABELS.items():
            for row in measured["measurements"]:
                if not isinstance(row, dict) or row.get("label") not in labels:
                    continue
                numeric = budget_numbers(budget, row)
                slots[budget].append({"output": entry["output"], "surface": entry["surface"],
                    "platform": entry.get("platform"),
                    "label": row["label"], "numbers": numeric,
                    "box_load": entry.get("box_load"),
                    "sample_state": "observed" if numeric else row.get("state", "unavailable"),
                    "probe_result": first_hour_probe_result(budget, row, measured.get("limits"))
                    if entry["mode"] == "first-hour" and not entry.get("behavior_only")
                    else probe_result(budget, row, measured.get("limits"), numeric),
                    "invocation_outcome": entry["outcome"], "reason": row.get("reason"), "limits": measured.get("limits")})
    gaps = [f"{key}: {label}" for key, labels in LABELS.items() for label in labels
            if not any(row["label"] == label and row["numbers"] for row in slots[key])]
    gaps += ["FULL: independent FULL-write probe unavailable"]
    if not any(entry.get("surface") == "codex" and entry["mode"] == "first-hour"
               and entry["receipt_complete"] and not entry.get("behavior_only") for entry in entries):
        gaps.append("Codex budgets: no validated first-hour budget receipt")
    for entry in entries:
        if entry.get("surface") == "codex" and entry["mode"] == "first-hour" and (
                entry.get("behavior_only") or not entry["receipt_complete"]):
            gaps.append("Codex budgets: " + entry["output"] + " has no validated first-hour budget receipt")
    budgets = []
    for key, probes in slots.items():
        missing = any(gap.startswith(key + ":") for gap in gaps)
        state = "NOT MEASURED"
        if any(p["probe_result"] == "MISS" for p in probes):
            state = "MISS"
        elif not missing and probes and all(p["probe_result"] == "PASS" for p in probes):
            state = "PASS"
        budgets.append({"id": key, "state": state, "probes": probes})
    return {"schema": "se.nightly-proof/v2", "started_at": run["started_at"], "status": status,
            "product": run.get("product"), "judge": run.get("judge"), "tables": tables,
            "budgets": budgets, "gaps": gaps, "invocations": entries}


def grid(report):
    status = report["status"]
    lines = [f"Rust nightly proof — {report['started_at']}", "",
             f"Run: {status['state'].upper()}; outcome: {status['outcome']}; producer: {status['producer_state']}",
             f"Product: `{(report.get('product') or {}).get('commit', 'unavailable')}`",
             f"Judge: `{(report.get('judge') or {}).get('commit', 'unavailable')}`", "",
             "A journey PASS requires witnessed behavior, clean cleanup and a matching scoped receipt; budgets are separate.",
             "Budget measurements and limits are in budgets.json with PASS, MISS or NOT MEASURED verdicts.",
             "INTERRUPTED identifies an interrupted producer or an unfinished journey in that attempt.",
             "UNKNOWN means the configured observation is unavailable; NOT RUN means this platform/journey was not configured.", ""]
    for table in report["tables"]:
        lines += [f"Scope: {table['mode']}", "", "| Journey | Linux | Windows | macOS |", "| --- | --- | --- | --- |"]
        for row in table["rows"]:
            lines.append("| " + row["name"] + " | " + " | ".join(row["platforms"][p]["state"] for p in PLATFORMS) + " |")
        lines.append("")
    if status.get("notes"):
        lines += ["Record corrections:", *[f"- {note}" for note in status["notes"]], ""]
    if status["errors"]:
        lines += ["Run issues:", *[f"- {error}" for error in status["errors"]], ""]
    return "\n".join(lines) + "\n"


def exit_status(report):
    """The producer can finish normally while reporting failed observations."""
    return 0 if report["status"]["outcome"] == "PASS" and report["status"]["complete"] else 1


def publish(directory):
    run, error = read(directory / "run.json")
    if error:
        raise RuntimeError("run.json: " + error)
    report = summarize(run, directory)
    status = report["status"]
    for name, value in [("report.json", report), ("budgets.json", {"schema": "se.nightly-budgets/v2",
        "started_at": report["started_at"], "status": status, "product": report["product"],
        "judge": report["judge"], "budgets": report["budgets"], "gaps": report["gaps"]})]:
        temporary = directory / (name + ".tmp")
        temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
        temporary.replace(directory / name)
    text = grid(report)
    temporary = directory / "grid.md.tmp"
    temporary.write_text(text)
    temporary.replace(directory / "grid.md")
    (directory / "report.md").write_text(text + "\nNumbers and raw samples: budgets.json and original judge receipts.\n\nNamed gaps:\n" +
        "\n".join("- " + gap for gap in report["gaps"]) + "\n")
    return report
