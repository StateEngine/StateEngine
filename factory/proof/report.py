"""Summarize independent receipts; incomplete evidence never becomes a pass."""
import json
import math
from pathlib import Path

PLATFORMS = ("linux", "win32", "darwin")
NAMES = ("Install", "Adopt", "Come back", "Two agents", "Remove")
FIRST_HOUR = ("Install", "Adopt", "Work", "Restart and recall", "Remove")
SELECTIONS = {"first-hour": ("first-hour", {1, 2, 3, 4, 5}),
              "wave-2": ("rust-wave-2", {1, 2, 3, 5})}
LABELS = {
    "B1": ("embedded A/B",), "B2": ("embedded A/B",),
    "B3": ("standalone persistent processes", "persistent processes after 1 seat(s)",
           "persistent processes after 2 seat(s)", "embedded A/B"),
    "B4": ("standalone RSS one session", "W5 post-task RSS journey 2",
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


def invocation(inv, directory):
    mode, expected = SELECTIONS.get(inv.get("selection"), ("unsupported", set(range(1, 6))))
    entry = {**inv, "mode": mode, "expected": sorted(expected), "results": [],
             "receipt_complete": False, "journeys": {}, "outcome": "UNKNOWN", "problems": [],
             "judge_outcome": "FAIL" if type(inv.get("exit")) is int and inv["exit"] != 0
                              else "PASS" if type(inv.get("exit")) is int and inv["exit"] == 0 else "UNKNOWN"}
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
    qualified = (isinstance(qualification, str) and isinstance(budget, dict)
                 and (qualification.startswith("Five behavior checks only;") if mode == "first-hour"
                      else qualification == "see journey scope and required budgets"))
    budget_artifact, budget_error = read(directory / inv["output"] / "budgets.json") if mode != "first-hour" else ({}, None)
    if mode != "first-hour" and (budget_error or budget_artifact.get("profile") != "rust"
                                or not isinstance(budget_artifact.get("measurements"), list)
                                or any(not isinstance(row, dict) or not isinstance(row.get("label"), str)
                                       or type(row.get("passed")) is not bool for row in budget_artifact["measurements"])):
        entry["problems"].append("budget artifact unavailable or invalid: " + str(budget_error))
        budget_error = budget_error or "invalid budget artifact"
    if mode != "first-hour" and not budget_error:
        required = budget.get("required") if isinstance(budget, dict) else None
        labels = {row["label"] for row in budget_artifact["measurements"]}
        if (not isinstance(required, list) or not required or any(not isinstance(label, str) for label in required)
                or not set(required).issubset(labels)
                or budget.get("passed") is True and any(row["passed"] is not True for row in budget_artifact["measurements"])):
            budget_error = "required measurement coverage or verdict differs from the receipt"
            entry["problems"].append(budget_error)
    entry.update(results=rows, scope=scope, cleanup=cleanup, qualification=qualification,
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
    elif mode != "first-hour" and budget.get("passed") is not True:
        entry["outcome"] = "FAIL"
        entry["problems"].append("required budgets did not pass")
    else:
        entry["outcome"] = "PASS"
    return entry


def summarize(run, directory):
    entries = [invocation(inv, directory) for inv in run.get("invocations", [])]
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
                    "label": row["label"], "numbers": numeric,
                    "sample_state": "observed" if numeric else row.get("state", "unavailable"),
                    "probe_result": "NOT MEASURED" if not numeric or row.get("state") == "unavailable" else
                                    "PASS" if row.get("passed") is True else "MISS" if row.get("passed") is False else "NOT MEASURED",
                    "invocation_outcome": entry["outcome"], "reason": row.get("reason"), "limits": measured.get("limits")})
    gaps = [f"{key}: {label}" for key, labels in LABELS.items() for label in labels
            if not any(row["label"] == label and row["numbers"] for row in slots[key])]
    gaps += ["FULL: independent FULL-write probe unavailable", "Codex budgets: first-hour selection measures no budgets"]
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
