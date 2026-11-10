"""Summarize independent journey receipts without changing their verdicts."""
import json
import math
from pathlib import Path

PLATFORMS = ("linux", "win32", "darwin")
NAMES = ("Install", "Adopt", "Come back", "Two agents", "Remove")
# Labels belong to the independent judge. Retain its limits and raw receipts;
# the scheduler never substitutes its own acceptance thresholds.
LABELS = {
    "B1": ("embedded A/B",),
    "B2": ("embedded A/B",),
    "B3": ("standalone persistent processes", "persistent processes after 1 seat(s)",
           "persistent processes after 2 seat(s)", "embedded A/B"),
    "B4": ("standalone RSS one session",),
    "B5": ("idle no session", "idle one session"),
    "B6": ("idle no session", "idle one session"),
    "B7": ("CLI --version", "CLI contextual read verbs"),
    "B8": ("host restart re-adoption",),
    "B9": ("CLI writes through running host", "in-session kept-open writes",
           "Claude stop hook through running host"),
    "FULL": (),
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
    """Keep numeric paths, including raw samples, but exclude process identities."""
    if type(value) in (int, float):
        return {prefix: value} if math.isfinite(value) else {}
    if isinstance(value, list):
        return {key: number for i, item in enumerate(value)
                for key, number in numbers(item, f"{prefix}[{i}]").items()}
    if isinstance(value, dict):
        return {key: number for name, item in value.items()
                if name not in {"processes", "added", "before", "after", "pid", "parent", "birth"}
                for key, number in numbers(item, f"{prefix}.{name}" if prefix else name).items()}
    return {}


def budget_numbers(budget, row):
    raw = numbers(row)
    selectors = {
        "B1": ("rss_bytes",), "B2": ("startup_ms", "first_request", "bound_ms"),
        "B3": ("count", "added_processes"), "B4": ("rss_bytes",),
        "B5": ("cpu_percent_one_core",), "B6": ("wakeups",),
        "B7": ("reads",), "B8": ("readoption", "readopt", "cutover", "elapsed_ms"),
        "B9": ("writes", "samples", "p95", "ceiling_ms"), "FULL": (),
    }
    return {path: value for path, value in raw.items()
            if any(part in path for part in selectors[budget])}


def summarize(run, directory):
    """Each entry names a fresh invocation and its observed exit, never a latest file."""
    grid = {platform: [] for platform in PLATFORMS}
    budgets = {key: [] for key in LABELS}
    problems = list(run.get("errors", []))
    for invocation in run.get("invocations", []):
        root = directory / invocation["output"]
        receipt, error = read(root / "results.json")
        platform = invocation["platform"]
        if platform not in grid:
            problems.append(f"unsupported platform {platform}")
            continue
        entry = {"output": invocation["output"], "exit": invocation.get("exit"),
                 "surface": invocation["surface"], "selection": invocation["selection"],
                 "state": error or "readable", "results": []}
        if error:
            problems.append(f"{invocation['output']}/results.json: {error}")
        elif receipt.get("platform") != platform or receipt.get("implementation") != "rust":
            entry["state"] = "identity mismatch"
            problems.append(f"{invocation['output']}: receipt platform/implementation mismatch")
        else:
            entry.update(scope=receipt.get("scope"), results=receipt.get("results", []),
                         cleanup=receipt.get("cleanup"), qualification=receipt.get("qualification"))
        if entry["state"] == "readable":
            rows = entry["results"]
            expected = {"first-hour": {1, 2, 3, 4, 5}, "wave-2": {1, 2, 3, 5}}.get(invocation["selection"])
            if (not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
                    or expected is not None and ({row.get("journey") for row in rows} != expected
                                               or len(rows) != len(expected))):
                entry["state"] = "incomplete or invalid journey rows"
                entry["results"] = []
                problems.append(f"{invocation['output']}: incomplete or invalid journey rows")
        grid[platform].append(entry)
        if entry["state"] != "readable":
            continue
        measured, error = read(root / "budgets.json")
        if measured is None:
            if error != "absent":
                problems.append(f"{invocation['output']}/budgets.json: {error}")
            continue
        if measured.get("profile") != "rust":
            problems.append(f"{invocation['output']}/budgets.json: profile mismatch")
            continue
        for budget, labels in LABELS.items():
            for row in measured.get("measurements", []):
                if row.get("label") not in labels:
                    continue
                numeric = budget_numbers(budget, row)
                budgets[budget].append({"output": invocation["output"], "platform": platform,
                    "surface": invocation["surface"], "label": row["label"],
                    "state": "measured" if numeric else row.get("state", "unavailable"),
                    "numbers": numeric, "probe_passed": row.get("passed"),
                    "reason": row.get("reason"), "limits": measured.get("limits")})
    # Keep the two different meanings of row 4 separate. A sequential first-hour
    # restart check cannot qualify the full two-agent messaging journey.
    modes = sorted({entry.get("scope", {}).get("mode", "unavailable")
                    for entries in grid.values() for entry in entries})
    tables = []
    for mode in modes or ["full"]:
        rows = []
        for number, name in enumerate(NAMES, 1):
            cells = {}
            for platform, entries in grid.items():
                evidence = [{"surface": entry["surface"], "output": entry["output"],
                             "result": row.get("result"), "reason": row.get("reason")}
                            for entry in entries if entry.get("scope", {}).get("mode") == mode
                            for row in entry["results"] if row.get("journey") == number]
                cells[platform] = {"state": "FAIL" if any(e["result"] != "PASS" for e in evidence)
                    else "PASS" if evidence else "NOT RUN", "evidence": evidence}
            rows.append({"journey": number, "name": name if mode != "first-hour" else f"First-hour step {number}",
                         "platforms": cells})
        tables.append({"mode": mode, "rows": rows})
    gaps = [f"{key}: {label}" for key, labels in LABELS.items() for label in labels
            if not any(row["label"] == label and row["numbers"] for row in budgets[key])]
    gaps += ["FULL: independent FULL-write probe unavailable",
             "Codex budgets: first-hour behavior selection measures no performance budgets"]
    return {"schema": "se.nightly-proof/v1", "product": run.get("product"), "judge": run.get("judge"),
            "started_at": run["started_at"], "tables": tables,
            "budgets": [{"id": key, "state": "measured" if any(r["numbers"] for r in rows)
                         else "NOT MEASURED", "probes": rows} for key, rows in budgets.items()],
            "errors": problems, "gaps": gaps, "invocations": grid}


def markdown(report):
    lines = [f"Rust nightly proof — {report['started_at']}", "",
             f"Product: `{(report.get('product') or {}).get('commit', 'unavailable')}`", ""]
    for table in report["tables"]:
        lines += [f"Scope: {table['mode']}", "", "| Journey | Linux | Windows | macOS |",
                  "| --- | --- | --- | --- |"]
        for row in table["rows"]:
            lines.append("| " + row["name"] + " | " + " | ".join(
                row["platforms"][platform]["state"] for platform in PLATFORMS) + " |")
        lines.append("")
    lines += ["Numbers and all raw samples: budgets.json and each invocation's budgets.json.", "",
              "| Budget | Measurement |", "| --- | --- |"]
    for budget in report["budgets"]:
        numeric = [f"{probe['surface']} {path}={value}" for probe in budget["probes"]
                   for path, value in probe["numbers"].items() if "samples[" not in path]
        lines.append(f"| {budget['id']} | " + ("; ".join(numeric) if numeric else "NOT MEASURED") + " |")
    lines += ["", "Named gaps:", *[f"- {gap}" for gap in report["gaps"]]]
    if report["errors"]:
        lines += ["", "Invocation errors:", *[f"- {error}" for error in report["errors"]]]
    return "\n".join(lines) + "\n"


def publish(directory):
    run, error = read(directory / "run.json")
    if error:
        raise RuntimeError(f"run.json: {error}")
    report = summarize(run, directory)
    (directory / "report.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    (directory / "report.md").write_text(markdown(report))
    (directory / "grid.md").write_text(markdown(report).split("Numbers and all raw samples:")[0])
    (directory / "budgets.json").write_text(json.dumps({"schema": "se.nightly-budgets/v1",
        "started_at": report["started_at"], "product": report["product"], "judge": report["judge"],
        "budgets": report["budgets"], "gaps": report["gaps"]}, indent=2, allow_nan=False) + "\n")
    return report
