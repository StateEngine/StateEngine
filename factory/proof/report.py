"""Summarize independent receipts; incomplete evidence never becomes a pass."""
import json
import math
from pathlib import Path
from native import validate as validate_native
from matrix_adapter import observation as matrix_observation
from remote_report import summarize as remote_summary
from budget_context import observation as machine_context, render as render_budget_context

PLATFORMS = ("linux", "win32", "darwin")
NAMES = ("Install", "Adopt", "Come back", "Two agents", "Remove")
FIRST_HOUR = ("Install", "Adopt", "Work", "Restart and recall", "Remove")
FIRST_HOUR_PROBES = frozenset((
    "CLI --version", "CLI contextual read verbs", "CLI writes through running host",
    "standalone persistent processes", "idle no session", "standalone RSS no session",
    "persistent processes after 1 seat(s)", "standalone RSS one session", "idle one session"))
SELECTIONS = {"writes": ("measurement", set()),
              "first-hour": ("first-hour", {1, 2, 3, 4, 5}),
              "wave-2": ("rust-wave-2", {1, 2, 3, 5}),
              "remote": ("remote", {1}),
              "4": ("selected", {4})}
# Budgets that only one platform can answer, and therefore only that platform's
# rows may feed them. `B10` is a Windows full-write ceiling measured from the same
# CLI-write samples; a Linux or macOS row carries no Windows relation, and its
# honest "not measured" is neither a missing probe nor a vote against a Windows
# result.
PLATFORM_BUDGETS = {"B10": "win32"}


class ProbeContext:
    """What one invocation's budget rows may be judged against.

    Built once, at the receipt boundary, from the platform the receipt itself was
    verified to have (`invocation()` already refuses a receipt whose platform
    differs from the requested one). Every consumer takes this value rather than
    re-reading a row or re-deriving the platform, because applicability decided in
    more than one place is what drifted three times before.

    `platform` is the verified platform, or None when it is not yet established;
    None applies to nothing platform-specific rather than to everything.
    """

    __slots__ = ("platform",)

    def __init__(self, platform):
        self.platform = platform

    def __repr__(self):
        # Never let a context print its way into a report or a diagnostic.
        return f"ProbeContext({self.platform!r})"

    def applies(self, budget):
        """Whether this context's rows may feed `budget` at all."""
        if budget not in PLATFORM_BUDGETS:
            return True
        return self.platform == PLATFORM_BUDGETS[budget]

    def required(self, budget):
        """Whether `budget` must pass for this receipt to be complete.

        A platform-only budget is never required coverage: it can only be measured
        in one venue, so its absence or its miss is a fact about that venue, not a
        missing required probe. It is still judged wherever it applies — a real
        Windows miss stays a MISS with its own probe rather than being discarded
        along with an otherwise valid receipt.
        """
        return budget not in PLATFORM_BUDGETS
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
           "Claude stop hook through running host"),
    "B10": ("CLI writes through running host",), "FULL": (),
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
                                "samples", "rows", "agent", "event", "arguments", "receipt", "machine_context"}
                for key, number in numbers(item, f"{prefix}.{name}" if prefix else name).items()}
    return {}


def budget_numbers(budget, row):
    selectors = {
        "B1": ("rss_bytes",), "B2": ("startup_ms", "first_request", "bound_ms"),
        "B3": ("count", "added_processes"), "B4": ("rss_bytes",),
        "B5": ("cpu_percent_one_core",), "B6": ("wakeups",),
        "B7": ("reads",), "B8": ("readoption", "readopt", "cutover", "elapsed_ms"),
        "B9": ("writes", "samples", "p95", "ceiling_ms"),
        "B10": ("writes", "samples", "p95", "ceiling_ms"), "FULL": (),
    }
    return {path: value for path, value in numbers(row).items()
            if any(part in path for part in selectors[budget])
            and (budget not in {"B2", "B7", "B9"} or path.endswith(("_ms", ".ms")) or ".p95_ms." in path)}



def windows_full_write_result(row, limits, context=None):
    """B10: native Windows serial send against the Windows full-write ceiling.

    The producer reports this budget as a named relation on the existing serial
    send row, so it reuses that row's samples rather than adding a second
    clients=1 entry: the write consumer reads exactly one serial and one
    eight-client cohort, and an extra entry would make both unmeasurable. Only a
    native Windows row that carries the relation can answer, and the relation
    must repeat the row's own p95 and describe the cohort it rides on.
    """
    # Applicability comes from the verified invocation context, never from a tag
    # the row carries: a Windows receipt with an unrelated platform tag on one row
    # is still a Windows receipt.
    if context is not None and not context.applies("B10"):
        return "NOT MEASURED"
    writes = row.get("writes")
    if not isinstance(writes, list):
        return "NOT MEASURED"
    ceiling_key = "full_write_windows_p95_ms_inclusive"
    if not isinstance(limits, dict):
        return "NOT MEASURED"
    ceiling = limits.get(ceiling_key)
    if not finite_nonnegative(ceiling):
        return "NOT MEASURED"
    seen = False
    for sample in writes:
        if not isinstance(sample, dict):
            continue
        relation = sample.get("full_write_windows")
        if relation is None:
            continue
        seen = True
        if not isinstance(relation, dict):
            return "NOT MEASURED"
        raw, value = sample.get("samples"), sample.get("p95_ms")
        count = 30 * sample.get("clients", 0) if type(sample.get("clients")) is int else 0
        # The relation is judged on the row it rides on, and it may not drift from it.
        if (sample.get("action") != "send" or sample.get("clients") != 1 or not count
                or relation.get("budget") != ceiling_key
                or relation.get("ceiling_ms_inclusive") != ceiling
                or not finite_nonnegative(value) or relation.get("p95_ms") != value
                or not isinstance(raw, list) or len(raw) != count
                or not finite_nonnegative(sample.get("ceiling_ms_inclusive"))
                or any(not isinstance(s, dict) or type(s.get("code")) is not int
                       or s["code"] != 0 or s.get("error") or s.get("routing_error")
                       or not finite_nonnegative(s.get("ms")) for s in raw)):
            return "NOT MEASURED"
        if value != sorted(s["ms"] for s in raw)[math.ceil(count * 0.95) - 1]:
            return "NOT MEASURED"
        if relation.get("passed") is not True or sample.get("passed") is not True or value > ceiling:
            return "MISS"
    return "PASS" if seen else "NOT MEASURED"


def probe_result(budget, row, limits, numeric, context=None):
    # A row that measured nothing is refused before any budget-specific
    # judgement, so retained samples can never be published as a verdict.
    if not numeric or state_measured_nothing(row):
        return "NOT MEASURED"
    if budget == "B10":
        return windows_full_write_result(row, limits, context)
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


# Every state a producer uses to say it measured nothing. A row carrying any of
# these must never publish a verdict, whatever samples it still holds. This is one
# definition on purpose: two consumers naming different sets is exactly how a B10
# row marked unreadable published PASS while the same row through first-hour did
# not.
NOT_MEASURED_STATES = frozenset((
    "unavailable", "not measured", "unreadable", "absent", "not reached"))


def state_measured_nothing(row):
    """Whether the producer said this row holds no measurement.

    A state that is absent, or is any string in `NOT_MEASURED_STATES`, means the
    row measured nothing. A non-string state is a malformed row rather than a
    measurement, so it is refused too.
    """
    state = row.get("state")
    if state is None:
        return False
    if not isinstance(state, str):
        return True
    return state in NOT_MEASURED_STATES


def finite_nonnegative(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def first_hour_probe_result(budget, row, limits, context=None):
    """Validate current first-hour measurements without changing legacy receipts.

    `context` is the one applicability value for this invocation. Without it the
    budget is judged as before, which keeps legacy callers working; with it, a
    row that cannot answer this budget is not judged at all.
    """
    if context is not None and not context.applies(budget):
        return "NOT MEASURED"
    if not isinstance(limits, dict) or state_measured_nothing(row):
        return "NOT MEASURED"
    if budget in {"B5", "B6"}:
        return probe_result(budget, row, limits, budget_numbers(budget, row))
    label = row.get("label")
    if budget == "B10":
        return windows_full_write_result(row, limits)
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
    """Summarize one invocation.

    The returned entry is emitted verbatim into report.json, so it may only hold
    JSON values. The applicability context is deliberately *not* stored on it;
    `invocation_context()` rebuilds it from the same verified receipt platform.
    """
    mode, expected = SELECTIONS.get(inv.get("selection"), ("unsupported", set(range(1, 6))))
    entry = {**inv, "mode": mode, "expected": sorted(expected), "results": [],
             "receipt_complete": False, "journeys": {}, "outcome": "UNKNOWN", "problems": [],
             "judge_outcome": "FAIL" if type(inv.get("exit")) is int and inv["exit"] != 0
                              else "PASS" if type(inv.get("exit")) is int and inv["exit"] == 0 else "UNKNOWN"}
    closure = inv.get("credential_closure")
    unreadable_scan = isinstance(closure, dict) and closure.get("state") == "unreadable"
    if unreadable_scan:
        entry["problems"].append(closure.get("error", "automation-output-scan-unreadable: input unspecified"))
        entry["outcome"] = "FAIL"
    if inv.get("remote_probe"):
        receipt, error = read(directory / inv["output"] / "remote.json")
        if error:
            entry["problems"].append("remote.json: " + error)
            return entry
        if inv.get("state") != "finished":
            entry["problems"].append("remote producer exit not witnessed")
            return entry
        return remote_summary(entry, receipt, run or {})
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
    # A measurement scope runs probes, not journeys: the judge records it as
    # `writes_only` with an empty selection, and there are no journey rows to check.
    # The judge marks this scope `writes_only` beside a mode of `selected`, so the
    # flag is the identity — not a mode name it never writes.
    measurement = (isinstance(scope, dict) and scope.get("writes_only") is True)
    if measurement and mode == "first-hour":
        entry["problems"].append("measurement scope reached a first-hour invocation")
        return entry
    if (receipt.get("platform") != inv.get("platform") or receipt.get("implementation") != "rust"
            or receipt.get("surface") != inv.get("surface")
            or not isinstance(scope, dict) or scope.get("mode") != mode or mode == "unsupported"
            or not isinstance(selected, list) or any(type(number) is not int for number in selected)
            or len(selected) != len(expected) or set(selected) != expected):
        if not (measurement and selected == []):
            entry["problems"].append("identity, selection or scope mismatch")
            return entry
    if measurement:
        # A measurement scope has no journey rows, but it is judged by the same rule
        # as any other receipt: failed cleanup, an unqualified receipt, a missing
        # budget artifact or a budget miss must still refuse. Only the journey-row
        # checks are exempt, because there are no journeys to check.
        if not isinstance(rows, list) or rows:
            entry["problems"].append("measurement scope reported journey rows")
            return entry
        entry["mode"] = "measurement"
        # A measurement scope has no journeys, so its expected set is empty. It must
        # stay INSIDE this branch: at function level it would wipe the journey
        # expectations every other scope relies on.
        expected = set()
    # One applicability value for everything downstream, built here because this
    # is where the receipt's platform became verified rather than asserted.
    context = ProbeContext(receipt.get("platform"))
    if (not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
            or any(type(row.get("journey")) is not int or row.get("result") not in ("PASS", "FAIL") for row in rows)
            or {row["journey"] for row in rows} != expected or len(rows) != len(expected)):
        entry["problems"].append("incomplete or invalid journey rows")
        return entry
    # A measurement scope's shutdown evidence is the write measurement's own
    # `cleanup_errors` inside budgets.json. The raw results.json carries no cleanup
    # field at all, so a top-level list here would have to be invented — and an
    # invented empty list is a clean run nothing witnessed.
    cleanup, cleanup_known = (None, False)
    if mode == "measurement":
        artifact, artifact_error = read(directory / inv["output"] / "budgets.json")
        witness = [row for row in (artifact or {}).get("measurements") or []
                   if isinstance(row, dict) and row.get("label") == "CLI writes through running host"]
        if not artifact_error and len(witness) == 1 and isinstance(witness[0].get("cleanup_errors"), list):
            cleanup, cleanup_known = witness[0]["cleanup_errors"], True
    elif mode == "first-hour":
        cleanup = receipt.get("cleanup")
        cleanup_known = isinstance(cleanup, list)
    else:
        cleanup = [row.get("cleanup") for row in rows]
        cleanup_known = all(isinstance(x, list) for x in cleanup)
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
                    first_hour_probe_result(key, row, budget_artifact.get("limits"), context) != "PASS"
                    for row in budget_artifact["measurements"] if row["label"] in FIRST_HOUR_PROBES
                    for key, expected_labels in LABELS.items()
                    if row["label"] in expected_labels
                    and context.applies(key) and context.required(key)):
                budget_error = "required first-hour probe is missing a passing measurement"
                entry["problems"].append(budget_error)
    # A measurement scope's published rows are its budget measurements. Leaving
    # `results` empty hides B10 from every table, which is the same as measuring
    # nothing even when the number exists.
    published = ([row for row in (budget_artifact or {}).get("measurements") or []
                  if isinstance(row, dict) and row.get("label") in FIRST_HOUR_PROBES]
                 if mode == "measurement" else rows)
    entry.update(results=published, scope=scope, cleanup=cleanup,
                 qualification=qualification, behavior_only=behavior_only,
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
    if unreadable_scan:
        entry["outcome"] = "FAIL"
    return entry


def invocation_context(entry):
    """The applicability context for one summarized invocation.

    Derived from the platform `invocation()` already verified against the receipt.
    It is a judgement input, never a report value: keeping it out of the entry is
    what lets the entry be JSON-serialized unchanged.
    """
    return ProbeContext(entry.get("platform"))


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
        names = ("Connect, launch, live output, message, reconnect",) if mode == "remote" else FIRST_HOUR if mode == "first-hour" else NAMES
        for number, name in enumerate(names, 1):
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
        if entry.get("remote_probe"):
            continue
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
                slot_context = invocation_context(entry)
                slots[budget].append({"output": entry["output"], "surface": entry["surface"],
                    "platform": entry.get("platform"), "context": slot_context,
                    "label": row["label"], "numbers": numeric,
                    "box_load": entry.get("box_load"),
                    "machine_context": machine_context(row, entry.get("platform")),
                    "sample_state": "observed" if numeric else row.get("state", "unavailable"),
                    "probe_result": first_hour_probe_result(budget, row, measured.get("limits"), slot_context)
                    if entry["mode"] == "first-hour" and not entry.get("behavior_only")
                    else probe_result(budget, row, measured.get("limits"), numeric, slot_context),
                    "invocation_outcome": entry["outcome"], "reason": row.get("reason"), "limits": measured.get("limits")})
    # A budget that no invocation could answer in this run is a named gap only
    # when some invocation was eligible to answer it. Asking for a Windows number
    # from a Linux-only run would be a gap the run could never close.
    eligible = {key: any(invocation_context(entry).applies(key) for entry in entries
                         if entry.get("receipt_complete"))
                for key in LABELS}
    gaps = [f"{key}: {label}" for key, labels in LABELS.items() for label in labels
            if eligible[key]
            and not any(row["label"] == label and row["numbers"] for row in slots[key])]
    gaps += ["FULL: independent FULL-write probe unavailable"]
    # A Windows budget that is absent must say why. "Not configured" and
    # "configured but no attempt in the custody window" are different facts, and
    # both are NOT MEASURED, never zero.
    windows_planned = any(entry.get("platform") == "win32" for entry in entries)
    windows_measured = any(entry.get("platform") == "win32" and entry.get("receipt_complete")
                           and not entry.get("behavior_only") for entry in entries)
    if not windows_planned:
        gaps.append("windows: not configured")
    elif not windows_measured:
        # A refusal's cause sits on the entry itself (`error`) or in its `problems`,
        # not on a result row. Reporting an attempted-but-refused run as "no attempt"
        # states a false fact, so both places are read.
        reasons = sorted({str(value)
                          for entry in entries if entry.get("platform") == "win32"
                          for value in [entry.get("error"), *(entry.get("problems") or []),
                                        *(row.get("error") or row.get("reason")
                                          for row in (entry.get("results") or []))]
                          if value})
        detail = "; ".join(reasons) if reasons else "no Windows attempt in the custody window"
        gaps.append("windows: " + detail)
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
        # A budget that only one platform answers is decided by that platform's
        # rows alone. Rows from elsewhere are not weaker votes or missing probes:
        # they are not evidence about this budget, so they never reach it.
        applicable = [p for p in probes if p["context"].applies(key)]
        state = "NOT MEASURED"
        if any(p["probe_result"] == "MISS" for p in applicable):
            state = "MISS"
        elif not missing and applicable and all(p["probe_result"] == "PASS" for p in applicable):
            state = "PASS"
        # The context travels with the probe while it is being decided and is not
        # serialized: it is a judgement input, not a measurement.
        budgets.append({"id": key, "state": state,
                        "probes": [{k: v for k, v in probe.items() if k != "context"}
                                   for probe in applicable]})
    matrix = matrix_observation(run, directory)
    if matrix is not None:
        status['errors'].extend('harness matrix: ' + value for value in matrix['errors'])
        if not matrix['complete'] and not interrupted:
            status.update(state='partial', complete=False)
        if matrix['outcome'] == 'FAIL' and not interrupted:
            status['outcome'] = 'FAIL'
        elif matrix['outcome'] != 'PASS' and status['outcome'] == 'PASS':
            status['outcome'] = 'UNKNOWN'
    return {"schema": "se.nightly-proof/v2", "started_at": run["started_at"], "status": status,
            "harness_matrix": matrix,
            "product": run.get("product"), "judge": run.get("judge"), "tables": tables,
            "budgets": budgets, "gaps": gaps, "invocations": entries,
            "remote_timings": [{"surface": entry["surface"], "platform": entry["platform"],
                                "output": entry["output"], "timings": entry.get("remote_timings", {})}
                               for entry in entries if entry.get("remote_probe")]}


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
    lines += render_budget_context(report["budgets"])
    if report.get("remote_timings"):
        lines += ["Remote timings (milliseconds; clock estimates retain their qualification):", "",
                  "| Surface | Attach | Pending echo | Live output | Reconnect |", "| --- | --- | --- | --- | --- |"]
        for row in report["remote_timings"]:
            values = []
            for name in ("attach", "pending_echo", "live_output", "reconnect"):
                sample = row["timings"].get(name, {})
                bracket = ("; source bracket=" + str(sample["source_bracket_us"]) + " us"
                           if "source_bracket_us" in sample else "")
                values.append(str(round(sample["milliseconds"], 3)) + " (n=" + str(sample["n"]) + "; " +
                              sample.get("qualification", "unavailable") + bracket + ")"
                              if sample.get("state") == "MEASURED" else "NOT MEASURED")
            lines.append("| " + row["surface"] + " | " + " | ".join(values) + " |")
        lines.append("")
    matrix = report.get('harness_matrix')
    if matrix is not None:
        lines += ['', '| Harness smoke | Linux | Windows | macOS |', '| --- | --- | --- | --- |']
        for row in matrix['rows']:
            lines.append('| ' + row['harness'] + ' | ' + ' | '.join(
                row['platforms'][platform]['result'] for platform in PLATFORMS) + ' |')
        lines += ['', matrix.get('qualification') or 'Native matrix observation unavailable.', '']
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
        "judge": report["judge"], "budgets": report["budgets"], "gaps": report["gaps"],
        "remote_timings": report["remote_timings"]})]:
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
