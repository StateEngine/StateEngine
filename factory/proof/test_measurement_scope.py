"""One vertical proof of the provider-free Windows measurement scope.

It mirrors what the pinned judge actually writes for `--only writes`
(journeys/run.mjs:739-750, 770-775): surface claude, `scope.mode` selected with an
empty selection and `writes_only` true, no journey rows, and the shutdown witness in
the write measurement's own `cleanup_errors`. No VM and no provider is involved, so
this can run anywhere the reporter runs.

Run: python3 test_measurement_scope.py
"""
import json
import math
import pathlib
import sys
import tempfile

import report as R

WINDOW = "full_write_windows_p95_ms_inclusive"
CEILING = 75


OMIT = object()


def write_row(p95, passed, cleanup_errors):
    """The serial send row carrying the Windows relation, as writes.mjs builds it."""
    samples = [{"code": 0, "ms": float(p95), "error": None, "routing_error": None}
               for _ in range(30)]
    samples = sorted(samples, key=lambda s: s["ms"])
    samples[math.ceil(30 * 0.95) - 1]["ms"] = float(p95)
    row = {"label": "CLI writes through running host", "action": "send", "clients": 1,
           "samples": samples, "p95_ms": p95, "ceiling_ms_inclusive": CEILING,
           "passed": passed,
           "full_write_windows": {"budget": WINDOW, "ceiling_ms_inclusive": CEILING,
                                  "p95_ms": p95, "passed": passed}}
    if cleanup_errors is not OMIT:
        row["cleanup_errors"] = cleanup_errors
    return row


def receipt(p95, cleanup_errors, budget_passed=True):
    record = {"platform": "win32", "implementation": "rust", "surface": "claude",
              "scope": {"mode": "selected", "selected": [], "writes_only": True},
              "results": [],
              "qualification": "see journey scope and required budgets",
            "budgets": {"passed": budget_passed, "state": "assessed",
                        "required": ["CLI writes through running host"]}}
    # The raw receipt carries no cleanup field at all; the witness lives in budgets.
    if cleanup_errors is not OMIT:
        record["cleanup_errors"] = cleanup_errors
    return record


def fixture(p95=40, cleanup_errors=None, budget_passed=True):
    directory = pathlib.Path(tempfile.mkdtemp())
    out = directory / "windows-writes"
    out.mkdir()
    cleanup_errors = [] if cleanup_errors is None else cleanup_errors
    (out / "results.json").write_text(json.dumps(receipt(p95, cleanup_errors, budget_passed)))
    (out / "budgets.json").write_text(json.dumps({
        "profile": "rust", "limits": {WINDOW: CEILING},
        "measurements": [write_row(p95, budget_passed and p95 <= CEILING, cleanup_errors)]}))
    return directory


INVOCATION = {"platform": "win32", "surface": "claude", "selection": "writes",
              "output": "windows-writes", "state": "finished", "exit": 0}


def check(label, expected_outcome, expected_complete, **kwargs):
    entry = R.invocation(dict(INVOCATION), fixture(**kwargs))
    ok = entry["outcome"] == expected_outcome and entry["receipt_complete"] == expected_complete
    print(f"  {'ok  ' if ok else 'FAIL'} {label:34} outcome={entry['outcome']:7} "
          f"complete={entry['receipt_complete']}")
    return ok, entry


def main():
    failures = 0
    print("B10 verdict through the real reporter, on the judge's real receipt shape:")
    for label, outcome, complete, kwargs in (
            ("40 ms under the 75 ceiling", "PASS", True, {"p95": 40}),
            ("90 ms over the 75 ceiling", "FAIL", True, {"p95": 90, "budget_passed": False}),
            ("cleanup reported an error", "FAIL", True, {"cleanup_errors": ["shutdown timed out"]}),
            ("shutdown witness absent", "UNKNOWN", False, {"cleanup_errors": OMIT})):
        ok, _ = check(label, outcome, complete, **kwargs)
        failures += 0 if ok else 1

    print("\nAbsent evidence is NOT MEASURED, never zero and never a pass:")
    entry = R.invocation(dict(INVOCATION), fixture(p95=40))
    # No win32 row at all: the report must say why, not report zero.
    empty = pathlib.Path(tempfile.mkdtemp())
    gaps = [g for g in R.summarize({"started_at": "2026-11-18T13:00:00+00:00", "state": "finished",
                                    "product": {"commit": "b" * 40}, "judge": {"commit": "c" * 40},
                                    "invocations": [{"platform": "linux", "surface": "claude",
                                                     "selection": "wave-2", "output": "o",
                                                     "state": "finished", "exit": 0}]},
                                   empty)["gaps"] if g.startswith("windows")]
    ok = gaps == ["windows: not configured"]
    print(f"  {'ok  ' if ok else 'FAIL'} no win32 row -> {gaps}")
    failures += 0 if ok else 1

    print("\nA journey row set is still refused for this scope:")
    directory = fixture(p95=40)
    (directory / "windows-writes" / "results.json").write_text(json.dumps({
        **receipt(40, []), "results": [{"journey": 1, "result": "PASS"}]}))
    entry = R.invocation(dict(INVOCATION), directory)
    ok = entry["receipt_complete"] is False
    print(f"  {'ok  ' if ok else 'FAIL'} journey rows refused: complete={entry['receipt_complete']}")
    failures += 0 if ok else 1

    print(f"\n{'ALL PASS' if not failures else str(failures) + ' FAILURE(S)'}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
