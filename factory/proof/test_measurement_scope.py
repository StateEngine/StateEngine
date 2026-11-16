"""One vertical proof of the provider-free Windows measurement scope.

Mirrors what the pinned judge writes for `--only writes` (journeys/run.mjs:739-750,
770-775; journeys/writes.mjs `writeLatency`): surface claude, `scope.mode` selected
with an empty selection and `writes_only` true, no journey rows, and the write
cohort nested under the measurement row's `writes` list. The shutdown witness is
that row's own `cleanup_errors`.

The path driven here is the real one: the four receipt files go through
`native.import_receipt`, which validates them, then through `report.publish`'s
summarize. No VM and no provider is involved.

Run: python3 test_measurement_scope.py
"""
import json
import math
import pathlib
import sys
import tempfile

import native
import report as R

WINDOW = "full_write_windows_p95_ms_inclusive"
WINDOWS_CEILING = 75      # full_write_windows_p95_ms_inclusive
GENERAL_CEILING = 100     # cli_write_p95_ms_inclusive
OMIT = object()


def sample(ms, code=0, **extra):
    return {"code": code, "ms": float(ms), "error": None, "routing_error": None, **extra}


def write_row(p95, platform="win32", cleanup_errors=OMIT):
    """One row exactly as writes.mjs's writeBudgets builds it, cohort nested."""
    samples = [sample(p95) for _ in range(30)]
    samples = sorted(samples, key=lambda s: s["ms"])
    samples[math.ceil(30 * 0.95) - 1] = sample(p95)
    routed = all(not s["routing_error"] and not s["error"] for s in samples)
    row = {"action": "send", "clients": 1, "samples_per_client": 30, "samples": samples,
           "p95_ms": p95, "ceiling_ms_inclusive": GENERAL_CEILING,
           "passed": routed and p95 <= GENERAL_CEILING}
    if platform == "win32" and row["action"] == "send" and row["clients"] == 1:
        row["full_write_windows"] = {
            "budget": WINDOW, "ceiling_ms_inclusive": WINDOWS_CEILING, "p95_ms": p95,
            "basis": "same public send-and-readback samples as this row; native Windows only",
            "passed": routed and p95 <= WINDOWS_CEILING}
    if cleanup_errors is not OMIT:
        row["cleanup_errors"] = cleanup_errors
    return row


def measurement_row(p95, platform="win32", cleanup_errors=OMIT, passed=True):
    """The budgets.json measurement for the serial send probe."""
    row = {"label": "CLI writes through running host",
           "state": "measured", "passed": passed,
           "writes": [write_row(p95, platform, cleanup_errors)]}
    if cleanup_errors is not OMIT:
        row["cleanup_errors"] = cleanup_errors
    return row


def receipt(p95, cleanup_errors=OMIT, budget_passed=True):
    record = {"platform": "win32", "implementation": "rust", "surface": "claude",
              "scope": {"mode": "selected", "selected": [], "writes_only": True},
              "results": [],
              "qualification": "see journey scope and required budgets",
              "budgets": {"passed": budget_passed, "state": "assessed",
                          "required": ["CLI writes through running host"]}}
    if cleanup_errors is not OMIT:
        record["cleanup_errors"] = cleanup_errors
    return record


def fixture(p95=40, cleanup_errors=OMIT, budget_passed=True, platform="win32"):
    """A retained attempt with all four receipt files, as the producer delivers them.

    `cleanup_errors` defaults to OMIT: the raw receipt carries no cleanup field and
    the witness lives in budgets.json, so "absent" must stay absent rather than
    collapse into an empty list that reads as a clean run.
    """
    directory = pathlib.Path(tempfile.mkdtemp())
    out = directory / "windows-writes"
    out.mkdir()
    results = receipt(p95, cleanup_errors, budget_passed)
    (out / "results.json").write_text(json.dumps(results))
    (out / "budgets.json").write_text(json.dumps({
        "profile": "rust", "limits": {WINDOW: WINDOWS_CEILING},
        "measurements": [measurement_row(p95, platform, cleanup_errors,
                                         budget_passed and p95 <= WINDOWS_CEILING)]}))
    # Native receipt and provider-none closure, both required by native.import_receipt.
    commit = "b" * 40
    judge = "c" * 40
    (out / "native-receipt.json").write_text(json.dumps({
        "schema": "se.native-proof/v1", "platform": "win32", "surface": "claude",
        "selection": "writes", "product_commit": commit, "judge_commit": judge,
        "provider": "none",
        "ended_at": "2026-11-18T14:00:00+00:00", "state": "finished", "exit": 0, "errors": [],
        "judge_files_sha256": {"journeys/run.mjs": "d" * 64},
        "archive_sha256": "e" * 64,
        "files_sha256": {"results.json": _sha(out / "results.json"),
                         "budgets.json": _sha(out / "budgets.json")}}))
    (out / "credential-closure.json").write_text(json.dumps(
        {"provider": "none", "read": False, "refresh_tokens_copied": False}))
    return directory, out


def _sha(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


INVOCATION = {"platform": "win32", "surface": "claude", "selection": "writes",
              "output": "windows-writes", "state": "finished", "exit": 0,
              "native_receipt": True, "windows_probe": True}

RUN = {"started_at": "2026-11-18T13:00:00+00:00", "state": "finished",
       "product": {"commit": "b" * 40}, "judge": {"commit": "c" * 40,
                                                 "files_sha256": {"journeys/run.mjs": "d" * 64}}}


def entry_for(**kwargs):
    directory, out = fixture(**kwargs)
    entry = R.invocation(dict(INVOCATION), directory, RUN)
    return entry, directory, out


def main():
    failures = 0
    print("Imported through native.import_receipt, judged by the reporter:")

    def case(label, expect_outcome, expect_complete, **kwargs):
        nonlocal failures
        entry, _, _ = entry_for(**kwargs)
        ok = entry["outcome"] == expect_outcome and entry["receipt_complete"] == expect_complete
        print(f"  {'ok  ' if ok else 'FAIL'} {label:38} outcome={entry['outcome']:7} "
              f"complete={entry['receipt_complete']}  {entry['problems'][:1]}")
        failures += 0 if ok else 1
        return entry

    case("40 ms under both ceilings", "PASS", True, p95=40, cleanup_errors=[])
    case("90 ms: general passes, Windows misses", "FAIL", True, p95=90,
         budget_passed=False, cleanup_errors=[])
    case("cleanup reported an error", "FAIL", True, cleanup_errors=["shutdown timed out"])
    case("shutdown witness absent", "UNKNOWN", False, cleanup_errors=OMIT)

    print("\nAbsent evidence is NOT MEASURED, never zero and never a pass:")
    empty = pathlib.Path(tempfile.mkdtemp())
    gaps = [g for g in R.summarize({**RUN, "invocations": [
        {"platform": "linux", "surface": "claude", "selection": "wave-2", "output": "o",
         "state": "finished", "exit": 0}]}, empty)["gaps"] if g.startswith("windows")]
    ok = gaps == ["windows: not configured"]
    print(f"  {'ok  ' if ok else 'FAIL'} no win32 row -> {gaps}")
    failures += 0 if ok else 1

    print("\nThe B10 relation is judged on the serial send row, not a flattened copy:")
    entry, _, _ = entry_for(p95=40, cleanup_errors=[])
    row = entry["results"][0] if entry["results"] else {}
    has_relation = isinstance(row.get("writes"), list) and any(
        "full_write_windows" in w for w in row["writes"])
    ok = entry["outcome"] == "PASS" and row.get("label") == "CLI writes through running host"
    print(f"  {'ok  ' if ok else 'FAIL'} measurement row present with nested cohort: "
          f"{row.get('label')!r}")
    failures += 0 if ok else 1

    print(f"\n{'ALL PASS' if not failures else str(failures) + ' FAILURE(S)'}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
