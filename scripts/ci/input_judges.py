"""Name unavailable external judge inputs without suppressing configured failures."""
import json
import os
from pathlib import Path
import sys


def requirements():
    # These tests remain compiled. Only their external fixture producers are optional.
    groups = [
        ("secode_selectors", None, ("SE_SELECTOR_SE",)),
        ("w3_lifecycle_independent", None, ("SE_W3_SE_BIN",)),
        ("w3_realhost_independent", None, ("SE_W3_SE_BIN",)),
        ("w3_realhost_independent", "native_task::native_secode_task_captures_the_judge_nonce_through_public_surfaces",
         ("SE_W3_NATIVE_DRIVER", "SE_W3_SECODE_SERVER", "SE_W3_PRODUCT_COMMIT")),
    ]
    if sys.platform.startswith("linux"):
        groups += [
            ("embedded_shutdown_independent", None, ("SE_SHUTDOWN_JUDGE_SE",)),
            ("h13_native_lifecycle_judge", None, ("JUDGE_H13_ROOT", "JUDGE_H13_SE")),
            ("h14_generation_judge", None, ("JUDGE_H14_ROOT", "JUDGE_H14_SE")),
            ("runtime_status_independent", None, ("SE_RUNTIME_JUDGE_SE", "SE_RUNTIME_JUDGE_OUT")),
        ]
    return groups


def detachment_venue(root: Path):
    """Selections whose precondition this venue cannot supply, named as not run.

    A hosted Windows runner wraps the job in a job object that forbids
    breakaway, so no same-user detached broker can exist there. Those checks
    stay compiled and are reported by name here; any other venue excludes
    nothing and runs them.
    """
    if not (sys.platform == "win32"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"):
        return []
    reason = ("the hosted runner wraps this job in a job object that forbids "
              "breakaway, so no same-user detached broker can exist")
    # The first two are nextest selections, excluded from the run. The third is
    # a case inside a custom harness: the harness itself still runs and reports
    # its other cases, so only the report records the skip.
    selections = [
        ("se", "breakaway_refusal",
         "eligible_broker_runtime_outlives_strict_job_and_public_down_closes_it",
         "se::breakaway_refusal::eligible_broker_runtime_outlives_strict_job_and_public_down_closes_it"),
        ("se", "host_e3",
         "private_startup_serves_and_retires",
         "se::host_e3::private_startup_serves_and_retires"),
    ]
    # Every trial in that harness launches a detached native child, so the
    # whole ordinary set is skipped too, not only the broker case.
    harness_records = [
        {"judge": f"se-native-proc::bootstrap_stderr::{case}",
         "status": "not_run", "reason": reason}
        # The names are the harness's own modes; `refuse` runs twice, which is
        # why the ordinary set is seven trials and not six.
        for case in (
            "broker",
            "refuse",
            "flood",
            "await-commit",
            "retained-await",
            "live-read",
            "inheritance",
        )
    ] + [
        # Cases inside se::host_e3 that start a detached native host, plus the
        # one subcase of a case that otherwise runs: the listener/hook case keeps
        # its embedded coverage and names only its detached cold-capture part.
        {"judge": f"se::host_e3::{case}", "status": "not_run", "reason": reason}
        for case in (
            "private_startup_serves_and_retires",
            "restart_after_crash",
        )
    ] + [
        {"judge": "se::host_e3::listener_message_working_and_hook::cold_capture",
         "status": "not_run", "reason": reason}
    ]
    excluded, records = [], []
    for package, binary, test, label in selections:
        excluded.append(f"(package(={package}) & binary(={binary}) & test(={test}))")
        records.append({"judge": label, "status": "not_run", "reason": reason})
    records.extend(harness_records)
    return [(excluded, records)]


def venue_unavailable(root: Path):
    """Venue selections to exclude, recorded in the same report.

    Applied on every Windows full run, not only with all features: the venue
    cannot supply these preconditions regardless of the feature set.
    """
    excluded, records = [], []
    for selectors, rows in detachment_venue(root):
        excluded.extend(selectors)
        records.extend(rows)
    if records:
        _append_report(root, records)
    return excluded


def _append_report(root: Path, records):
    report = root / "ci-reports/input-judges.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if report.is_file():
        try:
            existing = json.loads(report.read_text(encoding="utf-8")).get("not_run", [])
        except (OSError, ValueError):
            # A broken earlier report stays broken: rewrite from the known facts
            # rather than inventing completion.
            existing = []
    merged = {item.get("judge"): item for item in existing}
    for item in records:
        merged[item.get("judge")] = item
    report.write_text(
        json.dumps({"schema": "ci-input-judges/v1", "not_run": list(merged.values())},
                   indent=2) + "\n",
        encoding="utf-8",
    )


def unavailable(root: Path):
    excluded = []
    records = []
    for binary, test, names in requirements():
        missing = [name for name in names if not os.environ.get(name)]
        if not missing:
            continue
        selector = f"(package(=se-host) & binary(={binary})"
        label = f"se-host::{binary}"
        if test:
            selector += f" & test(={test})"
            label += "::" + test
        excluded.append(selector + ")")
        records.append({"judge": label, "status": "not_run", "missing_inputs": missing})
    # Archive extraction requires an absent target directory, even before tests run.
    _append_report(root, records)
    for record in records:
        if "missing_inputs" in record:
            detail = "missing input " + ", ".join(record["missing_inputs"])
        else:
            detail = record["reason"]
        print("NOT RUN " + record["judge"] + ": " + detail, file=sys.stderr, flush=True)
    print(f"External-input judges: {len(records)} not-run selections; configured tests retain ordinary failure status",
          file=sys.stderr, flush=True)
    return excluded
