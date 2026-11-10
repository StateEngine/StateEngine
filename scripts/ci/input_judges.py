"""Name unavailable external judge inputs without suppressing configured failures."""
import json
import os
from pathlib import Path
import sys


def nightly_features():
    return (os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") in {"schedule", "workflow_dispatch"})


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
    report = root / "target/nextest/input-judges.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({"schema": "ci-input-judges/v1", "not_run": records}, indent=2) + "\n")
    for record in records:
        print("NOT RUN " + record["judge"] + ": missing input "
              + ", ".join(record["missing_inputs"]), file=sys.stderr, flush=True)
    print(f"External-input judges: {len(records)} not-run selections; configured tests retain ordinary failure status",
          file=sys.stderr, flush=True)
    return excluded
