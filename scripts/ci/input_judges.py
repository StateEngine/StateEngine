"""Name unavailable external judge inputs without suppressing configured failures."""
import json
import os
from pathlib import Path
import subprocess
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


# Tests that need a runtime able to detach from its process job. A hosted Windows
# runner executes inside a job whose policy denies breakaway, so the direct spawn
# is refused and the broker fallback has no eligible broker: no runtime child is
# ever created, and these tests then wait for a host that cannot exist. That is a
# venue fact, not a product verdict, so on such a venue each one is reported as
# not run with its reason instead of failing or silently passing. The native
# Windows run still exercises every one of them in full.
BREAKAWAY_VENUE = "needs a breakaway-capable venue"
BREAKAWAY_TESTS = (
    ("se", "agent_allocation_routes", "direct_agent_allocations_remain_distinct_and_replay_without_new_events"),
    ("se", "agent_allocation_routes", "hosted_agent_allocations_remain_distinct_and_replay_without_new_events"),
    ("se", "breakaway_refusal", "eligible_broker_runtime_outlives_strict_job_and_public_down_closes_it"),
    ("se", "hook_session_independent", "hook_session_active"),
    ("se", "hook_session_independent", "hook_session_deadline"),
    ("se", "hook_session_independent", "hook_session_expired"),
    ("se", "hook_session_independent", "hook_session_prepared"),
    ("se", "hook_session_independent", "hook_session_purpose"),
    ("se", "hook_session_independent", "hook_session_revoked"),
    ("se", "hook_session_independent", "hook_session_stop_unproved"),
    ("se", "hook_session_independent", "hook_session_superseded"),
    ("se", "http_admission", "public_http_admission_precedes_anonymous_and_private_routes"),
    ("se", "runtime_image_remedy", "multilink_image_names_the_launch_precondition_and_a_single_link_copy_starts"),
    ("se", "runtime_refusals", "live_host_init_refuses_with_down_then_retry_succeeds"),
    ("se", "runtime_refusals", "uninstall_verifies_live_host_shutdown_before_removing_files"),
)


def breakaway_venue_required():
    """Whether this process is inside a job that denies breakaway.

    Asked the way the product meets it: a job permits a child to leave only when
    its LimitFlags include BREAKAWAY_OK or SILENT_BREAKAWAY_OK. Membership alone is
    not the question — a job that permits breakaway is fine — so this reads the
    enclosing job's limits and answers True only when breakaway is denied. If the
    limits cannot be read, nothing is claimed and the tests run normally, where
    their own failure names the real cause.
    """
    if not sys.platform.startswith("win"):
        return False
    script = r"""
import ctypes, sys
k = ctypes.WinDLL('kernel32', use_last_error=True)
class Basic(ctypes.Structure):
    _fields_ = [('PerProcessUserTimeLimit', ctypes.c_int64),
                ('PerJobUserTimeLimit', ctypes.c_int64),
                ('LimitFlags', ctypes.c_uint32),
                ('MinimumWorkingSetSize', ctypes.c_size_t),
                ('MaximumWorkingSetSize', ctypes.c_size_t),
                ('ActiveProcessLimit', ctypes.c_uint32),
                ('Affinity', ctypes.c_size_t),
                ('PriorityClass', ctypes.c_uint32),
                ('SchedulingClass', ctypes.c_uint32)]
class Io(ctypes.Structure):
    _fields_ = [('ReadOperationCount', ctypes.c_uint64),
                ('WriteOperationCount', ctypes.c_uint64),
                ('OtherOperationCount', ctypes.c_uint64),
                ('ReadTransferCount', ctypes.c_uint64),
                ('WriteTransferCount', ctypes.c_uint64),
                ('OtherTransferCount', ctypes.c_uint64)]
class Extended(ctypes.Structure):
    _fields_ = [('BasicLimitInformation', Basic), ('IoInfo', Io),
                ('ProcessMemoryLimit', ctypes.c_size_t),
                ('JobMemoryLimit', ctypes.c_size_t),
                ('PeakProcessMemoryUsed', ctypes.c_size_t),
                ('PeakJobMemoryUsed', ctypes.c_size_t)]
k.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
k.QueryInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
member = ctypes.c_int(0)
if not k.IsProcessInJob(ctypes.c_void_p(-1), None, ctypes.byref(member)) or not member.value:
    sys.exit(1)   # not in a job: breakaway is not gated here
info = Extended()
got = ctypes.c_uint32(0)
# JobObjectBasicLimitInformation is class 2; 9 is JobObjectExtendedLimitInformation.
MASK = 0x0800 | 0x1000  # JOB_OBJECT_LIMIT_BREAKAWAY_OK | SILENT_BREAKAWAY_OK
if not k.QueryInformationJobObject(None, 9, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(got)):
    if not k.QueryInformationJobObject(None, 2, ctypes.byref(info.BasicLimitInformation),
                                       ctypes.sizeof(Basic), ctypes.byref(got)):
        sys.exit(1)   # cannot read the limits: claim nothing
sys.exit(0 if (info.BasicLimitInformation.LimitFlags & MASK) == 0 else 1)
"""
    try:
        return subprocess.run([sys.executable, "-I", "-c", script],
                              capture_output=True).returncode == 0
    except OSError:
        return False


def venue_exclusions():
    """Exact nextest selectors this venue cannot exercise, and why.

    Kept separate from `unavailable`, which answers a feature-mode question. This
    one answers a machine question and is therefore consulted in every mode.
    """
    if not breakaway_venue_required():
        return []
    return [f"(package(={package}) & binary(={binary}) & test(={test}))"
            for package, binary, test in BREAKAWAY_TESTS]


def announce_venue(root: Path):
    """Name this venue's excluded tests where a reader will actually see them.

    A filter that drops tests silently is the failure mode this exists to prevent.
    GitHub exposes GITHUB_STEP_SUMMARY to every step, including the archived-test
    path that never reads input-judges.json, so the named reason is appended there
    when present. Without it the caller still gets the same lines on stderr.
    """
    excluded = venue_exclusions()
    if not excluded:
        return []
    lines = [f"- NOT RUN {package}::{binary}::{test}: {BREAKAWAY_VENUE}"
             for package, binary, test in BREAKAWAY_TESTS]
    # The log is the other place a reader looks, and the archived-test step never
    # reads input-judges.json, so the same names go to stderr as well.
    for package, binary, test in BREAKAWAY_TESTS:
        print(f"NOT RUN {package}::{binary}::{test}: {BREAKAWAY_VENUE}",
              file=sys.stderr, flush=True)
    report = root / "target/nextest/input-judges.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({"schema": "ci-input-judges/v1", "not_run": [
        {"judge": f"{package}::{binary}::{test}", "status": "not_run",
         "missing_inputs": [BREAKAWAY_VENUE]}
        for package, binary, test in BREAKAWAY_TESTS]}, indent=2) + "\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as output:
                output.write("Tests not run in this venue (not passes, not failures):\n")
                output.write("\n".join(lines) + "\n")
        except OSError:
            pass
    return excluded


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
    venue = venue_exclusions()
    if venue:
        excluded.extend(venue)
        for package, binary, test in BREAKAWAY_TESTS:
            # Exactly this test, not its whole binary: the rest of that binary is
            # ordinary coverage and must keep running.
            records.append({"judge": f"{package}::{binary}::{test}", "status": "not_run",
                            "missing_inputs": [BREAKAWAY_VENUE]})
            print(f"NOT RUN {package}::{binary}::{test}: {BREAKAWAY_VENUE}",
                  file=sys.stderr, flush=True)
    report = root / "target/nextest/input-judges.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({"schema": "ci-input-judges/v1", "not_run": records}, indent=2) + "\n")
    for record in records:
        print("NOT RUN " + record["judge"] + ": missing input "
              + ", ".join(record["missing_inputs"]), file=sys.stderr, flush=True)
    print(f"External-input judges: {len(records)} not-run selections; configured tests retain ordinary failure status",
          file=sys.stderr, flush=True)
    return excluded
