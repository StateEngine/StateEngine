"""Map one Windows nightly request onto the governed VM runner.

The nightly controller never boots the VM itself. It writes a request and invokes
this producer, which owns admission and shutdown through the configured runner:
that runner takes the floor claim, holds its own lock, refuses to replace a live
VM, and writes a `job.json` describing how the attempt ended.

Two phases, matching the custody contract:

- `run` admits the VM, drives the requested scope, and records what it saw.
- `finalize` writes the custody receipt. Every closure flag is read from the
  runner's own `job.json`; a flag whose evidence is absent stays false. Reporting
  a closure nothing witnessed is the one failure this module exists to prevent.

A missing or failed run is reported as `unavailable` with a named reason, never as
zero and never as a pass.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REQUEST_SCHEMA = "se.windows-nightly-request/v1"
CUSTODY_SCHEMA = "se.windows-nightly-custody/v1"
# The controller reserves five minutes of the slot for joining the guest and
# restoring shared custody, so a request with less left cannot finish.
MINIMUM_REMAINING_SECONDS = 300
# The one provider-free measurement scope this producer drives. Journey scopes are
# owner-attended and are refused here rather than booting a VM for them.
SCOPES = (("measure", "writes"),)
# The controller imports exactly these files; a run that writes fewer produced no
# usable native receipt, whatever the VM did.
RECEIPT_FILES = ("native-receipt.json", "credential-closure.json", "results.json",
                 "budgets.json")
# B10's Windows full-write ceiling. The first standing night must produce a number
# against it, so the target travels with the attempt instead of being assumed.
B10_CEILING_MS_INCLUSIVE = 75


def number(value):
    """An integer count of seconds, never a float or a bool."""
    return type(value) is int and value >= 0


def load(request_path):
    request = json.loads(Path(request_path).read_text())
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("request schema is not " + REQUEST_SCHEMA)
    for name in ("attempt", "judge", "output", "custody_receipt"):
        if not request.get(name):
            raise ValueError("request is missing " + name)
    product = request.get("product")
    if not isinstance(product, dict) or not product.get("commit"):
        raise ValueError("product pin is absent; no unpinned work may boot a VM")
    judge = request["judge"]
    if not isinstance(judge, dict) or not judge.get("commit"):
        raise ValueError("judge pin is absent; no unpinned work may boot a VM")
    if request.get("platform") != "win32":
        raise ValueError("request platform is not win32")
    scope = (request.get("surface"), request.get("selection"))
    if scope not in SCOPES:
        raise ValueError("request scope is not one this producer can drive: " + str(scope))
    settings = request.get("producer_config")
    if not isinstance(settings, dict):
        raise ValueError("request names no producer configuration")
    runner = settings.get("runner")
    if not isinstance(runner, str) or not runner or not Path(runner).is_absolute():
        raise ValueError("producer configuration names no absolute VM runner")
    claim = settings.get("claim")
    if not isinstance(claim, str) or not claim.startswith("msg-"):
        raise ValueError("producer configuration names no floor claim")
    seat = settings.get("seat")
    if not isinstance(seat, str) or not seat:
        raise ValueError("producer configuration names no seat")
    timeout = request.get("run_timeout_seconds")
    if type(timeout) is not int:
        raise ValueError("run_timeout_seconds must be a whole number of seconds")
    if timeout < MINIMUM_REMAINING_SECONDS:
        raise ValueError("no run time remains in this custody window")
    return request, settings, Path(runner), claim, seat, request_path


def host_load():
    """The host's load and memory, recorded beside the figures (the B12 rule).

    Windows reports no load average, so the guest cannot supply this; the host that
    owns the VM is the only witness. An unreadable figure stays marked unreadable
    rather than becoming zero.
    """
    try:
        one, five, fifteen = os.getloadavg()
        cpus = os.cpu_count() or 0
    except OSError:
        return {"state": "unreadable"}
    if not cpus:
        return {"state": "unreadable"}
    available = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                available = int(line.split()[1]) * 1024
                break
    except (OSError, ValueError, IndexError):
        available = None
    return {"state": "measured", "logical_cpus": cpus, "one_minute": one,
            "five_minute": five, "fifteen_minute": fifteen, "per_cpu": one / cpus,
            "available_memory": ({"state": "measured", "bytes": available,
                                  "method": "MemAvailable"}
                                 if isinstance(available, int) else {"state": "unreadable"})}


def job_record(request):
    """The runner's own account of the attempt, or None when it wrote none."""
    path = Path(request["output"]).parent / "job.json"
    candidates = [path, Path(request["output"] + "-runner-job.json")]
    for candidate in candidates:
        try:
            value = json.loads(candidate.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(value, dict):
            return value
    return None


def run(request, settings, runner, claim, seat):
    """Admit the VM through the governed runner for the pinned product commit."""
    commit = request["product"]["commit"]
    timeout = request["run_timeout_seconds"]
    output = Path(request["output"])
    output.mkdir(parents=True, exist_ok=True)
    # The target names the measurement scope. The runner change adds `measure:<name>`
    # and `--out`; until that lands this refuses rather than passing a journey target
    # that would produce no measurement receipt.
    surface, selection = request["surface"], request["selection"]
    if surface != "measure":
        raise ValueError("producer drives measurement scopes only, not " + str((surface, selection)))
    target = "measure:" + selection
    (output.parent / "scope.json").write_text(
        json.dumps({"surface": surface, "selection": selection, "target": target,
                    "b10_ceiling_ms_inclusive": B10_CEILING_MS_INCLUSIVE,
                    "host_load_before": host_load()},
                   indent=2, sort_keys=True) + "\n")
    argv = [str(runner), commit, target, "--seat", seat, "--claim", claim,
            "--low-priority", "--out", str(output)]
    # The runner owns VM admission and shutdown. A timed-out child is killed and
    # reaped so no guest custody outlives this attempt.
    log = output.parent / "runner.log"
    with log.open("ab") as stream:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream,
                                 stderr=subprocess.STDOUT, close_fds=True)
        try:
            code = child.wait(timeout=timeout)
            (output.parent / "host-load-after.json").write_text(
                json.dumps(host_load(), indent=2, sort_keys=True) + "\n")
            return code
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=30)
            raise RuntimeError("VM runner exceeded the custody window; guest custody retained")


def closure(request):
    """Derive each custody flag from the runner's evidence, never from hope.

    `reservation_closed` needs a job record whose status is terminal and which
    reports no live VM. `guest_processes_joined` needs the same record to name a
    guest exit, because a joined guest is one that reported. `shared_guest_restored`
    needs an untouched base snapshot, which is what the runner resets from.
    """
    record = job_record(request)
    if record is None:
        return {"reservation_closed": False, "guest_processes_joined": False,
                "shared_guest_restored": False, "evidence": "absent"}
    terminal = record.get("status") in ("complete", "failed", "unavailable")
    closed = terminal and record.get("vm_running") is False and not record.get("shutdown_error")
    joined = terminal and record.get("guest_exit") is not None
    # A closure is only useful if the guest also produced the receipts the
    # controller imports; otherwise the attempt is a boot that measured nothing.
    produced = sorted(name for name in RECEIPT_FILES
                      if (Path(request["output"]) / name).is_file())
    complete_receipts = len(produced) == len(RECEIPT_FILES)
    restored = closed and joined and complete_receipts
    evidence = "job.json status=%r vm_running=%r guest_exit=%r shutdown_error=%r" % (
        record.get("status"), record.get("vm_running"), record.get("guest_exit"),
        record.get("shutdown_error"))
    return {"reservation_closed": closed, "guest_processes_joined": joined,
            "shared_guest_restored": restored, "evidence": evidence,
            "receipt_files": produced}


def finalize(request, digest):
    """Write the custody receipt from the runner's witnessed shutdown."""
    receipt = Path(request["custody_receipt"])
    flags = closure(request)
    custody = {"schema": CUSTODY_SCHEMA, "attempt": request["attempt"],
               "request_sha256": digest, **flags}
    receipt.parent.mkdir(parents=True, exist_ok=True)
    temporary = receipt.with_suffix(".new")
    temporary.write_text(json.dumps(custody, indent=2, sort_keys=True) + "\n")
    temporary.replace(receipt)
    # A closure this producer cannot witness is reported as a refusal, not a pass.
    return 0 if (flags["reservation_closed"] and flags["guest_processes_joined"]
                 and flags["shared_guest_restored"]) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=("run", "finalize"))
    args = parser.parse_args()
    request, settings, runner, claim, seat, request_path = load(args.request)
    request["_path"] = str(request_path)
    if args.phase == "run":
        return run(request, settings, runner, claim, seat)
    digest = hashlib.sha256(Path(request["_path"]).read_bytes()).hexdigest()
    return finalize(request, digest)


if __name__ == "__main__":
    sys.exit(main())
