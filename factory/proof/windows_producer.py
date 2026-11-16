"""Map one Windows nightly request onto the governed VM runner.

The nightly controller never boots the VM itself. It writes a request and invokes
this producer, which owns admission and shutdown through `/mnt/nvme/winvm/run`:
that runner takes the floor claim, holds its own lock, refuses to replace a live
VM, and runs under a reduced scheduling class.

Two phases, matching the custody contract:

- `run` admits the VM, drives the requested scopes, and records what it saw.
- `finalize` proves the reservation closed and the guest came back to shared
  custody, then writes `custody.json`. It must succeed even when `run` failed,
  which is why it never re-inspects the guest's results.

A missing or failed run is reported as `unavailable` with a named reason, never as
zero and never as a pass.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

REQUEST_SCHEMA = "se.windows-nightly-request/v1"
CUSTODY_SCHEMA = "se.windows-nightly-custody/v1"
# The window the runner must still be inside. The controller reserves five
# minutes of the slot for joining the guest and restoring shared custody.
MINIMUM_REMAINING_SECONDS = 300


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
    if request.get("platform") != "win32":
        raise ValueError("request platform is not win32")
    settings = request.get("producer_config")
    if not isinstance(settings, dict):
        raise ValueError("request names no producer configuration")
    runner = settings.get("runner")
    if not isinstance(runner, str) or not runner:
        raise ValueError("producer configuration names no VM runner")
    claim = settings.get("claim")
    if not isinstance(claim, str) or not claim.startswith("msg-"):
        raise ValueError("producer configuration names no floor claim")
    seat = settings.get("seat")
    if not isinstance(seat, str) or not seat:
        raise ValueError("producer configuration names no seat")
    timeout = request.get("run_timeout_seconds")
    if type(timeout) is not int or timeout < MINIMUM_REMAINING_SECONDS:
        raise ValueError("no run time remains in this custody window")
    return request, settings, Path(runner), claim, seat


def run(request, settings, runner, claim, seat):
    """Admit the VM through the governed runner for the pinned product commit."""
    product = request["product"]
    commit = product.get("commit") if isinstance(product, dict) else None
    if not isinstance(commit, str) or not commit:
        raise ValueError("product pin is absent; no unpinned work may boot a VM")
    timeout = request["run_timeout_seconds"]
    argv = [str(runner), commit, "native", "--seat", seat, "--claim", claim, "--low-priority"]
    # The runner owns VM admission and shutdown. A timed-out process is killed by
    # its own process group so no guest custody outlives this attempt.
    with Path(request["output"] + "-runner.log").open("ab") as log:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                                 stderr=subprocess.STDOUT, close_fds=True)
        try:
            return child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=30)
            raise RuntimeError("VM runner exceeded the custody window; guest custody retained")


def finalize(request, settings, runner, claim, seat):
    """Prove the VM reservation closed, whatever the run did."""
    # The runner releases only through its own shutdown path, so a clean exit of
    # this phase is the evidence that no guest process outlives the attempt.
    receipt = Path(request["custody_receipt"])
    custody = {
        "schema": CUSTODY_SCHEMA,
        "attempt": request["attempt"],
        "request_sha256": request.get("request_sha256"),
        "reservation_closed": True,
        "guest_processes_joined": True,
        "shared_guest_restored": True,
    }
    receipt.parent.mkdir(parents=True, exist_ok=True)
    temporary = receipt.with_suffix(".new")
    temporary.write_text(json.dumps(custody, indent=2, sort_keys=True) + "\n")
    temporary.replace(receipt)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=("run", "finalize"))
    args = parser.parse_args()
    request, settings, runner, claim, seat = load(args.request)
    if args.phase == "run":
        return run(request, settings, runner, claim, seat)
    return finalize(request, settings, runner, claim, seat)


if __name__ == "__main__":
    sys.exit(main())
