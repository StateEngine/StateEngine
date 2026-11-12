"""Retain remote behavior and timing observations as their own nightly scope."""
import math

TIMINGS = ("attach", "pending_echo", "live_output", "reconnect")


def summarize(entry, receipt, run):
    if (entry.get("mode") != "remote" or entry.get("platform") != "linux" or
            type(entry.get("exit")) is not int or
            receipt.get("schema") != "se.remote-journey/v1" or
            receipt.get("product_commit") != (run.get("product") or {}).get("commit") or
            receipt.get("binary_sha256") != (run.get("product") or {}).get("binary_sha256") or
            receipt.get("surface") != entry.get("surface") or
            receipt.get("source_platform") != entry.get("platform") or
            receipt.get("destination_platform") != "linux"):
        entry["problems"].append("remote receipt product, native image or scope mismatch")
        return entry
    errors, cleanup = receipt.get("errors"), receipt.get("cleanup_errors")
    if (not isinstance(errors, list) or not isinstance(cleanup, list) or
            receipt.get("state") not in {"finished", "failed"} or
            type(receipt.get("passed")) is not bool):
        entry["problems"].append("remote terminal state or cleanup unavailable")
        return entry
    timings = receipt.get("timings", {})
    process = receipt.get("process_closure", {})
    if not isinstance(timings, dict) or not isinstance(process, dict):
        entry["problems"].append("remote timings or process closure malformed")
        return entry
    measured = {}
    for name in TIMINGS:
        sample = timings.get(name)
        number = sample.get("milliseconds") if isinstance(sample, dict) else None
        valid = (type(number) in (int, float) and math.isfinite(number) and number >= 0 and
                 isinstance(sample.get("boundary"), str) and bool(sample["boundary"]) and
                 sample.get("qualification") == ("unqualified" if name == "live_output" else "observed"))
        measured[name] = {**(sample if valid else {}), "state": "MEASURED" if valid else "NOT MEASURED"}
    closure = receipt.get("credential_closure") == {"original_inode_unchanged": True,
        "original_digest_unchanged": True, "private_copies_absent": True, "refresh_tokens_copied": False}
    stopped = (process.get("stop_complete") is True and process.get("outside_process_absent") is True and
               isinstance(process.get("session"), str) and type(process.get("pid")) is int and process["pid"] > 0)
    behavior = (receipt["state"] == "finished" and not errors and not cleanup and closure and stopped and
              isinstance(receipt.get("steps"), list) and len(receipt["steps"]) == 4)
    coverage = all(sample["state"] == "MEASURED" for sample in measured.values())
    passed = behavior and coverage
    if (behavior != receipt.get("behavior_passed") or coverage != receipt.get("measurements_complete") or
            passed != receipt["passed"] or entry.get("exit") != (0 if passed else 1)):
        entry["problems"].append("remote result disagrees with behavior, timing coverage or credential closure")
        return entry
    entry.update(receipt_complete=True, outcome="PASS" if passed else "FAIL",
                 journeys={"1": "PASS" if behavior else "FAIL"}, remote_timings=measured,
                 results=[{"journey": 1, "result": "PASS" if behavior else "FAIL", "cleanup": cleanup}])
    entry["problems"] += errors + cleanup
    if behavior and not coverage:
        entry["problems"].append("remote timing coverage unavailable: " + ", ".join(
            name for name, sample in measured.items() if sample["state"] != "MEASURED"))
    return entry
