"""Import a native observer's pinned receipts without executing remote code."""
import hashlib
import json
from pathlib import Path
import re
from datetime import datetime, timezone

FILES = ("native-receipt.json", "credential-closure.json", "results.json", "budgets.json")


def load(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"native receipt is not a plain file: {path.name}")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"native receipt is not an object: {path.name}")
    return raw, value


def validate(invocation, directory, run):
    root = directory / invocation["output"]
    raw = {name: load(root / name) for name in FILES}
    receipt = raw["native-receipt.json"][1]
    expected = {"schema": "se.native-proof/v1", "platform": invocation["platform"],
                "surface": invocation["surface"], "selection": invocation["selection"],
                "product_commit": run.get("product", {}).get("commit"),
                "judge_commit": run.get("judge", {}).get("commit")}
    if any(receipt.get(key) != value or value is None for key, value in expected.items()):
        raise ValueError("native receipt source or scope differs from this attempt")
    ended = datetime.fromisoformat(receipt.get("ended_at", ""))
    started = datetime.fromisoformat(run["started_at"])
    if ended.tzinfo is None or ended.astimezone(timezone.utc).date() != started.astimezone(timezone.utc).date():
        raise ValueError("native observation is outside this attempt's UTC night")
    if (receipt.get("state") != "finished" or type(receipt.get("exit")) is not int
            or receipt["exit"] not in (0, 1) or receipt.get("errors") != []):
        raise ValueError("native observer did not finish with a witnessed verdict")
    if receipt.get("judge_files_sha256") != run.get("judge", {}).get("files_sha256"):
        raise ValueError("native judge file inventory differs from this attempt")
    if not isinstance(receipt.get("archive_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", receipt["archive_sha256"]):
        raise ValueError("native archive hash unavailable")
    hashes = receipt.get("files_sha256")
    if not isinstance(hashes, dict) or set(hashes) != {"results.json", "budgets.json"}:
        raise ValueError("native result inventory incomplete")
    for name, expected_hash in hashes.items():
        if hashlib.sha256(raw[name][0]).hexdigest() != expected_hash:
            raise ValueError("native artifact digest differs: " + name)
    closure = raw["credential-closure.json"][1]
    source = closure.get("closure")
    if (closure.get("credential_complete") is not True or not isinstance(source, dict)
            or any(source.get(key) is not True for key in
                   ("original_inode_unchanged", "original_digest_unchanged", "private_copy_absent"))
            or source.get("refresh_tokens_copied") is not False):
        raise ValueError("native credential transport closure unavailable")
    rows = receipt.get("credential_closure")
    if (not isinstance(rows, list) or not rows or any(not isinstance(row, dict)
            or row.get("credential_absent") is not True or row.get("removed_by_finalizer") is not False for row in rows)):
        raise ValueError("native fixture credential closure unavailable or required recovery")
    return receipt


def import_receipt(invocation, source, directory, run, state):
    destination = directory / invocation["output"]
    destination.mkdir(mode=0o700)
    invocation["native_receipt"] = True
    try:
        for name in FILES:
            data, _ = load(Path(source) / name)
            with (destination / name).open("xb") as output:
                output.write(data)
        receipt = validate(invocation, directory, run)
        # A fixed local receipt path must not replay yesterday's or an earlier
        # attempt's pass when the producer did not run again.
        consumed = state / "native-observations"
        consumed.mkdir(mode=0o700, exist_ok=True)
        identity = hashlib.sha256((destination / "native-receipt.json").read_bytes()).hexdigest()
        with (consumed / (identity + ".json")).open("x") as claim:
            json.dump({"directory": str(directory), "output": invocation["output"]}, claim)
        invocation.update(state="finished", exit=receipt["exit"])
    except (OSError, ValueError, TypeError) as error:
        invocation.update(state="unavailable", error=str(error), exit=None)
