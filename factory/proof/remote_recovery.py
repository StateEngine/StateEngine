"""Durable ownership of interrupted SSH fixture attempts, without credential data."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import time

from remote_credentials import Credentials, plain


def snapshot(journey):
    return {"nonce": journey.nonce, "executable": str(journey.se.resolve()),
            "directory": str(journey.directory.resolve()), "remote_root": journey.remote_root,
            "target": journey.target, "target_parts": getattr(journey, "target_parts", None),
            "session": journey.session, "remote_runtime": journey.remote_runtime,
            "launch_attempted": journey.launch_attempted, "custody_safe": journey.custody_safe,
            "credentials": journey.credentials.snapshot() if journey.credentials else None}


def begin_recovery(journey):
    """Called only with the destination's exclusive fixture lock held."""
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    root = Path(journey.config.get("recovery_directory", home /
                ".local/state/stateengine-rust-proof/remote-recovery"))
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("remote recovery directory must be a private owned directory")
    key = hashlib.sha256(journey.config["destination"].encode()).hexdigest()
    path = root / (key + ".json")
    if path.exists() or path.is_symlink():
        reference = json.loads(plain(path)[0])
        if reference.get("destination") != journey.config["destination"]:
            raise RuntimeError("remote recovery destination differs from the locked account")
        recover(journey, path, reference)
    # Publish before any token handoff or runtime launch. A hard kill leaves
    # this pointer and the independently persisted per-attempt custody record.
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"destination": journey.config["destination"],
                                    "directory": str(journey.directory.resolve()), "nonce": journey.nonce}) + "\n")
    temporary.replace(path)
    journey.recovery_path = path
    journey.persist()


def recover(current, path, reference):
    directory = Path(reference["directory"])
    record = json.loads(plain(directory / "remote.json")[0])
    value = record["custody"]
    if value["nonce"] != reference["nonce"] or value["directory"] != str(directory):
        raise RuntimeError("remote recovery ownership record differs from its journal")
    if (len(value["nonce"]) != 32 or any(c not in "0123456789abcdef" for c in value["nonce"]) or
            Path(value["remote_root"]) != Path(current.remote_root).parent / value["nonce"]):
        raise RuntimeError("remote recovery root is outside the registered account fixture")
    previous = type(current).__new__(type(current))
    previous.config, previous.env = current.config, current.env
    previous.record, previous.directory = record, directory
    previous.se = Path(value["executable"])
    previous.source, previous.workspace = directory / "source-home", directory / "source-work"
    for name in ("nonce", "remote_root", "target", "target_parts", "session", "remote_runtime",
                 "launch_attempted", "custody_safe"):
        setattr(previous, name, value[name])
    previous.remote_se = previous.remote_root + "/se"
    previous.watch = previous.lock = None
    previous.credentials = Credentials.restore(previous, value["credentials"]) if value["credentials"] else None
    previous.recovery_path = path
    previous.commands = max((int(p.name.split("-")[0]) for p in directory.glob("*-command.*")), default=0)
    previous.deadline = time.monotonic() + 180
    previous.record.setdefault("prior_cleanup_errors", []).extend(previous.record["cleanup_errors"])
    previous.record["cleanup_errors"] = []
    previous.cleanup()
    current.record.setdefault("recovered_attempts", []).append({"nonce": previous.nonce,
        "closed": not previous.record["leftover"], "errors": previous.record["cleanup_errors"],
        "token_source": previous.record.get("recovered_token_source")})
    current.persist()
    if previous.record["leftover"]:
        reason = "; ".join(previous.record["cleanup_errors"]) or "owned resources remain unproven; inspect the retained cleanup observations"
        raise RuntimeError("previous owned remote attempt still has unresolved custody: " +
                           reason)


def finish_recovery(journey):
    if journey.recovery_path is not None and not journey.record["leftover"]:
        journey.recovery_path.unlink()
        journey.recovery_path = None
