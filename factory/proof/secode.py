"""Pin a local SE Code harness input; the independent judge owns behavior."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

SCHEMA = "se.journey-secode-input/v1"
BINARIES = ("secode", "secode-server", "secode-tui")
MANIFEST = "release-manifest.json"
TARGET = "x86_64-unknown-linux-gnu"


def inspect(path, limit, collect=False):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("SE Code input is not a bounded regular file: " + path.name)
        digest, size, chunks = hashlib.sha256(), 0, []
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError("SE Code input grew beyond its byte bound: " + path.name)
            digest.update(chunk)
            if collect:
                chunks.append(chunk)
        after = os.fstat(stream.fileno())
    current = path.lstat()
    signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if (not stat.S_ISREG(current.st_mode) or signature(before) != signature(after)
            or signature(before) != signature(current) or size != before.st_size):
        raise ValueError("SE Code input changed or is linked: " + path.name)
    return {"sha256": digest.hexdigest(), "bytes": size}, b"".join(chunks) if collect else None


def package(root, manifest_sha256):
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("SE Code package must name an absolute plain directory")
    if not isinstance(manifest_sha256, str) or not re.fullmatch("[a-f0-9]{64}", manifest_sha256):
        raise ValueError("SE Code package requires an exact manifest SHA256 pin")
    fact, raw = inspect(root / MANIFEST, 2 * 1024 * 1024, collect=True)
    if fact["sha256"] != manifest_sha256:
        raise ValueError("SE Code package manifest differs from its configured pin")
    document = json.loads(raw)
    if (not isinstance(document, dict) or document.get("schema") != "secode.release.package.v1"
            or document.get("target") != TARGET or not isinstance(document.get("binaries"), dict)):
        raise ValueError("SE Code first-night input requires a Linux native package manifest")
    binaries, source = {}, None
    for name in BINARIES:
        row = document["binaries"].get(name)
        if (not isinstance(row, dict) or row.get("bin") != name or row.get("target") != TARGET
                or not isinstance(row.get("source_commit"), str)
                or not re.fullmatch("[a-f0-9]{40}", row["source_commit"])):
            raise ValueError("SE Code package native identity is invalid: " + name)
        if source is not None and source != row["source_commit"]:
            raise ValueError("SE Code package native sources differ")
        source = row["source_commit"]
        binaries[name], _ = inspect(root / name, 256 * 1024 * 1024)
        if (type(row.get("bytes")) is not int or binaries[name] !=
                {"sha256": row.get("sha256"), "bytes": row["bytes"]}):
            raise ValueError("SE Code package native bytes differ: " + name)
    return {"root": str(root), "manifest_sha256": manifest_sha256,
            "source_commit": source, "binaries": binaries}


def provider(config):
    endpoint, model = config.get("base_url"), config.get("model")
    if not isinstance(endpoint, str) or not isinstance(model, str) or not model or len(model) > 256:
        raise ValueError("SE Code input requires an explicit local provider URL and model")
    parsed = urlsplit(endpoint)
    try:
        local = ipaddress.ip_address(parsed.hostname or "").is_loopback
        port = parsed.port
    except ValueError:
        local, port = False, None
    if (parsed.scheme != "http" or not local or port is None or not 1 <= port <= 65535
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or not parsed.path.rstrip("/").endswith("/v1")
            or any(ord(char) < 32 for char in endpoint + model)):
        raise ValueError("SE Code first-night provider requires credential-free loopback HTTP /v1")
    return {"base_url": endpoint, "model": model}


def identity(document):
    return {"package": {key: value for key, value in document["package"].items() if key != "root"},
            "provider": document["provider"]}


def prepare(config, directory):
    settings = config.get("secode")
    if not isinstance(settings, dict) or not isinstance(settings.get("package"), str):
        raise ValueError("a SE Code probe requires configured package, manifest pin and local model")
    if "secode" in config.get("credential_sources", {}):
        raise ValueError("SE Code first-night probes do not accept a credential source")
    document = {"schema": SCHEMA,
                "package": package(Path(settings["package"]), settings.get("manifest_sha256")),
                "provider": provider(settings)}
    raw = (json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    path = directory / "secode-input.json"
    with path.open("xb") as output:
        output.write(raw)
    return {"input": path.name, "input_sha256": hashlib.sha256(raw).hexdigest(),
            "identity": identity(document)}


def read_input(run, directory):
    pinned = run.get("secode")
    if not isinstance(pinned, dict) or pinned.get("input") != "secode-input.json":
        raise ValueError("SE Code input pin is unavailable")
    fact, raw = inspect(directory / pinned["input"], 2 * 1024 * 1024, collect=True)
    document = json.loads(raw)
    if (fact["sha256"] != pinned.get("input_sha256") or not isinstance(document, dict)
            or document.get("schema") != SCHEMA or not isinstance(document.get("package"), dict)
            or not isinstance(document.get("provider"), dict)
            or identity(document) != pinned.get("identity")):
        raise ValueError("SE Code retained input differs from this attempt's pin")
    return document


def verify_current(run, directory):
    document = read_input(run, directory)
    expected = document["package"]
    if package(Path(expected["root"]), expected["manifest_sha256"]) != expected:
        raise ValueError("SE Code package changed since this attempt was pinned")


def validate_receipt(receipt, invocation, run, directory):
    document = read_input(run, directory)
    pinned = run["secode"]["input_sha256"]
    if (invocation.get("platform") != "linux" or invocation.get("selection") != "secode"
            or invocation.get("surface") != "secode"
            or invocation.get("secode_input_sha256") != pinned
            or invocation.get("secode_inputs_verified_after") is not True
            or receipt.get("secode_input_sha256") != pinned
            or receipt.get("secode") != identity(document)):
        raise ValueError("SE Code receipt package, model or input binding differs from this attempt")
