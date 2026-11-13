"""Verify and extract a published standalone archive for package managers."""
import hashlib
import json
from pathlib import PurePosixPath
import re
import shutil
import tarfile
import zipfile


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def extract(archive, destination, entry, release, target):
    if (archive.is_symlink() or not archive.is_file()
            or archive.stat().st_size != entry["bytes"] or digest(archive) != entry["sha256"]):
        raise ValueError("published archive size or checksum differs")
    suffix = ".zip" if target.endswith("windows-msvc") else ".tar.gz"
    root = f"stateengine-{release['version']}-{target}-unsigned"
    if archive.name != root + suffix:
        raise ValueError("archive filename differs from its version and target")
    opened = zipfile.ZipFile(archive) if suffix == ".zip" else tarfile.open(archive, "r:gz")
    names = set()
    total = 0
    with opened as package:
        members = package.infolist() if suffix == ".zip" else package.getmembers()
        if not members or len(members) > 10000:
            raise ValueError("archive entry count exceeds its bound or is empty")
        for member in members:
            name = member.filename if suffix == ".zip" else member.name
            path = PurePosixPath(name)
            normal = path.as_posix()
            if (not re.fullmatch(r"[A-Za-z0-9_./+-]+", name)
                    or normal != name.rstrip("/") or path.is_absolute()
                    or ".." in path.parts or path.parts[0] != root
                    or normal.casefold() in names):
                raise ValueError("archive contains an unsafe or duplicate path")
            names.add(normal.casefold())
            if suffix == ".zip":
                kind = (member.external_attr >> 16) & 0o170000
                if kind not in (0, 0o100000, 0o040000):
                    raise ValueError("archive contains a linked or special entry")
                size = member.file_size
            else:
                if not (member.isdir() or member.isreg()):
                    raise ValueError("archive contains a linked or special entry")
                size = member.size
            total += size
            if size > 4 * 1024**3 or total > 8 * 1024**3:
                raise ValueError("archive expanded size exceeds its bound")
        for member in members:
            name = member.filename if suffix == ".zip" else member.name
            path = destination / name
            directory = member.is_dir() if suffix == ".zip" else member.isdir()
            if directory:
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                source = package.open(member) if suffix == ".zip" else package.extractfile(member)
                with source, path.open("xb") as output:
                    shutil.copyfileobj(source, output)
                mode = member.external_attr >> 16 if suffix == ".zip" else member.mode
                path.chmod(0o755 if mode & 0o111 else 0o644)
    bundle = destination / root
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    for field, expected in {"schema": "se.release/v1", "variant": "standalone",
                            "trust": "unsigned", "version": release["version"],
                            "source_commit": release["source_commit"], "target": target}.items():
        if manifest[field] != expected:
            raise ValueError("archive manifest differs in " + field)
    actual = {path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_file()}
    if actual != set(manifest["files"]) | {"manifest.json", "SHA256SUMS"}:
        raise ValueError("archive file inventory differs from its manifest")
    for name, record in manifest["files"].items():
        path = bundle / name
        if path.stat().st_size != record["bytes"] or digest(path) != record["sha256"]:
            raise ValueError("archive payload checksum differs: " + name)
    build = json.loads((bundle / "build.json").read_bytes())
    for field in ("version", "source_commit", "target", "trust", "variant"):
        if build[field] != manifest[field]:
            raise ValueError("build provenance differs from the release manifest")
    return bundle, build
