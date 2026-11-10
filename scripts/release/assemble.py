#!/usr/bin/env python3
"""Assemble an explicitly unsigned archive from a native build.py output."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import sys
import tarfile
import tempfile
import time
import zipfile

SCRIPTS = Path(__file__).resolve().parent


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def native_binary(path, windows, target=None):
    with path.open("rb") as stream:
        header = stream.read(64)
        if windows:
            if header[:2] != b"MZ" or len(header) < 64:
                raise ValueError("Windows archive requires a native PE binary")
            stream.seek(struct.unpack_from("<I", header, 60)[0])
            if stream.read(6) != b"PE\0\0\x64\x86":
                raise ValueError("Windows executable is not x86_64 PE")
        elif target is not None and target.endswith("apple-darwin"):
            cpu = 0x0100000C if target == "aarch64-apple-darwin" else 0x01000007
            if (len(header) < 32 or header[:4] != b"\xcf\xfa\xed\xfe"
                    or struct.unpack_from("<I", header, 4)[0] != cpu
                    or struct.unpack_from("<I", header, 12)[0] != 2):
                raise ValueError("macOS archive requires a thin native Mach-O executable for its target")
        elif header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != 62:
            raise ValueError("Linux executable is not x86_64 ELF")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True, help="native build-output directory")
    parser.add_argument("--remote-build", type=Path, action="append", default=[],
                        help="same-source native build for another supported destination (repeat for every other target)")
    parser.add_argument("--native-only", action="store_true",
                        help="assemble only this platform for local use, omitting remote bootstrap images")
    parser.add_argument("--out", type=Path, required=True, help="archive output directory")
    args = parser.parse_args()
    if args.native_only and args.remote_build:
        parser.error("--native-only cannot include --remote-build inputs")
    build = args.build.resolve()
    metadata = json.loads((build / "build.json").read_text())
    inputs = json.loads((SCRIPTS / "inputs.json").read_text())
    if metadata.get("schema") != "se.release-build/v1" or metadata.get("variant") != "standalone":
        parser.error("expected a standalone build.py manifest")
    if metadata.get("trust") != "unsigned" or metadata["target"] not in inputs["targets"]:
        parser.error("unsupported target or trust state")
    if not re.fullmatch(r"[0-9a-f]{40}", metadata["source_commit"]):
        parser.error("build source_commit must be an exact Git commit")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", metadata["version"]):
        parser.error("build version is invalid")
    if metadata["inputs_sha256"] != digest(SCRIPTS / "inputs.json"):
        parser.error("build and assembler release inputs differ")
    for name, checksum in metadata["release_assets"].items():
        if Path(name).name != name or digest(SCRIPTS / name) != checksum:
            parser.error(f"release asset differs from the pinned build source: {name}")
    windows = metadata["target"].endswith("windows-msvc")
    binary = "se.exe" if windows else "se"
    expected = set(metadata["files"]) | {"build.json"}
    actual = set()
    for path in build.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"build output contains a link: {path}")
        if path.is_file():
            actual.add(path.relative_to(build).as_posix())
    if actual != expected or binary not in metadata["files"]:
        raise ValueError("build output differs from its exact file inventory")
    for name, checksum in metadata["files"].items():
        path = PurePosixPath(name)
        if (not re.fullmatch(r"[A-Za-z0-9_./+-]+", name) or path.is_absolute() or ".." in path.parts
                or (name != binary and not name.startswith("notices/"))):
            raise ValueError(f"unexpected payload path: {name}")
        if digest(build / name) != checksum:
            raise ValueError(f"build checksum mismatch: {name}")
    native_binary(build / binary, windows, metadata["target"])
    companions = {}
    for directory in args.remote_build:
        directory = directory.resolve()
        companion = json.loads((directory / "build.json").read_text())
        target = companion.get("target")
        if target not in inputs["targets"] or target == metadata["target"] or target in companions:
            raise ValueError("remote builds must name distinct supported destination platforms")
        for key in ("schema", "variant", "trust", "source_commit", "version", "inputs_sha256", "cargo_lock_sha256", "features", "release_assets"):
            if companion.get(key) != metadata.get(key):
                raise ValueError(f"remote build differs in {key}")
        executable = "se.exe" if target.endswith("windows-msvc") else "se"
        inventory = companion["files"]
        actual = set()
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise ValueError("remote build contains a link")
            if path.is_file():
                actual.add(path.relative_to(directory).as_posix())
        if actual != set(inventory) | {"build.json"} or executable not in inventory:
            raise ValueError("remote build differs from its exact inventory")
        for name, checksum in inventory.items():
            path = PurePosixPath(name)
            if (not re.fullmatch(r"[A-Za-z0-9_./+-]+", name) or path.is_absolute() or ".." in path.parts
                    or (name != executable and not name.startswith("notices/"))):
                raise ValueError("unexpected remote payload path")
            if digest(directory / name) != checksum:
                raise ValueError("remote build checksum mismatch")
        native_binary(directory / executable, executable == "se.exe", target)
        companions[target] = (directory, companion, executable)
    if ("remote" in inputs["features"] and not args.native_only
            and set(companions) != set(inputs["targets"]) - {metadata["target"]}):
        raise ValueError("remote-enabled archives require same-source native builds for every other supported target")
    args.out.mkdir(parents=True, exist_ok=True)
    flavor = "-native-only" if args.native_only else ""
    stem = f'stateengine-{metadata["version"]}-{metadata["target"]}{flavor}-unsigned'
    archive = args.out / (stem + (".zip" if windows else ".tar.gz"))
    if archive.exists() or archive.with_suffix(archive.suffix + ".sha256").exists():
        raise ValueError(f"archive already exists: {archive}; choose a new output directory")
    with tempfile.TemporaryDirectory(prefix="se-assemble-") as scratch:
        root = Path(scratch) / stem
        root.mkdir()
        for name in sorted(expected):
            if name.startswith("notices/"):
                continue
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(build / name, target)
        for target, (directory, _, executable) in companions.items():
            payload = root / "remote-images" / target / executable
            payload.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(directory / executable, payload)
        # Preserve every original notice byte in one deterministic installed
        # file, rather than paying a durable publication for each small notice.
        with tarfile.open(root / "notices.tar", "x") as notices:
            for name in sorted(metadata["files"]):
                if not name.startswith("notices/"):
                    continue
                source = build / name
                info = notices.gettarinfo(str(source), name)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = metadata["source_timestamp"]
                info.mode = 0o644
                with source.open("rb") as stream:
                    notices.addfile(info, stream)
            for target, (directory, companion, _) in sorted(companions.items()):
                for name in sorted(companion["files"]):
                    if not name.startswith("notices/"):
                        continue
                    source = directory / name
                    info = notices.gettarinfo(str(source), f"remote/{target}/{name}")
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = metadata["source_timestamp"]
                    info.mode = 0o644
                    with source.open("rb") as stream:
                        notices.addfile(info, stream)
        for script in ("install", "uninstall"):
            name = script + (".ps1" if windows else ".sh")
            shutil.copyfile(SCRIPTS / name, root / name)
        shutil.copyfile(SCRIPTS / "NOTICE.txt", root / "NOTICE.txt")
        command = ("powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\install.ps1"
                   if windows else "sh ./install.sh")
        (root / "README.txt").write_text(
            f'StateEngine {metadata["version"]} ({metadata["target"]})\n'
            f'Unsigned development archive; source {metadata["source_commit"]}.\n\n'
            f'Extract this archive, then run {command} as your normal user.\n'
            'Run the installer\'s printed command to verify se in the same terminal.\n'
            'The notices.tar member collects the release notices for this archive.\n'
            'To remove the installation, run se uninstall from an owner terminal.\n'
            'The uninstall script delegates to the same operation.\n'
            'Installation does not launch a service or require Node, npm or Rust.\n'
            + ('This native-only archive omits remote bootstrap images; use a full archive for remote connections.\n'
               if args.native_only else ''))
        files = {p.relative_to(root).as_posix(): {"sha256": digest(p), "bytes": p.stat().st_size}
                 for p in sorted(root.rglob("*")) if p.is_file()}
        if (windows or metadata["target"].endswith("apple-darwin")) and len({name.casefold() for name in files}) != len(files):
            raise ValueError("payload paths collide on the target filesystem")
        (root / "manifest.json").write_text(json.dumps({
            "schema": "se.release/v1", "variant": "standalone", "trust": "unsigned",
            "version": metadata["version"], "target": metadata["target"],
            "source_commit": metadata["source_commit"], "files": files}, indent=2) + "\n")
        # The checksum list covers the manifest too; neither manifest claims to hash itself.
        (root / "SHA256SUMS").write_text("".join(
            f'{digest(p)}  {p.relative_to(root).as_posix()}\n'
            for p in sorted(root.rglob("*")) if p.is_file()))
        epoch = metadata["source_timestamp"]
        paths = [root] + sorted(root.rglob("*"))
        if windows:
            with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as output:
                for path in paths:
                    if path.is_file():
                        info = zipfile.ZipInfo(path.relative_to(root.parent).as_posix(), time.gmtime(epoch)[:6])
                        info.compress_type = zipfile.ZIP_DEFLATED
                        info.external_attr = 0o100644 << 16
                        output.writestr(info, path.read_bytes())
        else:
            with archive.open("xb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as gz:
                with tarfile.open(fileobj=gz, mode="w") as output:
                    for path in paths:
                        info = output.gettarinfo(str(path), path.relative_to(root.parent).as_posix())
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mtime = epoch
                        info.mode = 0o755 if path.is_dir() or path.name in (binary, "install.sh", "uninstall.sh") or "remote-images" in path.parts else 0o644
                        if path.is_file():
                            with path.open("rb") as stream:
                                output.addfile(info, stream)
                        else:
                            output.addfile(info)
    checksum = digest(archive)
    archive.with_suffix(archive.suffix + ".sha256").write_text(f"{checksum}  {archive.name}\n")
    print(json.dumps({"archive": str(archive.resolve()), "sha256": checksum,
                      "source_commit": metadata["source_commit"], "trust": "unsigned"}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, struct.error) as error:
        print(f"archive assembly refused: {error}", file=sys.stderr)
        sys.exit(1)
