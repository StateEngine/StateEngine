#!/usr/bin/env python3
"""Judge two real unsigned native builds; never assemble or install an archive.

Run on Linux, or from a Windows x64 Native Tools shell, with Python 3.11+:
python release_builds.py --source CLEAN_SOURCE --out NEW_OUTPUT_DIRECTORY
The source must be committed. The second clean worktree and both outputs remain
under --out for inspection. A passing stub build does not qualify J1 or R06.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys
import tomllib


def command(argv, cwd, env=None):
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(f"command refused ({result.returncode}): {argv}\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def checksum(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(root):
    result = {}
    for path in root.rglob("*"):
        assert not path.is_symlink(), f"linked build output: {path}"
        if path.is_file():
            result[path.relative_to(root).as_posix()] = checksum(path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    source, out = args.source.resolve(), args.out.resolve()
    assert not out.exists() and source not in out.parents and out != source
    assert platform.machine().lower() in ("amd64", "x86_64"), "native x86_64 host required"
    assert sys.platform in ("linux", "win32"), "native Linux or Windows required"
    target = "x86_64-pc-windows-msvc" if sys.platform == "win32" else "x86_64-unknown-linux-gnu"
    assert not command(["git", "status", "--porcelain", "--untracked-files=all"], source), "source must be clean"
    commit = command(["git", "rev-parse", "HEAD"], source)
    tree = command(["git", "rev-parse", "HEAD^{tree}"], source)
    toolchain = tomllib.loads((source / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = tomllib.loads((source / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    out.mkdir(parents=True)
    second = out / "different-source-path"
    command(["git", "worktree", "add", "--detach", str(second), commit], source)
    manifests = []
    for index, root in enumerate((source, second), 1):
        destination = out / f"build-{index}"
        result = subprocess.run([sys.executable, str(root / "scripts/release/build.py"), "--target", target,
                                 "--out", str(destination)], cwd=root, text=True, capture_output=True)
        (out / f"build-{index}.stdout").write_text(result.stdout)
        (out / f"build-{index}.stderr").write_text(result.stderr)
        assert result.returncode == 0, f"build {index} refused: {result.stderr}"
        assert "Compiling se " in result.stderr, f"build {index} did not compile the native CLI"
        manifest = json.loads((destination / "build.json").read_text())
        assert manifest["source_commit"] == commit and manifest["source_tree"] == tree
        assert manifest["toolchain"] == toolchain and manifest["target"] == target
        assert manifest["trust"] == "unsigned" and manifest["variant"] == "standalone"
        assert manifest["version"] == version and manifest["version_stdout"] == f"se {version}"
        assert manifest["panic"] == "unwind" and manifest["default_features"] is False
        actual = inventory(destination)
        assert set(actual) == set(manifest["files"]) | {"build.json"}
        assert all(actual[name] == digest for name, digest in manifest["files"].items())
        assert manifest["cargo_lock_sha256"] == checksum(root / "Cargo.lock")
        assert manifest["inputs_sha256"] == checksum(root / "scripts/release/inputs.json")
        binary = destination / ("se.exe" if sys.platform == "win32" else "se")
        header = binary.read_bytes()[:4096]
        if sys.platform == "win32":
            offset = struct.unpack_from("<I", header, 60)[0]
            assert header[:2] == b"MZ" and header[offset:offset+6] == b"PE\0\0\x64\x86"
            assert struct.unpack_from("<H", header, offset + 24)[0] == 0x20b
        else:
            assert header[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", header, 18)[0] == 62
            needed = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", command(["readelf", "--dynamic", str(binary)], out))
            assert sorted(set(needed)) == manifest["native_requirements"]["needed"]
            assert "not found" not in command(["ldd", str(binary)], out)
        requirements = manifest["native_requirements"]
        assert requirements["architecture"] == "x86_64" and requirements["needed"]
        assert command([str(binary), "--version"], out,
                       {k: v for k, v in {**os.environ, "PATH": ""}.items()
                        if k in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP")}) == f"se {version}"
        manifests.append(manifest)
    assert manifests[0] == manifests[1], "cold native build manifests differ"
    assert inventory(out / "build-1") == inventory(out / "build-2"), "cold native bytes or complete inventories differ"
    print("PASS: two cold builds at different source paths have identical native bytes, manifests, and inventories", flush=True)

    spec = importlib.util.spec_from_file_location("release_build_under_review", source / "scripts/release/build.py")
    module = importlib.util.module_from_spec(spec)
    # Import source without creating an untracked __pycache__ in the clean tree.
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    binary = out / "build-1" / ("se.exe" if sys.platform == "win32" else "se")
    original_path = os.environ.get("PATH")
    os.environ["PATH"] = str(out / "absent-tools")
    try:
        try:
            module.native_requirements(binary, sys.platform == "win32")
        except ValueError as error:
            assert "inspector is absent" in str(error)
        else:
            raise AssertionError("missing native dependency inspector was accepted")
    finally:
        if original_path is None:
            del os.environ["PATH"]
        else:
            os.environ["PATH"] = original_path
    print("PASS: actual native dependency inspection refuses an unavailable tool", flush=True)
    assert not command(["git", "status", "--porcelain", "--untracked-files=all"], source)
    assert not command(["git", "status", "--porcelain", "--untracked-files=all"], second)
    # Cargo discovers configuration outside the pinned checkout. A refusal
    # after executing that configuration's wrapper is already too late.
    marker = out / "ambient-wrapper-executed"
    wrapper = out / ("untrusted-wrapper.cmd" if sys.platform == "win32" else "untrusted-wrapper.sh")
    if sys.platform == "win32":
        wrapper.write_text(f'@echo off\necho executed>"{marker}"\nexit /b 89\n')
    else:
        import shlex
        wrapper.write_text(f'#!/bin/sh\nprintf executed > {shlex.quote(str(marker))}\nexit 89\n')
        wrapper.chmod(0o700)
    failures = []
    for label in ("parent", "parent-legacy", "user-home", "user-home-legacy"):
        env = dict(os.environ)
        config = (out / ".cargo" if label.startswith("parent") else out / "hostile-cargo-home")
        config.mkdir()
        if label.startswith("user-home"):
            env["CARGO_HOME"] = str(config)
        config_path = config / ("config" if label.endswith("legacy") else "config.toml")
        config_text = '[build]\nrustc-wrapper = ' + json.dumps(str(wrapper)) + '\n[profile.release]\npanic = "abort"\n'
        config_path.write_text(config_text)
        (out / (label + "-config.fixture")).write_text(config_text)
        destination = out / ("refused-" + label)
        try:
            result = subprocess.run([sys.executable, str(second / "scripts/release/build.py"), "--target", target,
                                 "--out", str(destination)], cwd=second, env=env, text=True, capture_output=True, timeout=120)
            (out / (label + "-override.stderr")).write_text(result.stderr)
            if result.returncode == 0:
                failures.append(f"ambient {label} configuration was accepted")
            if marker.exists():
                failures.append(f"ambient {label} wrapper executed before refusal")
                marker.unlink()
            if "config" not in result.stderr.lower() or "refus" not in result.stderr.lower():
                failures.append(f"ambient {label} did not give a configuration refusal: {result.stderr}")
            if (destination / "build.json").exists():
                failures.append(f"ambient {label} left a qualified build manifest")
        finally:
            config_path.unlink()
            if not any(config.iterdir()):
                config.rmdir()
    assert not failures, "; ".join(failures)
    print("PASS: ambient parent and user Cargo configuration refuse before an untrusted wrapper executes", flush=True)
    print("3 passed; 0 failed; build reproducibility only, native runtime/J1/R06 qualification remains separate")


if __name__ == "__main__":
    main()
