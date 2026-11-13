#!/usr/bin/env python3
"""Repackage verified GitHub Release archives into registry-only native packages."""
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import sys
import tarfile
import tempfile
import zipfile

from assemble import native_binary
from native_payload import publish
from release_archive import digest, extract

HERE = Path(__file__).resolve().parent
PLATFORMS = {
    "linux-x64": "x86_64-unknown-linux-gnu",
    "win32-x64": "x86_64-pc-windows-msvc",
    "darwin-arm64": "aarch64-apple-darwin",
    "darwin-x64": "x86_64-apple-darwin",
}


def document(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def prepare(release_directory, output):
    release = json.loads((release_directory / "release.json").read_bytes())
    if (release["schema"] != "stateengine.release-assets/v1" or release["trust"] != "unsigned"
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", release["version"])
            or release["tag"] != "v" + release["version"]
            or not re.fullmatch(r"[0-9a-f]{40}", release["source_commit"])
            or set(release["packages"]) != set(PLATFORMS.values())):
        raise ValueError("release metadata is incomplete or unsupported")
    base = "https://github.com/StateEngine/StateEngine/releases/download/" + release["tag"]
    if release["base_url"] != base:
        raise ValueError("release URL differs from the version tag")
    if output.exists() or output.is_symlink() or output.resolve().is_relative_to(HERE.parents[1]):
        raise ValueError("package output must be new and outside the source tree")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".se-npm-", dir=output.parent) as temporary:
        scratch = Path(temporary)
        stage = scratch / "packages"
        stage.mkdir()
        pins = {}
        order = []
        license_bytes = None
        for platform, target in PLATFORMS.items():
            entry = release["packages"][target]
            suffix = ".zip" if platform.startswith("win32-") else ".tar.gz"
            filename = f"stateengine-{release['version']}-{target}-unsigned{suffix}"
            if (entry["file"] != filename or entry["url"] != base + "/" + filename
                    or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
                raise ValueError("archive reference differs from the exact release target")
            unpack = scratch / platform
            bundle, build = extract(release_directory / filename, unpack, entry, release, target)
            native_binary(bundle / ("se.exe" if platform.startswith("win32-") else "se"),
                          platform.startswith("win32-"), target)
            package = stage / platform
            package.mkdir()
            pin = publish(bundle, build, package / "payload")
            current_license = (package / "payload/LICENSE").read_bytes()
            if license_bytes is not None and license_bytes != current_license:
                raise ValueError("platform packages disagree on the source license")
            license_bytes = current_license
            name = "@stateengine/cli-" + platform
            operating_system, cpu = platform.split("-")
            metadata = {"name": name, "version": release["version"], "private": False,
                        "description": "Native StateEngine payload", "os": [operating_system],
                        "cpu": [cpu], "files": ["payload"],
                        "repository": "github:StateEngine/StateEngine"}
            if operating_system == "linux":
                metadata["libc"] = ["glibc"]
            document(package / "package.json", metadata)
            pins[platform] = {"package": name, "target": target,
                              "manifest_sha256": pin["manifest_sha256"]}
            order.append({"name": name, "directory": platform})
        wrapper = stage / "cli"
        (wrapper / "bin").mkdir(parents=True)
        shutil.copyfile(HERE / "npm/se.mjs", wrapper / "bin/se.mjs")
        (wrapper / "bin/se.mjs").chmod(0o755)
        shutil.copyfile(HERE / "npm/README.md", wrapper / "README.md")
        (wrapper / "LICENSE").write_bytes(license_bytes)
        document(wrapper / "package.json", {
            "name": "@stateengine/cli", "version": release["version"], "type": "module",
            "description": "StateEngine native command-line interface", "bin": {"se": "bin/se.mjs"},
            "engines": {"node": ">=18"}, "files": ["bin", "platforms.json", "LICENSE", "README.md"],
            "repository": "github:StateEngine/StateEngine",
            "optionalDependencies": {pin["package"]: release["version"] for pin in pins.values()},
        })
        document(wrapper / "platforms.json", {"source_commit": release["source_commit"], "platforms": pins})
        order.append({"name": "@stateengine/cli", "directory": "cli"})
        document(stage / "publish-order.json", {"version": release["version"],
                 "source_commit": release["source_commit"], "packages": order})
        stage.rename(output)
    return {"directory": str(output), "version": release["version"], "packages": order}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", type=Path, required=True,
                        help="downloaded release.json and its four exact release archives")
    parser.add_argument("--out", type=Path, required=True, help="new directory for npm package sources")
    args = parser.parse_args()
    print(json.dumps(prepare(args.release_dir.resolve(), args.out.absolute())))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, struct.error, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"npm packaging refused: {error}", file=sys.stderr)
        sys.exit(1)
