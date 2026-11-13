#!/usr/bin/env python3
"""Assemble all native builds and render checksummed tag-release installers."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parents[1]
REPOSITORY = "https://github.com/StateEngine/StateEngine"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def render(name, values):
    text = (SCRIPTS / name).read_text(encoding="utf-8")
    for key, value in values.items():
        text = text.replace("@" + key + "@", value)
    if re.search(r"@[A-Z_]+@", text):
        raise ValueError("unresolved installer template field")
    return text


def installers(document, output):
    """Embed exact URLs and digests; clients never resolve a second latest pointer."""
    packages = document["packages"]
    cases = []
    for platform, target, macos in [
        ("Linux:x86_64", "x86_64-unknown-linux-gnu", 0),
        ("Darwin:arm64", "aarch64-apple-darwin", 1),
        ("Darwin:x86_64", "x86_64-apple-darwin", 1),
    ]:
        entry = packages[target]
        cases.append(f"    {platform}) target={target}; macos={macos}; "
                     f"archive='{entry['file']}'; checksum='{entry['sha256']}' ;;")
    common = {"VERSION": document["version"], "BASE": document["base_url"]}
    (output / "install.sh").write_text(render("download.sh.in", common | {
        "TARGETS": "\n".join(cases)}), encoding="utf-8", newline="\n")
    windows = packages["x86_64-pc-windows-msvc"]
    (output / "install.ps1").write_text(render("download.ps1.in", common | {
        "ARCHIVE": windows["file"], "CHECKSUM": windows["sha256"]}),
        encoding="utf-8", newline="\n")


def release_identity(tag):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag):
        raise ValueError("release tag must be vMAJOR.MINOR.PATCH with an optional prerelease")
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if tag != "v" + version:
        raise ValueError("release tag differs from the workspace package version")

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()

    source = git("rev-parse", "HEAD")
    if git("rev-parse", f"refs/tags/{tag}^{{commit}}") != source:
        raise ValueError("release tag does not name the checked-out commit")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("release source must be clean")
    return version, source


def prepare(builds, output, tag):
    version, source = release_identity(tag)
    if output.exists() or output.is_symlink() or output.resolve().is_relative_to(ROOT):
        raise ValueError("release output must be a new directory outside the source tree")
    targets = json.loads((SCRIPTS / "inputs.json").read_text())["targets"]
    for target in targets:
        metadata = json.loads((builds / target / "build.json").read_bytes())
        if (metadata["target"] != target or metadata["source_commit"] != source
                or metadata["version"] != version):
            raise ValueError("native build differs from the release tag, source or target")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".se-release-", dir=output.parent) as temporary:
        stage = Path(temporary) / "release"
        stage.mkdir()
        packages = {}
        base = f"{REPOSITORY}/releases/download/{tag}"
        for target in targets:
            arguments = [sys.executable, "-B", str(SCRIPTS / "assemble.py"),
                         "--build", str(builds / target), "--out", str(stage)]
            for other in targets:
                if other != target:
                    arguments += ["--remote-build", str(builds / other)]
            assembled = json.loads(subprocess.check_output(arguments, text=True))
            archive = Path(assembled["archive"])
            packages[target] = {"file": archive.name, "url": base + "/" + archive.name,
                                "sha256": assembled["sha256"], "bytes": archive.stat().st_size}
            for directory in sorted(stage.glob("*.symbols")):
                # Keep diagnostics separate from ordinary installer downloads.
                shutil.make_archive(str(directory), "gztar", directory.parent, directory.name)
                shutil.rmtree(directory)
        document = {"schema": "stateengine.release-assets/v1", "version": version,
                    "tag": tag, "source_commit": source, "trust": "unsigned",
                    "base_url": base, "packages": packages}
        (stage / "release.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        installers(document, stage)
        (stage / "SHA256SUMS").write_text("".join(
            f"{digest(file)}  {file.name}\n" for file in sorted(stage.iterdir()) if file.is_file()),
            encoding="utf-8", newline="\n")
        stage.rename(output)
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--builds", type=Path,
                        help="directory containing one build.py output per target triple")
    parser.add_argument("--out", type=Path, help="new release-asset directory")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--check-tag", action="store_true", help="check source identity before native builds")
    args = parser.parse_args()
    if args.check_tag:
        version, source = release_identity(args.tag)
        print(json.dumps({"version": version, "source_commit": source}))
        return
    if args.builds is None or args.out is None:
        parser.error("--builds and --out are required for assembly")
    print(json.dumps(prepare(args.builds.resolve(), args.out.absolute(), args.tag)))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"release preparation refused: {error}", file=sys.stderr)
        sys.exit(1)
