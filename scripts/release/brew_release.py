#!/usr/bin/env python3
"""Render the Homebrew tap formula from verified, already-built release archives."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

from release_archive import extract

HERE = Path(__file__).resolve().parent
TARGETS = {"linux": "x86_64-unknown-linux-gnu", "arm": "aarch64-apple-darwin",
           "intel": "x86_64-apple-darwin"}


def license_identifier(repository, source):
    cargo = subprocess.check_output(["git", "-C", str(repository), "show", source + ":Cargo.toml"], text=True)
    license_id = tomllib.loads(cargo)["workspace"]["package"]["license"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]*", license_id):
        raise ValueError("source license requires an explicit Homebrew expression; no license is inferred")
    return license_id


def prepare(release_directory, output, repository):
    release = json.loads((release_directory / "release.json").read_bytes())
    if (release["schema"] != "stateengine.release-assets/v1" or release["trust"] != "unsigned"
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", release["version"])
            or release["tag"] != "v" + release["version"]
            or not re.fullmatch(r"[0-9a-f]{40}", release["source_commit"])
            or set(release["packages"]) != set(TARGETS.values()) | {"x86_64-pc-windows-msvc"}):
        raise ValueError("release metadata is incomplete or unsupported")
    base = "https://github.com/StateEngine/StateEngine/releases/download/" + release["tag"]
    if release["base_url"] != base:
        raise ValueError("release URL differs from the version tag")
    if output.exists() or output.is_symlink():
        raise ValueError("formula output already exists; preserve it and use a new path")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".se-brew-", dir=output.parent) as temporary:
        scratch = Path(temporary)
        entries = {}
        for architecture, target in TARGETS.items():
            entry = release["packages"][target]
            name = f"stateengine-{release['version']}-{target}-unsigned.tar.gz"
            if (entry["file"] != name or entry["url"] != base + "/" + name
                    or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
                raise ValueError("archive reference differs from the exact release target")
            extract(release_directory / name, scratch / architecture, entry, release, target)
            entries[architecture] = entry
        license_id = license_identifier(repository, release["source_commit"])
        formula = f'''# Generated from verified release source {release["source_commit"]}.
class Stateengine < Formula
  desc "Run coding assistants with persistent conversations and messages"
  homepage "https://stateengine.ai"
  version "{release["version"]}"
  license "{license_id}"

  on_macos do
    on_arm do
      url "{entries["arm"]["url"]}"
      sha256 "{entries["arm"]["sha256"]}"
    end
    on_intel do
      url "{entries["intel"]["url"]}"
      sha256 "{entries["intel"]["sha256"]}"
    end
  end

  on_linux do
    depends_on arch: :x86_64
    url "{entries["linux"]["url"]}"
    sha256 "{entries["linux"]["sha256"]}"
  end

  def install
    libexec.install Dir["*"]
    bin.install_symlink libexec/"se"
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/se --version")
  end
end
'''
        staged = scratch / "stateengine.rb"
        staged.write_text(formula, encoding="utf-8", newline="\n")
        # Atomic non-overwriting publication, including a destination that appears
        # after the initial read-only checks.
        os.link(staged, output)
    return {"formula": str(output), "version": release["version"], "source_commit": release["source_commit"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="new Formula/stateengine.rb path")
    parser.add_argument("--repository", type=Path, default=HERE.parents[1],
                        help="Git checkout containing the release source's configured license metadata")
    args = parser.parse_args()
    print(json.dumps(prepare(args.release_dir.resolve(), args.out.absolute(), args.repository.resolve())))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError,
            tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"Homebrew packaging refused: {error}", file=sys.stderr)
        sys.exit(1)
