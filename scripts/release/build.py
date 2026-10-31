#!/usr/bin/env python3
"""Build the standalone CLI from pinned, already available offline inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(*argv):
    return subprocess.run(argv, cwd=ROOT, check=True, text=True,
                          stdout=subprocess.PIPE).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--out", required=True, type=Path,
                        help="new build-output directory outside the source tree")
    args = parser.parse_args()
    inputs = json.loads((ROOT / "scripts/release/inputs.json").read_text())
    if args.target not in inputs["targets"]:
        parser.error("target is not in scripts/release/inputs.json")
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents or out.exists():
        parser.error("--out must be a new directory outside the source tree")
    if run("git", "status", "--porcelain", "--untracked-files=all"):
        parser.error("commit the release source first; the source tree is not clean")
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    compiler = run("rustc", "+" + toolchain, "-vV")
    if f"host: {args.target}" not in compiler.splitlines():
        parser.error("build on the target's native machine; cross-builds do not qualify it")
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    if cargo.get("profile", {}).get("release", {}).get("panic") != "unwind":
        parser.error("the release profile must explicitly use panic=unwind")
    # Cargo would otherwise accept unrecorded environment/config overrides.
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER",
                 "RUSTC_WORKSPACE_WRAPPER", "CARGO_PROFILE_RELEASE_PANIC"):
        if os.environ.get(name):
            parser.error(f"unset {name} before the pinned release build")
    if any(k.startswith("CARGO_TARGET_") and k.endswith("_RUSTFLAGS") for k in os.environ):
        parser.error("unset CARGO_TARGET_*_RUSTFLAGS before the pinned release build")
    metadata = json.loads(run("cargo", "+" + toolchain, "metadata", "--offline", "--locked",
                              "--format-version=1"))
    source = run("git", "rev-parse", "HEAD")
    argv = ["cargo", "+" + toolchain, "build", "--offline", "--locked", "--release",
            "--package", inputs["package"], "--no-default-features", "--target", args.target,
            "--jobs", "1", "--message-format=json-render-diagnostics"]
    if inputs["features"]:
        argv += ["--features", ",".join(inputs["features"])]
    built = subprocess.run(argv, cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE)
    artifacts = [json.loads(line) for line in built.stdout.splitlines() if line.strip()]
    artifacts = [a for a in artifacts if a.get("reason") == "compiler-artifact"]
    binary = [a for a in artifacts if a.get("executable") and a["target"]["name"] == "se"]
    if len(binary) != 1:
        raise ValueError("Cargo did not report exactly one se executable")
    out.mkdir(parents=True)
    name = "se.exe" if "windows" in args.target else "se"
    shutil.copyfile(binary[0]["executable"], out / name)
    (out / name).chmod(0o755)
    packages = {p["id"]: p for p in metadata["packages"]}
    features = {}
    notices = out / "notices"
    notices.mkdir()
    for artifact in artifacts:
        package = packages[artifact["package_id"]]
        key = f'{package["name"]}-{package["version"]}'
        features[key] = sorted(set(features.get(key, []) + artifact["features"]))
        if package["source"] is None:
            continue
        crate = Path(package["manifest_path"]).parent
        texts = {p for pattern in ("LICENSE*", "COPYING*", "NOTICE*") for p in crate.glob(pattern)
                 if p.is_file() and not p.is_symlink()}
        if package.get("license_file"):
            texts.add(crate / package["license_file"])
        if not texts:
            raise ValueError(f"license texts missing for {key}; supply its licensed offline inputs")
        dest = notices / key
        dest.mkdir(exist_ok=True)
        (dest / "package.json").write_text(json.dumps({k: package.get(k) for k in
            ("name", "version", "source", "license", "repository")}, indent=2) + "\n")
        for path in sorted(texts):
            shutil.copyfile(path, dest / path.name)
    sysroot = Path(run("rustc", "+" + toolchain, "--print", "sysroot"))
    rust_notices = sysroot / "share/doc/rust"
    if not (rust_notices / "licenses").is_dir() or not (rust_notices / "COPYRIGHT.html").is_file():
        raise ValueError("Rust toolchain notices are absent; install its documentation component")
    shutil.copytree(rust_notices / "licenses", notices / "rust-toolchain")
    shutil.copyfile(rust_notices / "COPYRIGHT.html", notices / "rust-toolchain/COPYRIGHT.html")
    manifest = {"schema": "se.release-build/v1", "variant": "standalone", "trust": "unsigned",
        "source_commit": source, "source_tree": run("git", "rev-parse", "HEAD^{tree}"),
        "source_timestamp": int(run("git", "show", "-s", "--format=%ct", "HEAD")),
        "version": cargo["workspace"]["package"]["version"], "target": args.target,
        "toolchain": toolchain, "compiler": compiler, "panic": "unwind",
        "default_features": False, "features": inputs["features"], "compiled_features": features,
        "cargo_lock_sha256": digest(ROOT / "Cargo.lock"),
        "inputs_sha256": digest(ROOT / "scripts/release/inputs.json"),
        "release_assets": {p.name: digest(p) for p in sorted((ROOT / "scripts/release").iterdir())
                           if p.is_file()},
        "api_schema_sources": {p: digest(ROOT / p) for p in inputs["api_schema_sources"]},
        "files": {p.relative_to(out).as_posix(): digest(p) for p in sorted(out.rglob("*")) if p.is_file()}}
    # A source change during a build must not acquire the old source pin.
    if run("git", "rev-parse", "HEAD") != source or run("git", "status", "--porcelain"):
        raise ValueError("source changed while compiling; discard this unpinned build output")
    (out / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(out / "build.json")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"release build refused: {error}", file=sys.stderr)
        sys.exit(1)
