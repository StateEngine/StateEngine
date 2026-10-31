#!/usr/bin/env python3
"""Build the standalone CLI from pinned, already available offline inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(*argv):
    return subprocess.run(argv, cwd=ROOT, check=True, text=True,
                          stdout=subprocess.PIPE).stdout.strip()


def native_requirements(path, windows):
    with path.open("rb") as stream:
        header = stream.read(64)
        if windows:
            if header[:2] != b"MZ" or len(header) != 64:
                raise ValueError("expected a native Windows PE executable")
            stream.seek(struct.unpack_from("<I", header, 60)[0])
            valid = stream.read(6) == b"PE\0\0\x64\x86"
            stream.seek(struct.unpack_from("<I", header, 60)[0] + 24)
            valid = valid and stream.read(2) == b"\x0b\x02"
        else:
            valid = header[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", header, 18)[0] == 62
    if not valid:
        raise ValueError("native executable architecture is not x86_64")
    inspector = shutil.which("dumpbin.exe" if windows else "readelf")
    if not inspector:
        raise ValueError("install native binutils or use the Visual Studio x64 Native Tools shell; dependency inspector is absent")
    options = ["/DEPENDENTS"] if windows else ["--wide", "--dynamic", "--program-headers", "--version-info"]
    environment = {**os.environ, "LC_ALL": "C"}
    report = subprocess.run([inspector, *options, str(path)], check=True, text=True,
                            stdout=subprocess.PIPE, env=environment).stdout
    pattern = r"^\s+([\w.+-]+\.dll)\s*$" if windows else r"\(NEEDED\).*\[([^\]]+)\]"
    needed = sorted(set(re.findall(pattern, report, re.M | re.I)))
    if not needed:
        raise ValueError("dependency inspector reported no readable native requirements")
    if windows and any(re.match(r"(vcruntime|msvcp|ucrtbase|api-ms-win-crt)", name, re.I) for name in needed):
        raise ValueError("Windows release unexpectedly requires a separate C runtime")
    interpreters = re.findall(r"Requesting program interpreter: ([^\]]+)", report) if not windows else []
    if not windows and len(interpreters) != 1:
        raise ValueError("GNU/Linux executable must report exactly one dynamic interpreter")
    return {"format": "PE32+" if windows else "ELF64", "architecture": "x86_64",
            "needed": needed, "interpreter": None if windows else interpreters[0],
            "symbol_versions": [] if windows else sorted(set(re.findall(r"Name: ([\w.]+)", report))),
            "inspector_sha256": digest(Path(inspector))}


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
                 "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP", "CARGO_BUILD_RUSTFLAGS",
                 "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"):
        if os.environ.get(name):
            parser.error(f"unset {name} before the pinned release build")
    if any(k.startswith("CARGO_PROFILE_") or
           (k.startswith("CARGO_TARGET_") and k.endswith(("_RUSTFLAGS", "_LINKER"))) for k in os.environ):
        parser.error("unset Cargo profile, target rustflags and target linker overrides before the pinned release build")
    metadata = json.loads(run("cargo", "+" + toolchain, "metadata", "--offline", "--locked",
                              "--format-version=1"))
    source = run("git", "rev-parse", "HEAD")
    epoch = int(run("git", "show", "-s", "--format=%ct", "HEAD"))
    sysroot = Path(run("rustc", "+" + toolchain, "--print", "sysroot"))
    config = tomllib.loads((ROOT / ".cargo/config.toml").read_text())
    flags = config.get("target", {}).get(args.target, {}).get("rustflags", [])
    argv = ["cargo", "+" + toolchain, "build", "--offline", "--locked", "--release",
            "--package", inputs["package"], "--no-default-features", "--target", args.target,
            "--jobs", "1", "--message-format=json-render-diagnostics"]
    if inputs["features"]:
        argv += ["--features", ",".join(inputs["features"])]
    name = "se.exe" if "windows" in args.target else "se"
    # Never copy a cached Cargo artifact as an independent rebuild. Both source
    # and scratch prefixes are normalized before compilation, not after hashing.
    with tempfile.TemporaryDirectory(prefix="se-native-build-") as target:
        mappings = [(ROOT, "/stateengine/source"), (Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).resolve(), "/rust/cargo"),
                    (sysroot, "/rust/toolchain"), (Path(target), "/stateengine/target")]
        remaps = [f"--remap-path-prefix={spelling}={replacement}" for prefix, replacement in mappings
                  for spelling in sorted({str(prefix), prefix.as_posix()})]
        environment = {**os.environ, "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags + remaps),
                       "SOURCE_DATE_EPOCH": str(epoch), "CARGO_INCREMENTAL": "0"}
        built = subprocess.run(argv + ["--target-dir", target], cwd=ROOT, check=True, text=True,
                               stdout=subprocess.PIPE, env=environment)
        artifacts = [json.loads(line) for line in built.stdout.splitlines() if line.strip()]
        artifacts = [a for a in artifacts if a.get("reason") == "compiler-artifact"]
        binary = [a for a in artifacts if a.get("executable") and a["target"]["name"] == "se"]
        if len(binary) != 1:
            raise ValueError("Cargo did not report exactly one se executable")
        out.mkdir(parents=True)
        shutil.copyfile(binary[0]["executable"], out / name)
    (out / name).chmod(0o755)
    requirements = native_requirements(out / name, "windows" in args.target)
    version = subprocess.run([str(out / name), "--version"], cwd=out, check=True, text=True,
        stdout=subprocess.PIPE, env={k: v for k, v in {**os.environ, "PATH": ""}.items()
                                    if k in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP")}).stdout.strip()
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
    rust_notices = sysroot / "share/doc/rust"
    if not (rust_notices / "licenses").is_dir() or not (rust_notices / "COPYRIGHT.html").is_file():
        raise ValueError("Rust toolchain notices are absent; install its documentation component")
    shutil.copytree(rust_notices / "licenses", notices / "rust-toolchain")
    shutil.copyfile(rust_notices / "COPYRIGHT.html", notices / "rust-toolchain/COPYRIGHT.html")
    manifest = {"schema": "se.release-build/v1", "variant": "standalone", "trust": "unsigned",
        "source_commit": source, "source_tree": run("git", "rev-parse", "HEAD^{tree}"),
        "source_timestamp": epoch,
        "version": cargo["workspace"]["package"]["version"], "target": args.target,
        "toolchain": toolchain, "compiler": compiler, "panic": "unwind",
        "rustflags": flags, "source_date_epoch": epoch, "fresh_target": True,
        "path_remap": {name: value for name, (_, value) in zip(("source", "cargo", "toolchain", "target"), mappings)},
        "native_requirements": requirements, "version_stdout": version,
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
    (out / "build.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(out / "build.json")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, struct.error, subprocess.CalledProcessError) as error:
        print(f"release build refused: {error}", file=sys.stderr)
        sys.exit(1)
