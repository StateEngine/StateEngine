#!/usr/bin/env python3
"""Build the standalone CLI from lockfile-pinned inputs, fetching them by default.

Pass --offline to build only from the local Cargo cache instead.
"""
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


def license_texts(package):
    """Include version-pinned source texts when a published crate omits them."""
    crate = Path(package["manifest_path"]).parent
    key = f'{package["name"]}-{package["version"]}'
    supplement = ROOT / "scripts/release/licenses" / key
    texts = {}
    for directory in (crate, supplement):
        for path in sorted(directory.glob("*")):
            if (path.name.lower().startswith(("license", "copying", "notice"))
                    and path.is_file() and not path.is_symlink()):
                if path.name in texts and digest(texts[path.name]) != digest(path):
                    raise ValueError(f"license text differs from pinned input for {key}: {path.name}")
                texts[path.name] = path
    if package.get("license_file"):
        path = crate / package["license_file"]
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"declared license text is unavailable for {key}")
        texts.setdefault(path.name, path)
    if not texts:
        raise ValueError(f"license texts missing for {key}; supply its licensed offline inputs")
    return sorted(texts.values())


def run(*argv):
    return subprocess.run(argv, cwd=ROOT, check=True, text=True,
                          stdout=subprocess.PIPE, env={**os.environ, "RUSTUP_AUTO_INSTALL": "0"}).stdout.strip()


def checked_cargo_home():
    home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    home = (home if home.is_absolute() else ROOT / home).resolve()
    candidates = [ROOT / ".cargo/config", home / "config", home / "config.toml"]
    candidates += [parent / ".cargo" / name for parent in ROOT.parents for name in ("config", "config.toml")]
    for candidate in candidates:
        if candidate == ROOT / ".cargo/config.toml":
            continue  # The committed workspace configuration is the pinned input.
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        raise ValueError(f"external Cargo configuration is not a pinned build input: {candidate}; "
                         "use a clean parent path and a CARGO_HOME without configuration overrides")
    return home


def native_requirements(path, windows, target=None):
    apple = target is not None and target.endswith("apple-darwin")
    architecture = "aarch64" if target == "aarch64-apple-darwin" else "x86_64"
    with path.open("rb") as stream:
        header = stream.read(64)
        if windows:
            if header[:2] != b"MZ" or len(header) != 64:
                raise ValueError("expected a native Windows PE executable")
            stream.seek(struct.unpack_from("<I", header, 60)[0])
            valid = stream.read(6) == b"PE\0\0\x64\x86"
            stream.seek(struct.unpack_from("<I", header, 60)[0] + 24)
            valid = valid and stream.read(2) == b"\x0b\x02"
        elif apple:
            cpu = 0x0100000C if architecture == "aarch64" else 0x01000007
            valid = (len(header) >= 32 and header[:4] == b"\xcf\xfa\xed\xfe"
                     and struct.unpack_from("<I", header, 4)[0] == cpu
                     and struct.unpack_from("<I", header, 12)[0] == 2)
        else:
            valid = header[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", header, 18)[0] == 62
    if not valid:
        raise ValueError(f"native executable does not match target {target or architecture}")
    inspector = shutil.which("otool" if apple else "dumpbin.exe" if windows else "readelf")
    if not inspector:
        raise ValueError("install Xcode Command Line Tools, native binutils or Visual Studio Native Tools for this platform; dependency inspector is absent")
    options = ["-L"] if apple else ["/DEPENDENTS"] if windows else ["--wide", "--dynamic", "--program-headers", "--version-info"]
    environment = {**os.environ, "LC_ALL": "C"}
    report = subprocess.run([inspector, *options, str(path)], check=True, text=True,
                            stdout=subprocess.PIPE, env=environment).stdout
    pattern = (r"^\s+(.+?) \(compatibility version [^)]+\)\s*$" if apple else
               r"^\s+([\w.+-]+\.dll)\s*$" if windows else r"\(NEEDED\).*\[([^\]]+)\]")
    needed = sorted(set(re.findall(pattern, report, re.M | re.I)))
    if not needed:
        raise ValueError("dependency inspector reported no readable native requirements")
    if windows and any(re.match(r"(vcruntime|msvcp|ucrtbase|api-ms-win-crt)", name, re.I) for name in needed):
        raise ValueError("Windows release unexpectedly requires a separate C runtime")
    if apple and any(not name.startswith(("/usr/lib/", "/System/Library/")) for name in needed):
        raise ValueError("macOS archive requires a non-system dynamic library")
    interpreters = re.findall(r"Requesting program interpreter: ([^\]]+)", report) if not (windows or apple) else []
    if not (windows or apple) and len(interpreters) != 1:
        raise ValueError("GNU/Linux executable must report exactly one dynamic interpreter")
    return {"format": "Mach-O64" if apple else "PE32+" if windows else "ELF64", "architecture": architecture,
            "needed": needed, "interpreter": None if windows or apple else interpreters[0],
            "symbol_versions": [] if windows or apple else sorted(set(re.findall(r"Name: ([\w.]+)", report))),
            "inspector_sha256": digest(Path(inspector))}


def strip_binary(path, target, sysroot, cargo_artifact):
    """Strip with the pinned compiler's own tool, retaining cheap diagnostics."""
    windows = target.endswith("windows-msvc")
    tool = sysroot / "lib/rustlib" / target / "bin" / ("rust-objcopy.exe" if windows else "rust-objcopy")
    if not tool.is_file():
        raise ValueError("the pinned Rust compiler's rust-objcopy is absent; reinstall the pinned toolchain")
    environment = dict(os.environ)
    if windows:
        prefixes = [str(sysroot / "bin"), str(sysroot / "lib")]
        environment["PATH"] = os.pathsep.join(prefixes + [environment.get("PATH", "")])
    else:
        loader = "DYLD_LIBRARY_PATH" if target.endswith("apple-darwin") else "LD_LIBRARY_PATH"
        environment[loader] = os.pathsep.join([str(sysroot / "lib"), environment.get(loader, "")])
    before = {"sha256": digest(path), "bytes": path.stat().st_size}
    retained = []

    def objcopy(*arguments):
        subprocess.run([str(tool), *map(str, arguments)], check=True, env=environment)

    if target.endswith("linux-gnu"):
        symbols = path.parent / "symbols" / (path.name + ".debug")
        symbols.parent.mkdir()
        objcopy("--only-keep-debug", path, symbols)
        retained.append(symbols.relative_to(path.parent).as_posix())
    elif windows:
        pdb = Path(cargo_artifact).with_suffix(".pdb")
        if pdb.is_file():
            symbols = path.parent / "symbols" / pdb.name
            symbols.parent.mkdir()
            shutil.copyfile(pdb, symbols)
            retained.append(symbols.relative_to(path.parent).as_posix())
    objcopy("--strip-all", path)
    if target.endswith("linux-gnu"):
        objcopy("--add-gnu-debuglink=" + str(symbols), path)
    return {"mode": "all", "tool_sha256": digest(tool), "unstripped": before,
            "stripped": {"sha256": digest(path), "bytes": path.stat().st_size},
            "diagnostics": {"state": "retained" if retained else "not_retained", "files": retained,
                "reason": None if retained else ("the build produced no PDB" if windows
                    else "a separate native symbol bundle was not produced")}}


def feature_arguments(inputs):
    arguments = ["--no-default-features"]
    if inputs["features"]:
        arguments += ["--features", ",".join(inputs["features"])]
    return arguments


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--out", required=True, type=Path,
                        help="new build-output directory outside the source tree")
    parser.add_argument("--offline", action="store_true",
                        help="build only from the local Cargo cache instead of fetching the lockfile-pinned inputs")
    args = parser.parse_args()
    offline = ["--offline"] if args.offline else []
    inputs = json.loads((ROOT / "scripts/release/inputs.json").read_text())
    if args.target not in inputs["targets"]:
        parser.error("target is not in scripts/release/inputs.json")
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents or out.exists():
        parser.error("--out must be a new directory outside the source tree")
    if run("git", "status", "--porcelain", "--untracked-files=all"):
        parser.error("commit the release source first; the source tree is not clean")
    cargo_home = checked_cargo_home()
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
    overrides = ["--config", 'build.rustc-wrapper=""', "--config", 'build.rustc-workspace-wrapper=""',
                 "--config", 'profile.release.panic="unwind"',
                 "--config", 'profile.distribution.panic="unwind"']
    features_selected = feature_arguments(inputs)
    metadata = json.loads(run("cargo", "+" + toolchain, *overrides, "metadata", *offline, "--locked",
                              *features_selected, "--filter-platform", args.target, "--format-version=1"))
    source = run("git", "rev-parse", "HEAD")
    epoch = int(run("git", "show", "-s", "--format=%ct", "HEAD"))
    sysroot = Path(run("rustc", "+" + toolchain, "--print", "sysroot"))
    config = tomllib.loads((ROOT / ".cargo/config.toml").read_text())
    flags = config.get("target", {}).get(args.target, {}).get("rustflags", [])
    argv = ["cargo", "+" + toolchain, *overrides, "build", *offline, "--locked", "--profile", "distribution",
            "--package", inputs["package"], *features_selected, "--target", args.target,
            "--jobs", "1", "--message-format=json-render-diagnostics"]
    name = "se.exe" if "windows" in args.target else "se"
    # Never copy a cached Cargo artifact as an independent rebuild. Both source
    # and scratch prefixes are normalized before compilation, not after hashing.
    with tempfile.TemporaryDirectory(prefix="se-native-build-") as target:
        mappings = [(ROOT, "/stateengine/source"), (cargo_home, "/rust/cargo"),
                    (sysroot, "/rust/toolchain"), (Path(target), "/stateengine/target")]
        remaps = [f"--remap-path-prefix={spelling}={replacement}" for prefix, replacement in mappings
                  for spelling in sorted({str(prefix), prefix.as_posix()})]
        environment = {**os.environ, "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags + remaps),
                       "SOURCE_DATE_EPOCH": str(epoch), "CARGO_INCREMENTAL": "0", "RUSTUP_AUTO_INSTALL": "0"}
        built = subprocess.run(argv + ["--target-dir", target], cwd=ROOT, check=True, text=True,
                               stdout=subprocess.PIPE, env=environment)
        artifacts = [json.loads(line) for line in built.stdout.splitlines() if line.strip()]
        artifacts = [a for a in artifacts if a.get("reason") == "compiler-artifact"]
        binary = [a for a in artifacts if a.get("executable") and a["target"]["name"] == "se"]
        if len(binary) != 1:
            raise ValueError("Cargo did not report exactly one se executable")
        out.mkdir(parents=True)
        shutil.copyfile(binary[0]["executable"], out / name)
        stripping = strip_binary(out / name, args.target, sysroot, binary[0]["executable"])
    (out / name).chmod(0o755)
    requirements = native_requirements(out / name, "windows" in args.target, args.target)
    version = subprocess.run([str(out / name), "--version"], cwd=out, check=True, text=True,
        stdout=subprocess.PIPE, env={k: v for k, v in {**os.environ, "PATH": ""}.items()
                                    if k in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP")}).stdout.strip()
    packages = {p["id"]: p for p in metadata["packages"]}
    features = {}
    notices = out / "notices"
    notices.mkdir()
    (notices / "stateengine").mkdir()
    shutil.copyfile(ROOT / "LICENSE", notices / "stateengine/LICENSE")
    for artifact in artifacts:
        package = packages[artifact["package_id"]]
        key = f'{package["name"]}-{package["version"]}'
        features[key] = sorted(set(features.get(key, []) + artifact["features"]))
        if package["id"] in metadata["workspace_members"]:
            continue
        texts = license_texts(package)
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
        "profile": "distribution",
        "rustflags": flags, "source_date_epoch": epoch, "fresh_target": True,
        "cargo_config_overrides": overrides,
        "path_remap": {name: value for name, (_, value) in zip(("source", "cargo", "toolchain", "target"), mappings)},
        "native_requirements": requirements, "version_stdout": version, "stripping": stripping,
        "default_features": False, "offline": args.offline,
        "features": inputs["features"], "compiled_features": features,
        "cargo_lock_sha256": digest(ROOT / "Cargo.lock"),
        "inputs_sha256": digest(ROOT / "scripts/release/inputs.json"),
        "release_assets": {p.name: digest(p) for p in sorted((ROOT / "scripts/release").iterdir())
                           if p.is_file()},
        "api_schema_sources": {p: digest(ROOT / p) for p in inputs["api_schema_sources"]},
        "files": {p.relative_to(out).as_posix(): digest(p) for p in sorted(out.rglob("*")) if p.is_file()}}
    # A source change during a build must not acquire the old source pin.
    if run("git", "rev-parse", "HEAD") != source or run("git", "status", "--porcelain"):
        raise ValueError("source changed while compiling; discard this unpinned build output")
    checked_cargo_home()
    (out / "build.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(out / "build.json")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, struct.error, subprocess.CalledProcessError) as error:
        print(f"release build refused: {error}", file=sys.stderr)
        sys.exit(1)
