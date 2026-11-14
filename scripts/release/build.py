#!/usr/bin/env python3
"""Build the standalone CLI from lockfile-pinned inputs, fetching them by default.

Pass --offline to build only from the local Cargo cache instead. Pass --seed to
restore dependency artifacts from a seed archive built from the same pinned inputs
(lock file, build settings, and the bytes of every path dependency), and
--seed-out to publish such a dependency-only seed after a successful build.
Workspace crates are always compiled fresh; only non-member dependency artifacts
are ever restored or republished.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]

# Source and scratch prefixes are normalized before compilation, so a dependency
# seed built on one machine fingerprints identically on another with the same key.
REMAPPED = {"source": "/stateengine/source", "cargo": "/rust/cargo",
            "toolchain": "/rust/toolchain", "target": "/stateengine/target"}
SEED_SCHEMA = "se.release-build-seed/v1"


def system_root_env():
    # A PATH-less child environment that keeps the OS root variables under any runner
    # casing: Winsock refuses to initialize a child environment that lost its system
    # root (WinError 10106), and hosted runners do not guarantee the classic mixed case.
    system = {'path', 'systemroot', 'windir', 'temp', 'tmp'}
    taken = set()
    env = {}
    for key, value in {**os.environ, 'PATH': ''}.items():
        lowered = key.lower()
        if lowered in system and lowered not in taken:
            taken.add(lowered)
            env[key] = value
    return env

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


class SeedKeyMismatch(ValueError):
    """A named seed was built from different pinned inputs; the build stays valid without it."""


def seed_manifest_from_archive(path):
    with tarfile.open(path, "r:gz") as archive:
        try:
            member = archive.getmember("seed.json")
        except KeyError:
            raise ValueError("seed archive has no seed.json manifest") from None
        if not member.isreg():
            raise ValueError("seed archive manifest is not a regular file")
        stream = archive.extractfile(member)
        if stream is None:
            raise ValueError("seed archive manifest is unreadable")
        return json.loads(stream.read())


def restore_seed(path, target, key):
    """Verify the seed key, then restore dependency artifacts into the fresh target directory.

    The key carries the content hashes the seed covers, so a changed dependency
    is refused before any archive byte is written. Restored files intentionally
    take extraction-time mtimes: Cargo's path-dependency freshness is
    mtime-based, and a key-matched seed is correct by bytes, so the restored
    fingerprint only needs to be at least as new as the sources it covers.
    """
    manifest = seed_manifest_from_archive(path)
    if manifest.get("schema") != SEED_SCHEMA:
        raise ValueError(f"seed archive schema differs: {str(manifest.get('schema'))[:40]}")
    stored = manifest.get("key")
    if stored != key:
        reasons = ", ".join(name for name in sorted(set(stored or {}) | set(key))
                            if (stored or {}).get(name) != key.get(name))
        raise SeedKeyMismatch(f"seed key differs: {reasons}")
    with tarfile.open(path, "r:gz") as archive:
        root = Path(target).resolve()
        for member in archive.getmembers():
            name = member.name
            if name in ("target", "seed.json"):
                continue
            if not name.startswith("target/"):
                raise ValueError(f"seed archive entry escapes the target tree: {name}")
            relative = name[len("target/"):]
            parts = PurePosixPath(relative).parts
            # Refuse rooted, absolute and drive forms in both platform
            # dialects before anything is written: a leading separator after
            # the prefix makes Path join discard the target directory.
            if (relative == "" or "\x00" in relative or "\\" in relative
                    or ":" in relative or ".." in parts
                    or not parts or parts[0].startswith("/")):
                raise ValueError(f"seed archive entry escapes the target tree: {name}")
            destination = Path(target) / relative
            if not destination.resolve().is_relative_to(root):
                raise ValueError(f"seed archive entry escapes the target tree: {name}")
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            elif member.isreg():
                destination.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                with stream, open(destination, "xb") as output:
                    shutil.copyfileobj(stream, output)
                # Cached build scripts must remain executable; mask to
                # permission bits from the archive.
                destination.chmod(member.mode & 0o777)
            else:
                raise ValueError(f"seed archive entry is not a plain file or directory: {name}")
    return manifest


def prune_workspace(target, toolchain, overrides, target_triple, members, environment):
    """Remove exactly the workspace members' artifacts, leaving dependency artifacts seedable."""
    tag = Path(target) / "CACHEDIR.TAG"
    if not tag.is_file():
        # A pre-created scratch directory has no cargo cache tag, and cargo clean refuses it.
        tag.write_text("Signature: 8a477f597d28d172789f06886806bc55\n"
                       "# This file is a cache directory tag created by cargo.\n"
                       "# For information about cache directory tags see https://bford.info/cachedir/\n")
    arguments = ["cargo", "+" + toolchain, *overrides, "clean", "--locked", "--profile",
                 "distribution", "--target", target_triple, "--target-dir", target]
    for member in members:
        arguments += ["-p", member]
    result = subprocess.run(arguments, cwd=ROOT, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    if result.returncode:
        raise RuntimeError(f"cargo clean exited {result.returncode}: {result.stderr.strip()[-400:]}")


def package_seed(target, path, key, created_from, members):
    """Package the remaining dependency artifacts as the next seed archive."""
    target = Path(target)
    manifest = {"schema": SEED_SCHEMA, "key": key, "created_from": created_from,
                "workspace_packages_removed": list(members)}
    with tarfile.open(path, "w:gz", compresslevel=1) as archive:
        for member in sorted(target.rglob("*")):
            if member.is_file():
                archive.add(member, arcname="target/" + member.relative_to(target).as_posix(),
                            recursive=False)
        data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        info = tarfile.TarInfo("seed.json")
        info.size = len(data)
        info.mtime = 0
        archive.addfile(info, io.BytesIO(data))
    return manifest


def build_units(artifacts, metadata):
    """The work cargo actually performed.

    Cargo reports a compiler-artifact event for every planned unit, naming the
    package id and carrying a fresh flag: false when this run compiled the
    unit, true when a valid fingerprint was reused. The plan, the compiled
    set and the fresh set all come from those events, so the witness is exact
    for any version string, and an artifact for a package outside the plan
    still refuses the build.
    """
    packages = {package["id"] for package in metadata["packages"]}
    members = set(metadata["workspace_members"])
    compiled = {}
    for artifact in artifacts:
        package_id = artifact["package_id"]
        if package_id not in packages:
            raise ValueError(f"cargo reported an artifact for unknown package {package_id}")
        if not isinstance(artifact.get("fresh"), bool):
            raise ValueError(f"cargo reported no usable fresh flag for {package_id}")
        compiled[package_id] = compiled.get(package_id, False) or not artifact["fresh"]
    compiled_total = sum(compiled.values())
    compiled_members = sum(1 for package_id, is_compiled in compiled.items()
                           if is_compiled and package_id in members)
    member_total = sum(1 for package_id in compiled if package_id in members)
    return {"compiled": {"total": compiled_total, "workspace_members": compiled_members},
            "fresh": {"total": len(compiled) - compiled_total,
                      "workspace_members": member_total - compiled_members}}


def path_dependency_sources(metadata):
    """Content hashes for the inputs only the seed key can bind by bytes.

    Cargo verifies registry crates against the lock file, but a path
    dependency outside the workspace has no such check and its freshness is
    mtime-based, so the seed key binds the exact bytes of every external path
    dependency; any change refuses the seed instead of reusing artifacts.
    Entries are keyed by the full package id (name, version and source),
    because one package name can occur at two versions of a path dependency.
    """
    covered = {}
    for package in metadata["packages"]:
        if not package["id"].startswith("path+"):
            continue
        if package["id"] in metadata["workspace_members"]:
            continue
        manifest = Path(package["manifest_path"]).parent
        files = {}
        for file in sorted(manifest.rglob("*")):
            if not file.is_file():
                continue
            relative = file.relative_to(manifest)
            if ".git" in relative.parts or "target" in relative.parts:
                continue
            files[relative.as_posix()] = digest(file)
        covered[package["id"]] = files
    return covered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--out", required=True, type=Path,
                        help="new build-output directory outside the source tree")
    parser.add_argument("--offline", action="store_true",
                        help="build only from the local Cargo cache instead of fetching the lockfile-pinned inputs")
    parser.add_argument("--seed", type=Path,
                        help="restore dependency artifacts from a seed archive built from the same pinned inputs")
    parser.add_argument("--seed-out", dest="seed_out", type=Path,
                        help="publish a dependency-only seed archive after a successful build")
    parser.add_argument("--target-dir", type=Path,
        help="dedicated scratch target directory, new or empty; keep its path constant across "
             "seeded runs so restored dependency fingerprints still match")
    args = parser.parse_args()
    offline = ["--offline"] if args.offline else []
    if args.seed is not None and not args.seed.is_file():
        parser.error(f"--seed archive is absent: {args.seed}")
    if args.seed_out is not None and args.seed_out.exists():
        parser.error(f"--seed-out archive already exists: {args.seed_out}")
    if args.target_dir is not None and args.target_dir.exists() and any(args.target_dir.iterdir()):
        parser.error("--target-dir must be a new or empty directory")
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
    seed_key = {"schema": "se.release-build-seed-key/v2", "toolchain": toolchain,
        "compiler": compiler, "target": args.target, "profile": "distribution",
        "rustflags": flags, "cargo_config_overrides": overrides,
        "cargo_lock_sha256": digest(ROOT / "Cargo.lock"),
        "inputs_sha256": digest(ROOT / "scripts/release/inputs.json"),
        "path_dependency_sources": path_dependency_sources(metadata),
        "path_remap": REMAPPED}
    argv = ["cargo", "+" + toolchain, *overrides, "build", *offline, "--locked", "--profile", "distribution",
            "--package", inputs["package"], *features_selected, "--target", args.target,
            "--jobs", "1", "--message-format=json-render-diagnostics"]
    name = "se.exe" if "windows" in args.target else "se"
    # Never copy a cached Cargo artifact as an independent rebuild. Both source
    # and scratch prefixes are normalized before compilation, not after hashing.
    if args.target_dir is not None:
        target = str(args.target_dir.resolve())
    else:
        target = tempfile.mkdtemp(prefix="se-native-build-")
    try:
        mappings = [(ROOT, REMAPPED["source"]), (cargo_home, REMAPPED["cargo"]),
                    (sysroot, REMAPPED["toolchain"]), (Path(target), REMAPPED["target"])]
        remaps = [f"--remap-path-prefix={spelling}={replacement}" for prefix, replacement in mappings
                  for spelling in sorted({str(prefix), prefix.as_posix()})]
        environment = {**os.environ, "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags + remaps),
                       "SOURCE_DATE_EPOCH": str(epoch), "CARGO_INCREMENTAL": "0", "RUSTUP_AUTO_INSTALL": "0"}
        seed_manifest = None
        if args.seed is not None:
            try:
                seed_manifest = restore_seed(args.seed, target, seed_key)
                print(f"restored dependency seed built from {seed_manifest['created_from']['source_commit']}",
                      file=sys.stderr)
            except SeedKeyMismatch as error:
                print(f"seed rejected, dependencies build fresh: {error}", file=sys.stderr)
        built = subprocess.run(argv + ["--target-dir", target], cwd=ROOT, check=True, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        sys.stderr.write(built.stderr)
        artifacts = [json.loads(line) for line in built.stdout.splitlines() if line.strip()]
        artifacts = [a for a in artifacts if a.get("reason") == "compiler-artifact"]
        binary = [a for a in artifacts if a.get("executable") and a["target"]["name"] == "se"]
        if len(binary) != 1:
            raise ValueError("Cargo did not report exactly one se executable")
        out.mkdir(parents=True)
        shutil.copyfile(binary[0]["executable"], out / name)
        stripping = strip_binary(out / name, args.target, sysroot, binary[0]["executable"])
        units = build_units(artifacts, metadata)
        seed_published = None
        seed_publication = None
        if args.seed_out is not None:
            try:
                prune_workspace(target, toolchain, overrides, args.target,
                                metadata["workspace_members"], environment)
                document = package_seed(target, args.seed_out, seed_key,
                    {"source_commit": source, "source_tree": run("git", "rev-parse", "HEAD^{tree}"),
                     "source_timestamp": epoch}, metadata["workspace_members"])
                sidecar = Path(str(args.seed_out) + ".key.json")
                sidecar.write_text(json.dumps(
                    {**document, "archive_sha256": digest(args.seed_out),
                     "archive_bytes": args.seed_out.stat().st_size},
                    indent=2, sort_keys=True) + "\n")
                seed_published = {"sha256": digest(args.seed_out),
                                  "bytes": args.seed_out.stat().st_size}
            except Exception as error:  # the build itself is valid; the seed is a derived artifact
                seed_publication = f"refused: {error}"
    finally:
        if args.target_dir is None:
            shutil.rmtree(target, ignore_errors=True)
    (out / name).chmod(0o755)
    requirements = native_requirements(out / name, "windows" in args.target, args.target)
    version = subprocess.run([str(out / name), "--version"], cwd=out, check=True, text=True,
        stdout=subprocess.PIPE, env=system_root_env()).stdout.strip()
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
        "rustflags": flags, "source_date_epoch": epoch,
        "fresh_target": seed_manifest is None,
        "target_freshness": {"workspace": "fresh",
            "dependencies": "fresh" if seed_manifest is None else "seed"},
        "seed": None if seed_manifest is None else {"source_commit": seed_manifest["created_from"]["source_commit"],
            "archive_sha256": digest(args.seed),
            "workspace_packages_removed": seed_manifest["workspace_packages_removed"]},
        "seed_published": seed_published, "seed_publication": seed_publication,
        "build_units": units,
        "cargo_config_overrides": overrides,
        "path_remap": dict(REMAPPED),
        "native_requirements": requirements, "version_stdout": version, "stripping": stripping,
        "default_features": False, "offline": args.offline,
        "features": inputs["features"], "compiled_features": features,
        "cargo_lock_sha256": seed_key["cargo_lock_sha256"],
        "inputs_sha256": seed_key["inputs_sha256"],
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
