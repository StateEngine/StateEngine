"""Judge release metadata selection and real archive assembly, without compiling.

Archive fixtures have format headers, not runnable platform executables. These
checks do not qualify native installation or reproducible release compilation.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / "scripts/release"
INPUTS = json.loads((RELEASE / "inputs.json").read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def header(target):
    value = bytearray(128)
    if target.endswith("windows-msvc"):
        value[:2] = b"MZ"
        struct.pack_into("<I", value, 60, 64)
        value[64:70] = b"PE\0\0\x64\x86"
    elif target.endswith("apple-darwin"):
        value[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<I", value, 4,
                         0x0100000C if target.startswith("aarch64") else 0x01000007)
        struct.pack_into("<I", value, 12, 2)
    else:
        value[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", value, 18, 62)
    return value


class ArchiveAssembly(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="se-package-review-")
        self.root = Path(self.scratch.name)
        self.addCleanup(self.scratch.cleanup)
        self.builds = {}
        for target in INPUTS["targets"]:
            directory = self.root / target
            directory.mkdir()
            executable = "se.exe" if target.endswith("windows-msvc") else "se"
            (directory / executable).write_bytes(header(target))
            notices = directory / "notices"
            notices.mkdir()
            (notices / "fixture.txt").write_text("Synthetic package notice.\n")
            metadata = {
                "schema": "se.release-build/v1", "variant": "standalone",
                "trust": "unsigned", "target": target, "version": "0.0.1",
                "source_commit": "1" * 40, "source_timestamp": 1700000000,
                "inputs_sha256": digest(RELEASE / "inputs.json"),
                "cargo_lock_sha256": digest(ROOT / "Cargo.lock"),
                "features": INPUTS["features"],
                "release_assets": {p.name: digest(p) for p in RELEASE.iterdir()
                                   if p.is_file()},
                "files": {p.relative_to(directory).as_posix(): digest(p)
                          for p in directory.rglob("*") if p.is_file()},
            }
            (directory / "build.json").write_text(json.dumps(metadata))
            self.builds[target] = directory

    def assemble(self, target, label, *options):
        output = self.root / label
        result = subprocess.run(
            [sys.executable, str(RELEASE / "assemble.py"), "--build",
             str(self.builds[target]), "--out", str(output), *options],
            capture_output=True, text=True, timeout=30,
        )
        return result, output

    def unpack(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        archive = Path(json.loads(result.stdout)["archive"])
        checksum = archive.with_suffix(archive.suffix + ".sha256").read_text()
        self.assertEqual(checksum, f"{digest(archive)}  {archive.name}\n")
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as stream:
                files = {name.split("/", 1)[1]: stream.read(name)
                         for name in stream.namelist()}
        else:
            with tarfile.open(archive) as stream:
                files = {member.name.split("/", 1)[1]: stream.extractfile(member).read()
                         for member in stream.getmembers() if member.isfile()}
        manifest = json.loads(files["manifest.json"])
        self.assertEqual(set(files), set(manifest["files"]) | {"manifest.json", "SHA256SUMS"})
        for name, entry in manifest["files"].items():
            self.assertEqual(entry["sha256"], hashlib.sha256(files[name]).hexdigest(), name)
            self.assertEqual(entry["bytes"], len(files[name]), name)
        sums = {}
        for line in files["SHA256SUMS"].decode().splitlines():
            checksum, name = line.split("  ")
            self.assertNotIn(name, sums)
            sums[name] = checksum
        self.assertEqual(set(sums), set(files) - {"SHA256SUMS"})
        for name, checksum in sums.items():
            self.assertEqual(checksum, hashlib.sha256(files[name]).hexdigest(), name)
        return archive, files

    def test_native_archives_are_explicit_and_inventory_covers_installer(self):
        for target in INPUTS["targets"][:2]:
            with self.subTest(target=target):
                result, _ = self.assemble(target, target + "-native", "--native-only")
                archive, files = self.unpack(result)
                self.assertIn("-native-only-unsigned", archive.name)
                self.assertIn(b"omits remote bootstrap images", files["README.txt"])
                self.assertFalse(any(name.startswith("remote-images/") for name in files))
                installer = "install.ps1" if target.endswith("windows-msvc") else "install.sh"
                self.assertEqual(files[installer], (RELEASE / installer).read_bytes())

    def test_omitting_native_option_still_refuses_missing_full_release_companions(self):
        for target in INPUTS["targets"][:2]:
            with self.subTest(target=target):
                result, output = self.assemble(target, target + "-missing")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("every other supported target", result.stderr)
                self.assertFalse(output.exists())

    def test_full_release_has_every_companion_and_distinct_name(self):
        for target in INPUTS["targets"][:2]:
            with self.subTest(target=target):
                options = [part for other, directory in self.builds.items()
                           if other != target for part in ("--remote-build", str(directory))]
                result, _ = self.assemble(target, target + "-full", *options)
                archive, files = self.unpack(result)
                self.assertNotIn("native-only", archive.name)
                self.assertNotIn(b"omits remote bootstrap images", files["README.txt"])
                expected = {f"remote-images/{other}/" +
                            ("se.exe" if other.endswith("windows-msvc") else "se")
                            for other in INPUTS["targets"] if other != target}
                self.assertEqual({name for name in files if name.startswith("remote-images/")}, expected)

    def test_native_option_cannot_mix_companions(self):
        target, other = INPUTS["targets"][:2]
        result, output = self.assemble(target, "mixed", "--native-only",
                                       "--remote-build", str(self.builds[other]))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot include --remote-build", result.stderr)
        self.assertFalse(output.exists())

    def test_native_option_does_not_bypass_payload_checksum(self):
        target = INPUTS["targets"][1]
        binary = self.builds[target] / "se.exe"
        binary.write_bytes(binary.read_bytes() + b"changed")
        result, output = self.assemble(target, "tampered", "--native-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertFalse(output.exists())


class MetadataSelection(unittest.TestCase):
    def test_metadata_selects_compile_features_and_platform(self):
        # Stop before compilation, after running the real locked offline Cargo
        # metadata consumer. The synthetic compiler host admits both target
        # command shapes; it is not evidence of native Windows execution.
        spec = importlib.util.spec_from_file_location("release_build_judge", RELEASE / "build.py")
        module = importlib.util.module_from_spec(spec)
        with patch.object(sys, "dont_write_bytecode", True):
            spec.loader.exec_module(module)
        original_run = subprocess.run

        class CompilationReached(Exception):
            pass

        for target in INPUTS["targets"][:2]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as scratch:
                calls = {}

                def run(*argv):
                    if argv[:3] == ("git", "status", "--porcelain"):
                        return ""
                    if argv[0] == "rustc" and argv[-1] == "-vV":
                        return "host: " + target
                    if argv[0] == "cargo" and "metadata" in argv:
                        calls["metadata"] = argv
                    result = original_run(argv, cwd=ROOT, check=True, text=True,
                                          stdout=subprocess.PIPE)
                    if argv[0] == "cargo" and "metadata" in argv:
                        calls["packages"] = {(p["name"], p["version"])
                                             for p in json.loads(result.stdout)["packages"]}
                    return result.stdout.strip()

                def intercept(argv, **kwargs):
                    if argv[0] == "cargo" and "build" in argv:
                        calls["build"] = argv
                        raise CompilationReached
                    return original_run(argv, **kwargs)

                environment = {k: v for k, v in os.environ.items()
                               if not k.startswith(("RUSTFLAGS", "RUSTC", "CARGO_ENCODED_RUSTFLAGS",
                                                    "CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_BUILD_RUST"))}
                with patch.dict(os.environ, environment, clear=True), \
                        patch.object(module, "run", run), \
                        patch.object(module, "checked_cargo_home", lambda: Path.home() / ".cargo"), \
                        patch.object(subprocess, "run", intercept), \
                        patch.object(sys, "argv", ["build.py", "--target", target, "--offline",
                                                   "--out", str(Path(scratch) / "build")]):
                    with self.assertRaises(CompilationReached):
                        module.main()
                # Independently ask Cargo for the compilation dependency graph:
                # every emitted package must have metadata for notice collection.
                graph = original_run(
                    ["cargo", "tree", "--offline", "--locked", "--package", INPUTS["package"],
                     "--no-default-features", "--features", ",".join(INPUTS["features"]),
                     "--target", target, "--edges", "normal,build", "--prefix", "none",
                     "--format", "{p}"], cwd=ROOT, check=True, text=True,
                    stdout=subprocess.PIPE, env=environment,
                ).stdout
                dependencies = set(re.findall(r"^(\S+) v(\S+)", graph, re.M))
                self.assertGreater(len(dependencies), 1)
                self.assertFalse(dependencies - calls["packages"],
                                 "compiled dependencies have no release notice metadata")
                for phase in ("metadata", "build"):
                    self.assertIn("--no-default-features", calls[phase])
                    position = calls[phase].index("--features")
                    self.assertEqual(calls[phase][position + 1], ",".join(INPUTS["features"]))
                position = calls["metadata"].index("--filter-platform")
                self.assertEqual(calls["metadata"][position + 1], target)


if __name__ == "__main__":
    unittest.main()
