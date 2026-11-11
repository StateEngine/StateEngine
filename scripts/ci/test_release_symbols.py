"""Independent symbol-artifact and explicit feature-mode consumers."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_release_packaging as fixtures


class SymbolArchives(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ArchiveAssembly()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def add_symbols(self):
        for target, directory in self.fixture.builds.items():
            name = "se.pdb" if target.endswith("windows-msvc") else "se.debug"
            symbol = directory / "symbols" / name
            symbol.parent.mkdir()
            symbol.write_bytes(("synthetic symbols for " + target).encode())
            path = directory / "build.json"
            metadata = json.loads(path.read_text())
            metadata["files"]["symbols/" + name] = fixtures.digest(symbol)
            path.write_text(json.dumps(metadata))

    def test_full_archives_keep_each_targets_symbols_outside_the_payload(self):
        self.add_symbols()
        for target in fixtures.INPUTS["targets"]:
            with self.subTest(target=target):
                options = [argument for other, directory in self.fixture.builds.items()
                           if other != target for argument in ("--remote-build", str(directory))]
                result, _ = self.fixture.assemble(target, target + "-symbols", *options)
                _, files = self.fixture.unpack(result)
                self.assertFalse(any("symbols/" in name or name.endswith((".pdb", ".debug"))
                                     for name in files))
                external = json.loads(result.stdout)["symbols"]
                self.assertEqual(set(external), set(fixtures.INPUTS["targets"]))
                for platform, destination in external.items():
                    destination = Path(destination)
                    record = json.loads((destination / "manifest.json").read_text())
                    executable = "se.exe" if platform.endswith("windows-msvc") else "se"
                    self.assertEqual(record["target"], platform)
                    self.assertEqual(record["source_commit"], "1" * 40)
                    self.assertEqual(record["executable_sha256"],
                                     fixtures.digest(self.fixture.builds[platform] / executable))
                    self.assertEqual(len(record["files"]), 1)
                    for name, checksum in record["files"].items():
                        self.assertEqual(fixtures.digest(destination / name), checksum)

    def test_altered_primary_and_companion_symbols_refuse_before_archive_writes(self):
        self.add_symbols()
        primary = fixtures.INPUTS["targets"][0]
        for changed in fixtures.INPUTS["targets"][:2]:
            with self.subTest(changed=changed):
                directory = self.fixture.builds[changed]
                symbol = next((directory / "symbols").iterdir())
                original = symbol.read_bytes()
                symbol.write_bytes(original + b"altered")
                try:
                    options = [argument for other, build in self.fixture.builds.items()
                               if other != primary for argument in ("--remote-build", str(build))]
                    result, output = self.fixture.assemble(primary, changed + "-bad-symbols", *options)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("checksum mismatch", result.stderr)
                    self.assertFalse(output.exists())
                finally:
                    symbol.write_bytes(original)

    def test_an_archive_without_retained_symbols_reports_an_empty_symbol_set(self):
        result, _ = self.fixture.assemble(fixtures.INPUTS["targets"][0], "no-symbols", "--native-only")
        self.fixture.unpack(result)
        self.assertEqual(json.loads(result.stdout)["symbols"], {})


@unittest.skipUnless(sys.platform.startswith("linux"), "native ELF inspection runs on Linux")
class NativeStrip(unittest.TestCase):
    def test_real_stripping_preserves_execution_and_binds_the_separate_debug_file(self):
        spec = importlib.util.spec_from_file_location("release_symbols_build", fixtures.RELEASE / "build.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory(prefix="se-symbol-native-") as temporary:
            root = Path(temporary)
            source, binary = root / "probe.rs", root / "se"
            source.write_text('fn main() { println!("synthetic-symbol-probe"); }\n')
            subprocess.run(["rustc", "--crate-name", "symbol_probe", "-g", str(source), "-o", str(binary)],
                           cwd=fixtures.ROOT, check=True, capture_output=True, timeout=60)
            sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"],
                                                  cwd=fixtures.ROOT, text=True).strip())
            original = {"sha256": fixtures.digest(binary), "bytes": binary.stat().st_size}
            record = builder.strip_binary(binary, "x86_64-unknown-linux-gnu", sysroot, binary)
            self.assertEqual(record["unstripped"], original)
            self.assertLess(record["stripped"]["bytes"], original["bytes"])
            self.assertEqual(record["stripped"]["sha256"], fixtures.digest(binary))
            self.assertEqual(record["diagnostics"]["files"], ["symbols/se.debug"])
            self.assertEqual(record["diagnostics"]["state"], "retained")
            self.assertTrue((root / "symbols/se.debug").is_file())
            sections = subprocess.check_output(["readelf", "-SW", str(binary)], text=True)
            self.assertNotIn(".symtab", sections)
            self.assertNotIn(".debug_info", sections)
            self.assertIn(".gnu_debuglink", sections)
            reply = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(reply.returncode, 0, reply.stderr)
            self.assertEqual(reply.stdout, "synthetic-symbol-probe\n")


class ExplicitArchiveMode(unittest.TestCase):
    def test_actual_filter_cli_does_not_infer_all_features_from_the_event(self):
        with tempfile.TemporaryDirectory(prefix="se-feature-mode-") as temporary:
            root = Path(temporary)
            scripts = root / "scripts/ci"
            scripts.mkdir(parents=True)
            for name in ("custom.py", "input_judges.py"):
                shutil.copyfile(fixtures.ROOT / "scripts/ci" / name, scripts / name)
            (root / "Cargo.toml").write_text('[workspace]\nmembers = ["example"]\n')
            (root / "example").mkdir()
            (root / "example/Cargo.toml").write_text(
                '[package]\nname="example"\nversion="0.0.1"\n'
                '[[test]]\nname="custom"\nharness=false\n')
            environment = {k: v for k, v in os.environ.items()
                           if not k.startswith(("SE_", "JUDGE_"))}
            report = root / "target/nextest/input-judges.json"
            for event in ("schedule", "workflow_dispatch", "pull_request"):
                with self.subTest(event=event):
                    environment.update(GITHUB_EVENT_NAME=event, GITHUB_REF="refs/heads/main")
                    if report.exists():
                        report.unlink()
                    reply = subprocess.run([sys.executable, "-B", str(scripts / "custom.py"), "filter"],
                                           env=environment, capture_output=True, text=True, timeout=10)
                    self.assertEqual(reply.returncode, 0, reply.stderr)
                    self.assertIn("binary(=custom)", reply.stdout)
                    self.assertNotIn("binary(=secode_selectors)", reply.stdout)
                    self.assertFalse(report.exists(), "default archive acquired all-feature judge exclusions")
                    explicit = subprocess.run(
                        [sys.executable, "-B", str(scripts / "custom.py"), "filter", "--all-features"],
                        env=environment, capture_output=True, text=True, timeout=10)
                    self.assertEqual(explicit.returncode, 0, explicit.stderr)
                    self.assertIn("binary(=secode_selectors)", explicit.stdout)
                    data = json.loads(report.read_text())
                    self.assertGreater(len(data["not_run"]), 0)
                    self.assertTrue(all(row["status"] == "not_run" for row in data["not_run"]))


if __name__ == "__main__":
    unittest.main()
