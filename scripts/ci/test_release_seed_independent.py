"""Exercise seed restoration with real dependency compilation and hostile paths."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "scripts/release/build.py"
SPEC = importlib.util.spec_from_file_location("seed_release", BUILD)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
TARGET = "x86_64-unknown-linux-gnu"


class SeedIndependent(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="release-seed-independent-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def test_archive_cannot_restore_an_absolute_suffix_outside_target(self):
        target = self.work / "target"
        target.mkdir()
        escaped = self.work / "outside" / "created-by-archive"
        key = {"synthetic": True}
        manifest = {"schema": MODULE.SEED_SCHEMA, "key": key}
        archive = self.work / "seed.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name, data in [
                ("seed.json", json.dumps(manifest).encode()),
                ("target/" + str(escaped), b"outside the build target"),
            ]:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
        try:
            MODULE.restore_seed(archive, target, key)
        except ValueError:
            pass
        self.assertFalse(escaped.exists(), "archive wrote outside the target directory")

    def command(self, *args, cwd=None, env=None):
        result = subprocess.run(args, cwd=cwd or self.source, env=env or self.environment,
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0,
                         f"command {args[:3]} failed: {result.stdout}\n{result.stderr}")
        return result.stdout.strip()

    def fixture(self):
        if sys.platform != "linux" or not shutil.which("cargo"):
            self.skipTest("this native Cargo control requires Linux and Cargo")
        self.source = self.work / "source"
        self.source.mkdir()
        self.environment = {k: v for k, v in os.environ.items()
                            if not k.startswith(("CARGO_", "RUSTC", "RUSTFLAGS"))}
        self.environment.update({"CARGO_HOME": str(self.work / "cargo-home"),
                                 "RUSTUP_AUTO_INSTALL": "0"})
        toolchain = self.command("rustc", "-vV").splitlines()[0].split()[1]
        contents = {
            "Cargo.toml": '''[workspace]
resolver = "2"
members = ["crates/se"]
[workspace.package]
version = "0.0.1"
edition = "2021"
license = "MIT-0"
[profile.release]
panic = "unwind"
[profile.distribution]
inherits = "release"
opt-level = 0
debug = false
lto = false
''',
            ".cargo/config.toml": "# No local configuration overrides.\n",
            "rust-toolchain.toml": f'[toolchain]\nchannel = "{toolchain}"\n',
            "LICENSE": "MIT No Attribution\n",
            "crates/se/Cargo.toml": '''[package]
name = "se"
version.workspace = true
edition.workspace = true
license.workspace = true
[dependencies]
independent-dependency = { path = "../../../dependency" }
''',
            "crates/se/src/main.rs": '''fn main() {
    if std::env::args().any(|arg| arg == "--version") {
        println!("se 0.0.1");
    } else {
        println!("{}", independent_dependency::value());
    }
}
''',
            "scripts/release/inputs.json": json.dumps({
                "package": "se", "features": [], "targets": [TARGET],
                "api_schema_sources": []}),
        }
        for relative, value in contents.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        self.script = self.source / "scripts/release/build.py"
        shutil.copyfile(BUILD, self.script)
        dependency = self.work / "dependency"
        (dependency / "src").mkdir(parents=True)
        (dependency / "Cargo.toml").write_text(
            '[package]\nname = "independent-dependency"\nversion = "0.0.1"\nedition = "2021"\nlicense = "MIT-0"\n')
        (dependency / "LICENSE").write_text("MIT No Attribution\n")
        self.dep_source = dependency / "src/lib.rs"
        self.dep_source.write_text('pub fn value() -> &\'static str { "seed-old" }\n')
        os.utime(self.dep_source, (1_700_000_000, 1_700_000_000))
        self.command("cargo", "generate-lockfile", "--offline")
        self.command("git", "init", "-q")
        self.command("git", "config", "user.name", "Synthetic fixture")
        self.command("git", "config", "user.email", "fixture@example.invalid")
        self.commit_fixture()
        self.scratch = self.work / "scratch"

    def commit_fixture(self):
        paths = [str(p.relative_to(self.source)) for p in self.source.rglob("*")
                 if p.is_file() and ".git" not in p.relative_to(self.source).parts]
        self.command("git", "add", "--", *paths)
        env = {**self.environment, "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
               "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}
        result = subprocess.run(["git", "commit", "-q", "-F", "-", "--", *paths],
                                input="Record synthetic fixture.\n", text=True,
                                capture_output=True, cwd=self.source, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)

    def build(self, label, *options, target_dir=True):
        if self.scratch.exists():
            shutil.rmtree(self.scratch)
        out = self.work / label
        args = [sys.executable, str(self.script), "--target", TARGET, "--offline", "--out", str(out)]
        if target_dir:
            args += ["--target-dir", str(self.scratch)]
        self.command(*args, *options)
        return out, json.loads((out / "build.json").read_text())

    def test_restored_mtime_dependency_change_matches_a_fresh_build(self):
        self.fixture()
        seed = self.work / "seed.tar.gz"
        self.build("seed-source", "--seed-out", str(seed))
        self.assertTrue(seed.is_file(), "a dependency seed was not published")
        before = self.dep_source.stat()
        self.dep_source.write_text(self.dep_source.read_text().replace("seed-old", "seed-new"))
        os.utime(self.dep_source, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(self.dep_source.stat().st_mtime_ns, before.st_mtime_ns)
        seeded, _ = self.build("seeded", "--seed", str(seed))
        fresh, _ = self.build("fresh")
        actual = self.command(str(seeded / "se"))
        expected = self.command(str(fresh / "se"))
        self.assertEqual(actual, expected, "seeded executable retained old dependency source")
        self.assertEqual((seeded / "se").read_bytes(), (fresh / "se").read_bytes(),
                         "seeded output differs from an independent fresh build")

    def test_each_version_of_a_path_package_binds_its_source_bytes(self):
        self.fixture()
        second = self.work / "dependency-v2"
        (second / "src").mkdir(parents=True)
        (second / "Cargo.toml").write_text(
            '[package]\nname = "independent-dependency"\nversion = "0.0.2"\nedition = "2021"\nlicense = "MIT-0"\n')
        (second / "LICENSE").write_text("MIT No Attribution\n")
        (second / "src/lib.rs").write_text(self.dep_source.read_text())
        os.utime(second / "src/lib.rs", (1_700_000_000, 1_700_000_000))
        manifest = self.source / "crates/se/Cargo.toml"
        with manifest.open("a") as stream:
            stream.write('other-dependency = { package = "independent-dependency", path = "../../../dependency-v2" }\n')
        main = self.source / "crates/se/src/main.rs"
        main.write_text(main.read_text().replace(
            'println!("{}", independent_dependency::value());',
            'println!("{}:{}", independent_dependency::value(), other_dependency::value());'))
        self.command("cargo", "generate-lockfile", "--offline")
        metadata = json.loads(self.command("cargo", "metadata", "--offline", "--format-version", "1"))
        dependencies = [p for p in metadata["packages"] if p["name"] == "independent-dependency"]
        self.assertEqual(len(dependencies), 2)
        self.commit_fixture()
        seed = self.work / "seed.tar.gz"
        self.build("two-version-seed", "--seed-out", str(seed))
        changed = Path(dependencies[0]["manifest_path"]).parent / "src/lib.rs"
        before = changed.stat()
        changed.write_text(changed.read_text().replace("seed-old", "seed-new"))
        os.utime(changed, ns=(before.st_atime_ns, before.st_mtime_ns))
        seeded, _ = self.build("two-version-seeded", "--seed", str(seed))
        fresh, _ = self.build("two-version-fresh")
        self.assertEqual(self.command(str(seeded / "se")), self.command(str(fresh / "se")),
                         "one version's dependency hashes overwrote the other version")
        self.assertEqual((seeded / "se").read_bytes(), (fresh / "se").read_bytes())

    def test_default_off_accepts_dependency_version_build_metadata(self):
        self.fixture()
        manifest = self.dep_source.parent.parent / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace('version = "0.0.1"',
                                                       'version = "0.0.1+seed.1"'))
        self.command("cargo", "generate-lockfile", "--offline")
        self.commit_fixture()
        built, _ = self.build("version-metadata", target_dir=False)
        self.assertEqual(self.command(str(built / "se")), "seed-old")

    def test_default_off_build_matches_the_parent_release_builder(self):
        self.fixture()
        candidate, manifest = self.build("default-candidate", target_dir=False)
        self.assertTrue(manifest["fresh_target"])
        self.assertIsNone(manifest["seed"])
        self.assertIsNone(manifest["seed_published"])
        self.assertEqual(manifest["build_units"], {
            "compiled": {"total": 2, "workspace_members": 1},
            "fresh": {"total": 0, "workspace_members": 0}})
        self.assertEqual(self.command(str(candidate / "se")), "seed-old")
        base = os.environ.get("RELEASE_BASE_BUILD")
        if base is None:
            return
        shutil.copyfile(base, self.script)
        self.commit_fixture()
        parent, _ = self.build("default-parent", target_dir=False)
        self.assertEqual((candidate / "se").read_bytes(), (parent / "se").read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
