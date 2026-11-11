"""End-to-end dependency seed behavior for scripts/release/build.py.

Builds a small two-crate fixture workspace (one workspace member binary, one
external path dependency) with the real build.py, then proves that a second
build restores the dependency from the published seed and compiles only the
workspace member. Run from the repository root:

    python -m unittest scripts.release.test_release_seed -v
"""
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
BUILD_PY = HERE / "build.py"
TARGET = "x86_64-unknown-linux-gnu"


def rustc_version():
    return subprocess.run(["rustc", "-vV"], check=True, text=True,
                          stdout=subprocess.PIPE).stdout.splitlines()[0].split()[1]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


FIXTURE_CARGO = """\
[workspace]
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
codegen-units = 16
"""

FIXTURE_SE_CARGO = """\
[package]
name = "se"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
fixture-dep = { path = "../../../dep" }
"""

FIXTURE_DEP_CARGO = """\
[package]
name = "fixture-dep"
version = "0.0.1"
edition = "2021"
license = "MIT-0"
"""

FIXTURE_MAIN = """\
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--version" {
        println!("se 0.0.1 (fixture)");
        return;
    }
    println!("{}", fixture_dep::greet());
}
"""

FIXTURE_DEP_LIB = "\n".join([
    "pub fn greet() -> &'static str {",
    '    "fixture-dep"',
    "}",
    "",
])
LICENSE = "MIT-0 license text for the fixture.\n"


class SeedBuild(unittest.TestCase):
    def setUp(self):
        if shutil.which("cargo") is None or shutil.which("readelf") is None:
            self.skipTest("cargo and readelf are required for the seed fixture build")
        self.temporary = TemporaryDirectory(prefix="seed-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        # The dependency lives outside the workspace root, like a registry crate:
        # a path dependency inside the root would become an implicit member.
        self.root = self.work / "fixture"
        self.out_dir = self.work / "outputs"
        self.out_dir.mkdir()
        self.cargo_home = self.work / "cargo-home"
        self.cargo_home.mkdir()
        self.scratch = self.work / "target-scratch"
        self.environment = {**os.environ, "CARGO_HOME": str(self.cargo_home)}
        for name in list(self.environment):
            if name.startswith(("CARGO_", "RUSTFLAGS", "RUSTC")) and name != "CARGO_HOME":
                self.environment.pop(name)
        self.write_fixture()
        self.commit()

    def write_fixture(self):
        (self.root / ".cargo").mkdir(parents=True)
        (self.root / ".cargo/config.toml").write_text("# fixture: no target rustflags\n")
        (self.root / "Cargo.toml").write_text(FIXTURE_CARGO)
        (self.root / "LICENSE").write_text(LICENSE)
        (self.root / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "%s"\n' % rustc_version())
        scripts = self.root / "scripts/release"
        scripts.mkdir(parents=True)
        shutil.copyfile(BUILD_PY, scripts / "build.py")
        (scripts / "inputs.json").write_text(json.dumps({
            "schema": "se.release-inputs/v1", "variant": "standalone", "package": "se",
            "default_features": False, "features": [], "targets": [TARGET],
            "trust": "unsigned", "api_schema_sources": []}, indent=2) + "\n")
        se = self.root / "crates/se"
        (se / "src").mkdir(parents=True)
        (se / "Cargo.toml").write_text(FIXTURE_SE_CARGO)
        (se / "src/main.rs").write_text(FIXTURE_MAIN)
        dep = self.work / "dep"
        (dep / "src").mkdir(parents=True)
        (dep / "Cargo.toml").write_text(FIXTURE_DEP_CARGO)
        (dep / "LICENSE").write_text(LICENSE)
        (dep / "src/lib.rs").write_text(FIXTURE_DEP_LIB)
        subprocess.run(["cargo", "generate-lockfile"], cwd=self.root, check=True,
                       env=self.environment, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

    def commit(self, message="fixture"):
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["git", "config", "user.email", "seed@test"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "seed test"], cwd=self.root, check=True)
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-q", "-m", message], cwd=self.root, check=True)

    def build(self, name, *extra):
        out = self.out_dir / name
        # A constant scratch path across the cycle: restored dependency
        # fingerprints record the scratch remap prefix, so a new path per
        # build would make every restored artifact stale.
        shutil.rmtree(self.scratch, ignore_errors=True)
        argv = ["python3", str(self.root / "scripts/release/build.py"), "--target", TARGET,
                "--out", str(out), "--target-dir", str(self.scratch)] + list(extra)
        result = subprocess.run(argv, cwd=self.root, env=self.environment, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900)
        self.assertEqual(result.returncode, 0,
                         f"{name} build refused: {result.stderr[-2000:]}")
        manifest = json.loads((out / "build.json").read_text())
        return out, manifest, result.stderr

    def test_full_seed_cycle(self):
        first, m1, _ = self.build("first", "--seed-out", str(self.out_dir / "seed1.tar.gz"))
        self.assertTrue((first / "se").is_file())
        self.assertIs(m1["fresh_target"], True)
        self.assertEqual(m1["target_freshness"],
                         {"workspace": "fresh", "dependencies": "fresh"})
        self.assertIsNone(m1["seed"])
        self.assertIsNone(m1["seed_publication"])
        self.assertEqual(m1["build_units"], {"compiled": {"total": 2, "workspace_members": 1},
                         "fresh": {"total": 0, "workspace_members": 0}})
        published = m1["seed_published"]
        seed1 = self.out_dir / "seed1.tar.gz"
        self.assertEqual(published["sha256"], digest(seed1))
        sidecar = json.loads((self.out_dir / "seed1.tar.gz.key.json").read_text())
        self.assertEqual(sidecar["archive_sha256"], published["sha256"])
        self.assertEqual(sidecar["key"]["cargo_lock_sha256"], m1["cargo_lock_sha256"])

        names = set()
        with tarfile.open(seed1, "r:gz") as archive:
            names = set(member.name for member in archive.getmembers())
        self.assertIn("seed.json", names)
        dependency = [name for name in names if "libfixture_dep" in name]
        self.assertTrue(dependency, "seed lost its dependency artifacts")
        self.assertFalse(any(name.endswith("/distribution/se") or
                             name.endswith("/deps/se-") for name in names),
                         "seed carries a workspace member artifact")

        second, m2, err2 = self.build("second", "--seed", str(seed1),
                                      "--seed-out", str(self.out_dir / "seed2.tar.gz"))
        self.assertIn("restored dependency seed built from", err2)
        self.assertIs(m2["fresh_target"], False)
        self.assertEqual(m2["target_freshness"],
                         {"workspace": "fresh", "dependencies": "seed"})
        self.assertEqual(m2["seed"]["source_commit"], m1["source_commit"])
        self.assertEqual(m2["seed"]["archive_sha256"], published["sha256"])
        self.assertEqual(m2["build_units"], {"compiled": {"total": 1, "workspace_members": 1},
                         "fresh": {"total": 1, "workspace_members": 0}})
        self.assertTrue((second / "se").is_file())

        # A changed dependency source keeps the same seed key: cargo must recompile
        # the stale dependency and the build must still qualify as seeded.
        # The dependency source moves without changing the seed key: cargo's
        # fingerprints must notice and recompile it.
        (self.work / "dep/src/lib.rs").write_text(
            FIXTURE_DEP_LIB.replace("fixture-dep", "fixture-dep-v2"))
        third, m3, _ = self.build("third", "--seed", str(seed1))
        self.assertIs(m3["fresh_target"], False)
        self.assertEqual(m3["build_units"], {"compiled": {"total": 2, "workspace_members": 1},
                         "fresh": {"total": 0, "workspace_members": 0}})

        # A changed pinned input changes the seed key: the seed is rejected and
        # every dependency builds fresh, and the build still succeeds.
        (self.root / ".cargo/config.toml").write_text(
            '[target.%s]\nrustflags = ["-C", "codegen-units=1"]\n' % TARGET)
        self.commit("fixture change")
        fourth, m4, err4 = self.build("fourth", "--seed", str(seed1))
        self.assertIn("seed rejected", err4)
        self.assertIs(m4["fresh_target"], True)
        self.assertEqual(m4["build_units"], {"compiled": {"total": 2, "workspace_members": 1},
                         "fresh": {"total": 0, "workspace_members": 0}})


if __name__ == "__main__":
    unittest.main(verbosity=2)
