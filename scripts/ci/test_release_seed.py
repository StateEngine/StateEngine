"""Seed archive safety for scripts/release/build.py, without invoking cargo.

The full restore-and-rebuild behavior is exercised by the fixture build in
scripts/release/test_release_seed.py; these controls pin the validation rules
that must hold before any archive byte is written into a build target tree.
"""
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

BUILD = Path(__file__).resolve().parents[2] / "scripts" / "release" / "build.py"

spec = importlib.util.spec_from_file_location("release_build_under_test", BUILD)
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def make_key(**changes):
    key = {"schema": "se.release-build-seed-key/v1", "toolchain": "1.97.1",
           "compiler": "rustc 1.97.1 (test)", "target": "x86_64-unknown-linux-gnu",
           "profile": "distribution", "rustflags": [], "cargo_config_overrides": [],
           "cargo_lock_sha256": "a" * 64, "inputs_sha256": "b" * 64,
           "path_remap": {"source": "/stateengine/source", "cargo": "/rust/cargo",
                          "toolchain": "/rust/toolchain", "target": "/stateengine/target"}}
    key.update(changes)
    return key


FIXED_MTIME = 1_700_000_000


def make_seed(path, key, entries, schema=build.SEED_SCHEMA, mtimes=None):
    manifest = {"schema": schema, "key": key,
                "created_from": {"source_commit": "c" * 40, "source_tree": "d" * 40,
                                 "source_timestamp": 1},
                "workspace_packages_removed": ["se 0.0.1 (path+file:///fixture/crates/se)"]}
    data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    with tarfile.open(path, "w:gz", compresslevel=1) as archive:
        info = tarfile.TarInfo("seed.json")
        info.size = len(data)
        info.mtime = FIXED_MTIME
        archive.addfile(info, io.BytesIO(data))
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = (mtimes or {}).get(name, FIXED_MTIME)
            archive.addfile(info, io.BytesIO(content))


def make_seed_modes(path, key, entries):
    """Like make_seed, with an explicit mode per entry: {name: (content, mode)}."""
    make_seed(path, key, {})
    with tarfile.open(path, "r:gz") as archive:
        manifest = archive.extractfile("seed.json").read()
    with tarfile.open(path, "w:gz", compresslevel=1) as archive:
        info = tarfile.TarInfo("seed.json")
        info.size = len(manifest)
        info.mtime = FIXED_MTIME
        archive.addfile(info, io.BytesIO(manifest))
        for name, (content, mode) in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = FIXED_MTIME
            info.mode = mode
            archive.addfile(info, io.BytesIO(content))


def make_seed_link(path, key, name, linkname, member_type):
    manifest = {"schema": build.SEED_SCHEMA, "key": key,
                "created_from": {"source_commit": "c" * 40, "source_tree": "d" * 40,
                                 "source_timestamp": 1},
                "workspace_packages_removed": ["se 0.0.1 (path+file:///fixture/crates/se)"]}
    data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    with tarfile.open(path, "w:gz", compresslevel=1) as archive:
        info = tarfile.TarInfo("seed.json")
        info.size = len(data)
        info.mtime = FIXED_MTIME
        archive.addfile(info, io.BytesIO(data))
        member = tarfile.TarInfo(name)
        member.type = member_type
        member.linkname = linkname
        archive.addfile(member)


class SeedArchiveControls(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory(prefix="seed-control-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / "seed.tar.gz"
        self.target = self.root / "target"
        self.target.mkdir()

    def test_restore_extracts_verified_entries(self):
        make_seed(self.archive, make_key(),
                  {"target/dep/deps/libfixture-abc123.rlib": b"dep-bytes"})
        manifest = build.restore_seed(self.archive, self.target, make_key())
        self.assertEqual(manifest["created_from"]["source_commit"], "c" * 40)
        self.assertEqual((self.target / "dep/deps/libfixture-abc123.rlib").read_bytes(), b"dep-bytes")

    @unittest.skipIf(os.name == "nt", "execute bits are a POSIX concept")
    def test_restore_keeps_a_cached_build_script_executable(self):
        # Cargo reuses a cached build-script-build by running it directly, so a
        # restore that drops 0755 makes the seeded build fail with errno 13.
        program = Path(shutil.which("true")).read_bytes()
        script = "target/dep/build/dep-abc123/build-script-build"
        make_seed_modes(self.archive, make_key(), {
            script: (program, 0o755),
            "target/dep/deps/libfixture-abc123.rlib": (b"dep-bytes", 0o644)})
        build.restore_seed(self.archive, self.target, make_key())
        restored = self.target / script[len("target/"):]
        self.assertEqual(restored.stat().st_mode & 0o777, 0o755)
        self.assertEqual(subprocess.run([str(restored)]).returncode, 0)
        library = self.target / "dep/deps/libfixture-abc123.rlib"
        self.assertEqual(library.stat().st_mode & 0o777, 0o644)

    @unittest.skipIf(os.name == "nt", "mode bits differ on Windows")
    def test_restore_never_restores_privilege_bits(self):
        make_seed_modes(self.archive, make_key(), {
            "target/dep/tool": (b"x", 0o4777), "target/dep/other": (b"y", 0o2755)})
        build.restore_seed(self.archive, self.target, make_key())
        for name in ("tool", "other"):
            self.assertEqual((self.target / "dep" / name).stat().st_mode & 0o7000, 0)

    @unittest.skipIf(os.name == "nt", "mode bits differ on Windows")
    def test_restored_read_only_entries_can_still_be_cleaned_up(self):
        make_seed_modes(self.archive, make_key(), {
            "target/dep/deps/libro.rlib": (b"ro", 0o444)})
        build.restore_seed(self.archive, self.target, make_key())
        shutil.rmtree(self.target)
        self.assertFalse(self.target.exists())

    def test_restore_refuses_rooted_absolute_and_drive_suffixes(self):
        # A leading separator after the target prefix makes Path join discard
        # the target directory, in either platform dialect.
        for suffix in ("/etc/passwd", "//etc/passwd", "\\evil", "C:/evil", "C:evil"):
            with self.subTest(suffix=suffix):
                make_seed(self.archive, make_key(), {"target/" + suffix: b"escape"})
                with self.assertRaisesRegex(ValueError, "escapes the target tree"):
                    build.restore_seed(self.archive, self.target, make_key())
        self.assertEqual(list(self.target.iterdir()), [])

    def test_restore_refuses_link_members(self):
        for member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(member_type=member_type):
                make_seed_link(self.archive, make_key(), "target/dep/link", "evil", member_type)
                with self.assertRaisesRegex(ValueError, "not a plain file or directory"):
                    build.restore_seed(self.archive, self.target, make_key())
        self.assertEqual(list(self.target.iterdir()), [])

    def test_restore_names_every_key_field_that_differs(self):
        make_seed(self.archive, make_key(cargo_lock_sha256="f" * 64,
                                         rustflags=["-C", "other"]), {})
        with self.assertRaisesRegex(build.SeedKeyMismatch, "cargo_lock_sha256.*rustflags"):
            build.restore_seed(self.archive, self.target, make_key())
        self.assertEqual(list(self.target.iterdir()), [])

    def test_restore_refuses_a_different_schema(self):
        make_seed(self.archive, make_key(), {}, schema="se.release-build-seed/v99")
        with self.assertRaisesRegex(ValueError, "schema differs"):
            build.restore_seed(self.archive, self.target, make_key())

    def test_restore_refuses_an_entry_outside_the_target_tree(self):
        for name in ("../escape.c", "target/../escape.c", "/absolute/escape.c", "other/escape.c"):
            with self.subTest(name=name):
                make_seed(self.archive, make_key(), {name: b"escape"})
                with self.assertRaisesRegex(ValueError, "escapes the target tree"):
                    build.restore_seed(self.archive, self.target, make_key())
                self.assertEqual(list(self.target.iterdir()), [])

    def test_restore_refuses_special_members(self):
        manifest = {"schema": build.SEED_SCHEMA, "key": make_key(),
                    "created_from": {"source_commit": "c" * 40, "source_tree": "d" * 40,
                                     "source_timestamp": 1},
                    "workspace_packages_removed": []}
        with tarfile.open(self.archive, "w:gz") as archive:
            data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
            info = tarfile.TarInfo("seed.json")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo("target/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            archive.addfile(link)
        with self.assertRaisesRegex(ValueError, "not a plain file or directory"):
            build.restore_seed(self.archive, self.target, make_key())

    def test_manifest_requires_a_regular_seed_json(self):
        with tarfile.open(self.archive, "w:gz") as archive:
            directory = tarfile.TarInfo("seed.json")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            build.seed_manifest_from_archive(self.archive)

    def test_manifest_requires_a_seed_json_member(self):
        with tarfile.open(self.archive, "w:gz") as archive:
            info = tarfile.TarInfo("target/dep/lib.a")
            info.size = 0
            archive.addfile(info, io.BytesIO(b""))
        with self.assertRaisesRegex(ValueError, "no seed.json manifest"):
            build.seed_manifest_from_archive(self.archive)


    def test_path_dependency_sources_hashes_every_regular_file(self):
        with TemporaryDirectory(prefix="seed-sources-") as name:
            root = Path(name)
            dep = root / "dep"
            (dep / "src").mkdir(parents=True)
            (dep / "Cargo.toml").write_bytes(b"[package]")
            (dep / "src/lib.rs").write_bytes(b"pub fn f() {}")
            (dep / "target").mkdir()
            (dep / "target/junk.bin").write_bytes(b"build output")
            dep2 = root / "dep2"
            (dep2 / "src").mkdir(parents=True)
            (dep2 / "Cargo.toml").write_bytes(b"[package]")
            (dep2 / "src/lib.rs").write_bytes(b"pub fn g() {}")
            metadata = {"packages": [
                {"id": "path+file:///x/dep#0.0.1", "name": "dep",
                 "manifest_path": str(dep / "Cargo.toml")},
                {"id": "path+file:///x/dep2#dep@0.0.2", "name": "dep",
                 "manifest_path": str(dep2 / "Cargo.toml")},
                {"id": "registry+https://github.com/rust-lang/crates.io-index#other@1.0.0",
                 "name": "other", "manifest_path": str(root / "other/Cargo.toml")},
                {"id": "path+file:///x/dep/member#1.0.0", "name": "member",
                 "manifest_path": str(dep / "member/Cargo.toml")}],
                "workspace_members": ["path+file:///x/dep/member#1.0.0"]}
            expected = {"path+file:///x/dep#0.0.1":
                        {"Cargo.toml": build.digest(dep / "Cargo.toml"),
                         "src/lib.rs": build.digest(dep / "src/lib.rs")},
                        "path+file:///x/dep2#dep@0.0.2":
                        {"Cargo.toml": build.digest(dep2 / "Cargo.toml"),
                         "src/lib.rs": build.digest(dep2 / "src/lib.rs")}}
            covered = build.path_dependency_sources(metadata)
        self.assertEqual(covered, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
