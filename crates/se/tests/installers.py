#!/usr/bin/env python3
"""Judge a real Linux archive: python3 crates/se/tests/installers.py --archive ARCHIVE.

These exercise installation ownership, not native CLI/uninstall completion or Windows.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def contents(root):
    """Compare foreign data without following symbolic links."""
    result = {}
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            path = Path(directory) / name
            relative = str(path.relative_to(root))
            if path.is_symlink():
                result[relative] = ("link", os.readlink(path))
            elif path.is_file():
                result[relative] = ("file", path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
    return result


class LinuxInstaller(unittest.TestCase):
    archive = None

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="se-installer-judge-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        extraction = self.root / "archive"
        with tarfile.open(self.archive) as archive:
            # Our fixture cleanup must never traverse an archive-provided link.
            for member in archive.getmembers():
                self.assertTrue(member.isfile() or member.isdir(), member.name)
            archive.extractall(extraction, filter="data")
        roots = list(extraction.iterdir())
        self.assertEqual(len(roots), 1)
        self.bundle = roots[0]
        self.assertTrue((self.bundle / "install.sh").is_file())

    def home(self, name):
        home = self.root / (name + " home ü")
        home.mkdir(mode=0o700)
        return home

    def command(self, home, bundle=None):
        return ["/bin/sh", str((bundle or self.bundle) / "install.sh")], {
            "HOME": str(home), "PATH": "/usr/bin:/bin", "SHELL": "/bin/sh", "LC_ALL": "C.UTF-8"
        }

    def install(self, home, bundle=None):
        argv, environment = self.command(home, bundle)
        return subprocess.run(argv, env=environment, capture_output=True, timeout=30)

    def test_foreign_paths_and_profiles_are_preserved(self):
        # Existing commands, records, assets, links and unreadable profile encodings
        # must be refusals, rather than invitations to replace foreign ownership.
        for case in ("command", "record", "assets", "profile-link", "bin-link", "utf8", "path-block"):
            with self.subTest(case=case):
                home = self.home(case)
                outside = self.root / (case + " outside")
                outside.mkdir()
                (outside / "sentinel").write_bytes(b"foreign work\n")
                if case in ("command", "record"):
                    binary_dir = home / ".local/bin"
                    binary_dir.mkdir(parents=True)
                    (binary_dir / ("se" if case == "command" else "install.json")).write_bytes(b"foreign\n")
                elif case == "assets":
                    target = home / ".local/share/stateengine/installation"
                    target.mkdir(parents=True)
                    (target / "sentinel").write_bytes(b"foreign\n")
                elif case == "profile-link":
                    (home / ".profile").symlink_to(outside / "sentinel")
                elif case == "bin-link":
                    (home / ".local").mkdir()
                    (home / ".local/bin").symlink_to(outside, target_is_directory=True)
                else:
                    (home / ".profile").write_bytes(b"\xff\n" if case == "utf8" else b"# >>> StateEngine PATH >>>\n")
                before, foreign = contents(home), contents(outside)
                run = self.install(home)
                self.assertNotEqual(run.returncode, 0, run.stdout.decode(errors="replace"))
                self.assertIn(b"Install refused:", run.stderr)
                self.assertEqual(contents(home), before)
                self.assertEqual(contents(outside), foreign)

    def test_untrusted_archive_inventory_has_no_install_effects(self):
        for case in ("changed-binary", "extra-file", "duplicate-entry", "linked-file"):
            with self.subTest(case=case):
                bundle = self.root / case
                shutil.copytree(self.bundle, bundle)
                if case == "changed-binary":
                    with (bundle / "se").open("ab") as binary:
                        binary.write(b"changed")
                elif case == "extra-file":
                    (bundle / "unlisted").write_bytes(b"extra")
                elif case == "duplicate-entry":
                    inventory = bundle / "SHA256SUMS"
                    inventory.write_bytes(inventory.read_bytes() + inventory.read_bytes().splitlines(keepends=True)[0])
                else:
                    (bundle / "linked").symlink_to(self.bundle / "se")
                home = self.home(case)
                (home / ".profile").write_bytes(b"# foreign profile\n")
                before = contents(home)
                run = self.install(home, bundle)
                self.assertNotEqual(run.returncode, 0)
                self.assertIn(b"Install refused:", run.stderr)
                self.assertEqual(contents(home), before)

    def test_concurrent_install_has_one_owner_and_complete_readback(self):
        home = self.home("concurrent")
        profile = "# café: preserve tabs\tand CRLF\r\n".encode()
        (home / ".profile").write_bytes(profile)
        (home / ".bash_profile").write_bytes(profile)
        argv, environment = self.command(home)
        processes = [subprocess.Popen(argv, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        try:
            outputs = [process.communicate(timeout=30) for process in processes]
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        self.assertEqual(sorted(process.returncode for process in processes), [0, 1], outputs)
        install_root = home / ".local"
        record_path = install_root / "bin/install.json"
        record = json.loads(record_path.read_bytes())
        self.assertEqual(record["schema"], "stateengine-install/v1")
        self.assertEqual(record["install_root"], str(install_root))
        self.assertEqual(record["owner"], str(os.getuid()))
        self.assertEqual(stat.S_IMODE(record_path.stat().st_mode), 0o600)
        actual = {str(p.relative_to(install_root)) for p in install_root.rglob("*") if p.is_file() and p != record_path}
        self.assertEqual({entry["path"] for entry in record["files"]}, actual)
        self.assertEqual(len(record["files"]), len(actual))
        for entry in record["files"]:
            self.assertEqual(digest(install_root / entry["path"]), entry["sha256"])
        self.assertEqual((install_root / "bin/se").read_bytes(), (self.bundle / "se").read_bytes())
        self.assertEqual(stat.S_IMODE((install_root / "bin/se").stat().st_mode), 0o755)
        self.assertEqual({Path(edit["target"]).name for edit in record["path_edits"]}, {".profile", ".bash_profile"})
        for edit in record["path_edits"]:
            self.assertEqual(edit["before"].encode(), profile)
            self.assertEqual(Path(edit["target"]).read_bytes(), edit["after"].encode())
            self.assertTrue(edit["after"].encode().startswith(profile))
        self.assertFalse(list(home.rglob(".install-*")))
        self.assertFalse(list(home.glob(".se-profile-*")))
        for shell in ("/bin/sh", "/bin/bash"):
            terminal = subprocess.run([shell, "-lc", "command -v se"], env=environment,
                                      capture_output=True, timeout=10)
            self.assertEqual(terminal.returncode, 0, terminal.stderr)
            self.assertEqual(terminal.stdout.decode().strip(), str(install_root / "bin/se"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    args, remaining = parser.parse_known_args()
    if sys.platform != "linux":
        parser.error("these judging tests require Linux; no Windows claim is made")
    LinuxInstaller.archive = args.archive.resolve(strict=True)
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
