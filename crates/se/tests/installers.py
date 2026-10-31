#!/usr/bin/env python3
"""Judge a real Linux archive: python3 crates/se/tests/installers.py --archive ARCHIVE.

These exercise installation ownership, not native CLI/uninstall completion or Windows.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import signal
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
            elif path.is_dir():
                result[relative] = ("directory", stat.S_IMODE(path.stat().st_mode))
    return result


class LinuxInstaller(unittest.TestCase):
    archive = None
    source_root = None
    maxDiff = None

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
        if self.source_root:
            # Development fixture only: retain the native payload and old
            # provenance. This neither assembles nor qualifies a new release.
            for name in ("install.sh", "uninstall.sh"):
                shutil.copyfile(self.source_root / "scripts/release" / name, self.bundle / name)
            inventory = self.bundle / "SHA256SUMS"
            inventory.write_text("".join(
                f"{digest(path)}  {path.relative_to(self.bundle).as_posix()}\n"
                for path in sorted(self.bundle.rglob("*")) if path.is_file() and path != inventory))

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
        for case in ("command", "record", "assets", "profile-link", "bin-link", "path-block"):
            with self.subTest(case=case):
                home = self.home(case)
                outside = self.root / (case + " outside")
                outside.mkdir()
                (outside / "sentinel").write_bytes(b"foreign work\n")
                if case == "command":
                    target = home / ".local/bin/se"
                    target.parent.mkdir(parents=True)
                    target.write_bytes(b"foreign\n")
                elif case == "record":
                    target = home / ".local/state/stateengine/standalone-install.json"
                    target.parent.mkdir(parents=True)
                    target.write_bytes(b"foreign\n")
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
                    (home / ".profile").write_bytes(b"# >>> StateEngine PATH >>>\n")
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

    def test_state_home_overrides_place_the_record_at_the_declared_path(self):
        for variable in ("SE_HOME", "XDG_STATE_HOME"):
            with self.subTest(variable=variable):
                home = self.home(variable)
                state = self.root / (variable + " separate state")
                argv, environment = self.command(home)
                environment[variable] = str(state)
                run = subprocess.run(argv, env=environment, capture_output=True, timeout=30)
                self.assertEqual(run.returncode, 0, run.stderr)
                data = state if variable == "SE_HOME" else state / "stateengine"
                record = data / "standalone-install.json"
                self.assertEqual(json.loads(record.read_bytes())["owner"], str(os.getuid()))
                self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
                self.assertFalse((home / ".local/state/stateengine/standalone-install.json").exists())

    def test_relative_state_home_overrides_refuse_without_creating_paths(self):
        for variable in ("SE_HOME", "XDG_STATE_HOME"):
            with self.subTest(variable=variable):
                home = self.home("relative-" + variable)
                argv, environment = self.command(home)
                environment[variable] = "relative-state"
                before = contents(home)
                run = subprocess.run(argv, env=environment, cwd=home, capture_output=True, timeout=30)
                self.assertNotEqual(run.returncode, 0)
                self.assertIn(b"Install refused:", run.stderr)
                self.assertEqual(contents(home), before)

    def test_dotfiles_repository_and_non_utf8_profiles_are_supported(self):
        for case in ("dotfiles", "non-utf8"):
            with self.subTest(case=case):
                home = self.home(case)
                prior = b"# ordinary profile\n" if case == "dotfiles" else b"# foreign bytes: \xff\x01\n"
                (home / ".profile").write_bytes(prior)
                if case == "dotfiles":
                    (home / ".git").mkdir()
                    (home / ".git/config").write_bytes(b"[core]\n")
                preexisting = {str(p) for p in home.rglob("*") if p.is_dir()}
                run = self.install(home)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertTrue((home / ".profile").read_bytes().startswith(prior))
                record = json.loads((home / ".local/state/stateengine/standalone-install.json").read_bytes())
                edit = next(edit for edit in record["path_edits"] if edit["target"] == str(home / ".profile"))
                self.assertEqual(edit["before_sha256"], hashlib.sha256(prior).hexdigest())
                self.assertEqual((home / ".profile").read_bytes(), prior + edit["block"].encode())
                created = {str(p) for p in home.rglob("*") if p.is_dir()} - preexisting
                self.assertEqual(set(record["created_directories"]), created, "single-writer ownership records every new directory")
                if case == "dotfiles":
                    self.assertEqual((home / ".git/config").read_bytes(), b"[core]\n")

    @unittest.skipUnless(shutil.which("fish"), "native fish is required to witness fresh-shell discovery")
    def test_fish_uses_owned_configuration_and_fresh_shell_discovery(self):
        home = self.home("fish")
        argv, environment = self.command(home)
        environment["SHELL"] = shutil.which("fish")
        run = subprocess.run(argv, env=environment, capture_output=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        configuration = home / ".config/fish/conf.d/stateengine.fish"
        self.assertTrue(configuration.is_file())
        record = json.loads((home / ".local/state/stateengine/standalone-install.json").read_bytes())
        self.assertIn({"path": str(configuration), "sha256": digest(configuration)}, record["files"])
        terminal = subprocess.run([environment["SHELL"], "-lc", "command -s se"],
                                  env=environment, capture_output=True, timeout=10)
        self.assertEqual(terminal.returncode, 0, terminal.stderr)
        self.assertEqual(terminal.stdout.decode().strip(), str(home / ".local/bin/se"))

    def test_concurrent_install_has_one_owner_and_complete_readback(self):
        home = self.home("concurrent")
        profile = "# café: preserve tabs\tand CRLF\r\n# credential=not-a-real-key-judge-secret\n".encode()
        (home / ".profile").write_bytes(profile)
        (home / ".bash_profile").write_bytes(profile)
        (home / ".local/bin").mkdir(parents=True)
        preexisting = {str(p) for p in home.rglob("*") if p.is_dir()}
        argv, environment = self.command(home)
        tools = self.root / "claim-barrier"
        tools.mkdir()
        # Both installers must reach the exclusive claim after preflight. This
        # prevents an up-front exists check from masquerading as a race witness.
        shim = tools / "ln"
        shim.write_text('#!/bin/sh\nfor destination do :; done\ncase "$destination" in */se) exec /usr/bin/ln "$@";; esac\n'
                        'for source do case "$source" in */install.json) break;; esac; done\n'
                        'printf "CLAIM-READY:%s\\n" "$source"\nIFS= read -r release\n'
                        'if /usr/bin/ln "$@"; then printf "CLAIM-WON\\n"; IFS= read -r release; exit 0; else exit 1; fi\n')
        shim.chmod(0o700)
        environment["PATH"] = str(tools) + ":" + environment["PATH"]
        processes = [subprocess.Popen(argv, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        try:
            plans = []
            for process in processes:
                self.assertTrue(select.select([process.stdout], [], [], 10)[0], "installer never reached the atomic claim")
                ready = process.stdout.readline().decode().strip()
                self.assertTrue(ready.startswith("CLAIM-READY:"), ready)
                plans.append(json.loads(Path(ready.removeprefix("CLAIM-READY:")).read_bytes()))
            self.assertFalse(list(home.rglob("standalone-install.json")), "neither paused installer has claimed the record")
            # Make the installer which created the asset parent lose. Its
            # rollback must not remove a directory the winner still needs.
            parent = str(home / ".local/share/stateengine")
            owners = [i for i, plan in enumerate(plans) if parent in plan["created_directories"]]
            self.assertEqual(len(owners), 1)
            loser, winner = owners[0], 1 - owners[0]
            processes[winner].stdin.write(b"claim\n")
            processes[winner].stdin.flush()
            self.assertTrue(select.select([processes[winner].stdout], [], [], 10)[0])
            self.assertEqual(processes[winner].stdout.readline(), b"CLAIM-WON\n")
            processes[loser].stdin.write(b"claim\n")
            processes[loser].stdin.flush()
            outputs = [None, None]
            outputs[loser] = processes[loser].communicate(timeout=30)
            processes[winner].stdin.write(b"publish\n")
            processes[winner].stdin.flush()
            outputs[winner] = processes[winner].communicate(timeout=30)
        finally:
            for process in processes:
                if process.stdin and not process.stdin.closed:
                    process.stdin.close()
                    process.stdin = None
                if process.poll() is None:
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        self.assertEqual(sorted(process.returncode for process in processes), [0, 1], outputs)
        install_root = home / ".local"
        record_path = home / ".local/state/stateengine/standalone-install.json"
        self.assertTrue(record_path.is_file(), "ownership record belongs in the StateEngine data home")
        record_bytes = record_path.read_bytes()
        record = json.loads(record_bytes)
        self.assertEqual(record["schema"], "stateengine-install/v1")
        self.assertNotIn("install_root", record)
        self.assertNotIn(b"not-a-real-key-judge-secret", record_bytes, "profiles must not acquire a second persistent secret copy")
        self.assertEqual(record["owner"], str(os.getuid()))
        self.assertEqual(stat.S_IMODE(record_path.stat().st_mode), 0o600)
        actual = {str(p) for p in install_root.rglob("*") if p.is_file() and p != record_path}
        self.assertEqual({entry["path"] for entry in record["files"]}, actual)
        self.assertEqual(len(record["files"]), len(actual))
        for entry in record["files"]:
            self.assertTrue(Path(entry["path"]).is_absolute())
            self.assertEqual(digest(Path(entry["path"])), entry["sha256"])
        directories = {str(p) for p in home.rglob("*") if p.is_dir()}
        self.assertTrue(set(record["created_directories"]) <= directories)
        self.assertTrue(set(record["created_directories"]).isdisjoint(preexisting))
        self.assertEqual((install_root / "bin/se").read_bytes(), (self.bundle / "se").read_bytes())
        self.assertEqual(stat.S_IMODE((install_root / "bin/se").stat().st_mode), 0o755)
        self.assertEqual({Path(edit["target"]).name for edit in record["path_edits"]}, {".profile", ".bash_profile"})
        for edit in record["path_edits"]:
            self.assertEqual(set(edit), {"target", "before_sha256", "block"})
            self.assertEqual(edit["before_sha256"], hashlib.sha256(profile).hexdigest())
            self.assertEqual(Path(edit["target"]).read_bytes(), profile + edit["block"].encode())
        self.assertFalse(list(home.rglob(".install-*")))
        self.assertFalse(list(home.glob(".se-profile-*")))
        for shell in ("/bin/sh", "/bin/bash"):
            terminal = subprocess.run([shell, "-lc", "command -v se"], env=environment,
                                      capture_output=True, timeout=10)
            self.assertEqual(terminal.returncode, 0, terminal.stderr)
            self.assertEqual(terminal.stdout.decode().strip(), str(install_root / "bin/se"))

    def publication_fault(self, home, abrupt):
        """Fail at the first binary publication, after the durable ownership claim."""
        tools = self.root / ("kill-tools" if abrupt else "fail-tools")
        tools.mkdir()
        shim = tools / "ln"
        record = home / ".local/state/stateengine/standalone-install.json"
        shim.write_text(
            '#!/bin/sh\nfor destination do :; done\ncase "$destination" in */se)\n'
            '  test -f "$HOME/.local/state/stateengine/standalone-install.json" || exit 75\n'
            '  printf "JUDGE-AFTER-CLAIM\\n" >&2\n'
            + ('  case "$(tr "\\000" " " < /proc/$PPID/cmdline)" in *"$JUDGE_INSTALL_SCRIPT"*) kill -KILL "$PPID";; *) exit 76;; esac\n' if abrupt else '')
            + '  exit 74;;\nesac\nexec /usr/bin/ln "$@"\n')
        shim.chmod(0o700)
        argv, environment = self.command(home)
        environment["JUDGE_INSTALL_SCRIPT"] = str(self.bundle / "install.sh")
        environment["PATH"] = str(tools) + ":" + environment["PATH"]
        run = subprocess.run(argv, env=environment, capture_output=True, timeout=30)
        self.assertIn(b"JUDGE-AFTER-CLAIM", run.stderr, "fault must occur after the real exclusive claim")
        return run, record

    def test_failure_after_claim_rolls_back_only_its_effects(self):
        home = self.home("rollback")
        (home / ".profile").write_bytes(b"# original profile\n")
        history = home / ".local/state/stateengine/history"
        history.mkdir(parents=True)
        (history / "sentinel").write_bytes(b"unrelated durable history\n")
        before = contents(home)
        run, record = self.publication_fault(home, abrupt=False)
        self.assertNotEqual(run.returncode, 0)
        self.assertFalse(record.exists())
        self.assertEqual(contents(home), before, "complete rollback removes only new files/directories and preserves prior history")

    def test_failure_after_real_profile_publication_restores_or_preserves_foreign_edits(self):
        for concurrent_edit in (False, True):
            with self.subTest(concurrent_edit=concurrent_edit):
                home = self.home("profile-rollback-" + str(concurrent_edit))
                profile = home / ".profile"
                prior = b"# original profile credential=judge-profile-secret\r\n"
                profile.write_bytes(prior)
                profile.chmod(0o640)
                os.setxattr(profile, b"user.se-install-judge", b"preserve-profile-metadata")
                (home / ".bash_profile").write_bytes(b"# original bash profile\n")
                before = contents(home)
                tools = self.root / ("profile-fault-tools-" + str(concurrent_edit))
                tools.mkdir()
                shim = tools / "mv"
                shim.write_text(
                    '#!/bin/sh\nfor destination do :; done\ncase "$destination" in */.bash_profile)\n'
                    '  grep -q -F "# >>> StateEngine PATH >>>" "$HOME/.profile" || exit 75\n'
                    '  test -f "$HOME/.local/state/stateengine/standalone-install.json" || exit 76\n'
                    '  printf "JUDGE-AFTER-PROFILE-PUBLICATION\\n" >&2\n'
                    + ('  printf "# concurrent foreign edit\\n" >> "$HOME/.profile"\n' if concurrent_edit else '')
                    + '  exit 78;;\nesac\nexec /usr/bin/mv "$@"\n')
                shim.chmod(0o700)
                argv, environment = self.command(home)
                environment["PATH"] = str(tools) + ":" + environment["PATH"]
                run = subprocess.run(argv, env=environment, capture_output=True, timeout=30)
                self.assertNotEqual(run.returncode, 0)
                self.assertIn(b"JUDGE-AFTER-PROFILE-PUBLICATION", run.stderr)
                self.assertEqual(os.getxattr(profile, b"user.se-install-judge"), b"preserve-profile-metadata")
                record = home / ".local/state/stateengine/standalone-install.json"
                if concurrent_edit:
                    self.assertIn(b"Rollback incomplete", run.stderr)
                    self.assertTrue(record.is_file(), "unresolved foreign edits retain exact recovery ownership")
                    self.assertTrue(profile.read_bytes().startswith(prior))
                    self.assertTrue(profile.read_bytes().endswith(b"# concurrent foreign edit\n"))
                    self.assertIn(b"# >>> StateEngine PATH >>>", profile.read_bytes())
                else:
                    self.assertEqual(contents(home), before, "published profile rollback restores original bytes, mode and owned paths")
                    self.assertFalse(record.exists())

    def test_abrupt_loss_after_claim_retains_recoverable_nonsecret_ownership(self):
        home = self.home("interrupted")
        prior = b"# credential=not-a-real-interruption-secret\n"
        (home / ".profile").write_bytes(prior)
        run, record = self.publication_fault(home, abrupt=True)
        self.assertEqual(run.returncode, -signal.SIGKILL)
        self.assertTrue(record.is_file(), "recovery ownership must precede installed effects")
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        raw = record.read_bytes()
        self.assertNotIn(b"not-a-real-interruption-secret", raw)
        # The profile itself is the sole allowed copy. Check the complete
        # private fixture, including the state home, installer scratch and
        # temporary publication files, rather than only the JSON record.
        for path in self.root.rglob("*"):
            if path == home / ".profile" or not path.is_file():
                continue
            self.assertNotIn(b"not-a-real-interruption-secret", path.read_bytes(),
                             f"interrupted installer retained profile secrets in {path}")
        ownership = json.loads(raw)
        self.assertNotIn("install_root", ownership)
        self.assertIn(str(home / ".local/bin/se"), {entry["path"] for entry in ownership["files"]})
        installed = [Path(entry["path"]) for entry in ownership["files"] if Path(entry["path"]).exists()]
        self.assertTrue(installed, "the interruption must leave actual planned effects, not just an empty record")
        for entry in ownership["files"]:
            if Path(entry["path"]).exists():
                self.assertEqual(digest(Path(entry["path"])), entry["sha256"])
        self.assertFalse((home / ".local/bin/se").exists())
        self.assertEqual((home / ".profile").read_bytes(), prior)

    def test_unsupported_login_shells_refuse_without_creating_install_state(self):
        for shell in ("/bin/csh", "/bin/tcsh", "/usr/bin/nu"):
            with self.subTest(shell=shell):
                home = self.home(Path(shell).name)
                before = contents(home)
                argv, environment = self.command(home)
                environment["SHELL"] = shell
                run = subprocess.run(argv, env=environment, capture_output=True, timeout=30)
                self.assertNotEqual(run.returncode, 0, "unsupported login shell was told installation succeeded")
                self.assertIn(b"Install refused:", run.stderr)
                self.assertRegex(run.stderr.decode(), r"sh|bash|zsh|fish")
                self.assertEqual(contents(home), before)

    def test_state_home_on_another_filesystem_does_not_break_binary_publication(self):
        if not Path("/dev/shm").is_dir() or Path("/dev/shm").stat().st_dev == self.root.stat().st_dev:
            self.skipTest("no independent writable filesystem: cross-filesystem install NOT GRADED")
        with tempfile.TemporaryDirectory(prefix="se-installer-state-", dir="/dev/shm") as state:
            home = self.home("cross-filesystem")
            argv, environment = self.command(home)
            environment["SE_HOME"] = state
            run = subprocess.run(argv, env=environment, capture_output=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
            record = Path(state) / "standalone-install.json"
            self.assertTrue(record.is_file())
            self.assertEqual((home / ".local/bin/se").read_bytes(), (self.bundle / "se").read_bytes())
            for entry in json.loads(record.read_text())["files"]:
                self.assertEqual(digest(Path(entry["path"])), entry["sha256"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--source-root", type=Path, help="overlay production scripts in private test fixtures; never creates a release archive")
    args, remaining = parser.parse_known_args()
    if sys.platform != "linux":
        parser.error("these judging tests require Linux; no Windows claim is made")
    LinuxInstaller.archive = args.archive.resolve(strict=True)
    LinuxInstaller.source_root = args.source_root.resolve(strict=True) if args.source_root else None
    if LinuxInstaller.source_root:
        print("FIXTURE ONLY: production script overlay; native payload/provenance remain from the retained archive", flush=True)
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
