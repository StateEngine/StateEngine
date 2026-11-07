#!/usr/bin/env python3
"""Judge rollback recovery through real Linux release installers and public CLI.

Run outside managed agent ancestry. Releases are extracted, retained archives;
--binary/--source-root overlays are development fixtures, not release qualification.
Failed fixtures stay in --output; cleanup never discards an unclosed runtime.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sqlite3
import subprocess
import unittest


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def no_links(root):
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            if (Path(directory) / name).is_symlink():
                raise AssertionError(f"linked fixture path preserved: {Path(directory) / name}")


def release(source, target, binary=None, source_root=None):
    no_links(source)
    shutil.copytree(source, target)
    if binary:
        shutil.copyfile(binary, target / 'se')
        (target / 'se').chmod(0o755)
    if source_root:
        for name in ('install.sh', 'uninstall.sh'):
            shutil.copyfile(source_root / 'scripts/release' / name, target / name)
    if binary or source_root:
        manifest = json.loads((target / 'manifest.json').read_bytes())
        for name, entry in manifest['files'].items():
            entry.update(sha256=digest(target / name), bytes=(target / name).stat().st_size)
        (target / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        (target / 'SHA256SUMS').write_text(''.join(
            f'{digest(p)}  {p.relative_to(target).as_posix()}\n'
            for p in sorted(target.rglob('*')) if p.is_file() and p.name != 'SHA256SUMS'))


class RollbackInstaller(unittest.TestCase):
    def setUp(self):
        self.root = OPTIONS.output / self._testMethodName
        self.root.mkdir(mode=0o700)
        self.owner = self.root / "owner's home"
        self.owner.mkdir(mode=0o700)
        self.state = self.owner / '.local/state/stateengine'
        self.bin = self.owner / '.local/bin/se'
        self.repo = self.root / 'repository'
        self.repo.mkdir()
        self.work = self.repo / 'user.txt'
        self.work.write_bytes(b'Keep this user work exactly.\n')
        (self.owner / '.profile').write_bytes(b'# User shell profile.\n')
        self.env = {'HOME': str(self.owner), 'PATH': '/usr/bin:/bin',
                    'SHELL': '/bin/sh', 'LANG': 'C.UTF-8', 'TMPDIR': str(self.root)}
        self.sequence = 0
        self.cleaning = False
        self.initialized = False
        self.host_pin = None
        self.exec(['git', 'init', '--quiet'])
        self.exec(['git', 'add', '--', 'user.txt'])
        self.exec(['git', '-c', 'user.name=Rollback fixture', '-c', 'user.email=fixture@invalid.example',
                   'commit', '-F', '-', '--', 'user.txt'], stdin=b'Keep user work.\n')
        self.head = self.exec(['git', 'rev-parse', 'HEAD']).stdout
        self.addCleanup(self.close_owned)

    def exec(self, argv, *, terminal=False, expected=0, stdin=None):
        available = int(next(l.split()[1] for l in Path('/proc/meminfo').read_text().splitlines()
                             if l.startswith('MemAvailable:'))) * 1024
        if not self.cleaning:
            self.assertGreater(available, 34 * 1024 ** 3, 'start line; retain this fixture')
        argv = [str(a) for a in argv]
        actual = ['/usr/bin/script', '--quiet', '--return', '--command', shlex.join(argv), '/dev/null'] if terminal else argv
        result = subprocess.run(actual, env=self.env, cwd=self.repo, input=stdin,
                                capture_output=True, timeout=180)
        self.sequence += 1
        log = self.root / f'call-{self.sequence:03}'
        log.with_suffix('.stdout').write_bytes(result.stdout)
        log.with_suffix('.stderr').write_bytes(result.stderr)
        log.with_suffix('.json').write_text(json.dumps(
            dict(argv=argv, terminal=terminal, exit=result.returncode, available_bytes=available), indent=2) + '\n')
        if expected is not None:
            self.assertEqual(result.returncode, expected, (argv, result.stdout[-2000:], result.stderr[-2000:]))
        return result

    def cli(self, *args, image=None, **kw):
        return self.exec([image or self.bin, '--json', '--home', self.state, *args], **kw)

    def json_cli(self, *args, **kw):
        return json.loads(self.cli(*args, **kw).stdout)

    def data(self):
        # A logical dump ignores harmless WAL/checkpoint layout changes, but covers
        # every actual table/row, not a hand-picked projection or record count.
        with sqlite3.connect((self.state / 'state.db').as_uri() + '?mode=ro', uri=True) as db:
            self.assertEqual(db.execute('pragma integrity_check').fetchone(), ('ok',))
            schema = db.execute('pragma user_version').fetchone()[0]
            logical = hashlib.sha256('\n'.join(db.iterdump()).encode()).hexdigest()
        protected = {}
        for name in ('machine.json', 'credential', 'config.toml'):
            try:
                protected[name] = digest(self.state / name)
            except FileNotFoundError:
                protected[name] = {'state': 'absent'}
        return dict(schema=schema, logical=logical, protected=protected,
                    user_file=digest(self.work), head=self.exec(['git', 'rev-parse', 'HEAD']).stdout.decode())

    def pin(self, pid):
        try:
            proc = Path('/proc') / str(pid)
            stat = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
            return dict(pid=pid, birth=stat[19], state=stat[0], argv=(proc / 'cmdline').read_bytes().hex(),
                        executable=str((proc / 'exe').resolve(strict=True)))
        except FileNotFoundError:
            return None

    def closed(self):
        if self.host_pin:
            now = self.pin(self.host_pin['pid'])
            self.assertFalse(now and now['birth'] == self.host_pin['birth'] and now['state'] != 'Z', now)
        self.assertFalse((self.state / 'endpoint.json').exists())
        lock = self.state / 'runtime.lock'
        if lock.exists():
            with lock.open('rb') as lease:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(lease, fcntl.LOCK_UN)

    def uninstall(self):
        self.cli('uninstall', terminal=True)
        self.assertFalse(self.bin.exists())
        self.assertFalse((self.state / 'standalone-install.json').exists())

    def seed_rollback(self):
        self.exec(['/bin/sh', CURRENT / 'install.sh'])
        self.json_cli('init', '--provider', 'codex')
        self.initialized = True
        # Keep this schema-rollback fixture readable by the retained older
        # release's config parser. The new optional hook key otherwise refuses
        # before that image can exercise the newer database schema guard.
        config = self.state / 'config.toml'
        config.write_bytes(config.read_bytes().replace(b'hooks = false\n', b''))
        self.json_cli('msg', 'send', 'main', 'Unread saved work — keep quotes: "hello".', '--no-wake', '--key', 'rollback-mail')
        self.json_cli('working-state', 'set', 'Resume this saved note.', '--agent', 'main', '--expect', 'absent')
        down = self.json_cli('down')
        self.assertTrue(down['complete'], down)
        self.closed()
        self.before = self.data()
        self.uninstall()
        self.assertEqual(self.data(), self.before)
        self.exec(['/bin/sh', OLDER / 'install.sh'])
        self.assertEqual(digest(self.bin), digest(OLDER / 'se'))
        for args in [('up',), ('uninstall',)]:
            result = self.cli(*args, terminal=args[0] == 'uninstall', expected=None)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('toonew', (result.stdout + result.stderr).decode(errors='replace').lower())
            self.assertEqual(self.data(), self.before)
        self.closed()

    def close_owned(self):
        self.cleaning = True
        if not self.initialized:
            return
        # Cleanup can run below a stop line: it only closes the exact fixture's
        # runtime through its public door; no process is killed by name.
        stopped = self.json_cli('down', image=CURRENT / 'se')
        self.assertTrue(stopped['complete'], stopped)
        self.closed()
        if self.bin.exists() and digest(self.bin) == digest(CURRENT / 'se'):
            self.uninstall()
        (self.root / 'outside-closure.json').write_text(json.dumps(
            dict(endpoint_absent=True, runtime_lease_free=True,
                 current_installation_removed=not self.bin.exists()), indent=2) + '\n')
        # Keep failed rollback/ownership fixtures and all raw calls for diagnosis.

    def test_current_installer_recovers_older_binary_without_touching_newer_data(self):
        """Bug: rollback recovery — a genuine old binary refuses newer data but cannot strand supported reinstall/uninstall."""
        self.seed_rollback()
        self.exec(['/bin/sh', CURRENT / 'install.sh'])
        self.assertEqual(digest(self.bin), digest(CURRENT / 'se'))
        self.assertEqual(self.data(), self.before)
        old = self.cli('up', image=OLDER / 'se', expected=None)
        self.assertNotEqual(old.returncode, 0)
        self.assertIn('toonew', (old.stdout + old.stderr).decode(errors='replace').lower())
        self.uninstall()
        self.assertEqual(self.data(), self.before)
        self.assertEqual((self.owner / '.profile').read_bytes(), b'# User shell profile.\n')

    def test_live_runtime_refuses_replacement_and_survives_until_public_down(self):
        """Protects: rollback repair cannot replace a live runtime or turn a live-runtime refusal into an empty claim."""
        self.seed_rollback()
        self.json_cli('up', image=CURRENT / 'se')
        status = self.json_cli('status', image=CURRENT / 'se')
        process = status['runtime']['process']
        self.host_pin = self.pin(process['pid'])
        self.assertIsNotNone(self.host_pin)
        self.assertEqual(self.host_pin['executable'], str(CURRENT / 'se'))
        endpoint = (self.state / 'endpoint.json').read_bytes()
        before = self.data()
        binary, record = digest(self.bin), (self.state / 'standalone-install.json').read_bytes()
        refused = self.exec(['/bin/sh', CURRENT / 'install.sh'], expected=None)
        self.assertNotEqual(refused.returncode, 0)
        reason = (refused.stdout + refused.stderr).decode(errors='replace').lower()
        self.assertIn('runtime', reason)
        self.assertTrue(any(word in reason for word in ('live', 'running', 'active', 'stop')), reason)
        self.assertEqual((self.state / 'endpoint.json').read_bytes(), endpoint)
        now = self.pin(process['pid'])
        self.assertIsNotNone(now)
        for field in ('pid', 'birth', 'argv', 'executable'):
            self.assertEqual(now[field], self.host_pin[field])
        self.assertNotEqual(now['state'], 'Z')
        self.assertEqual(self.json_cli('status', image=CURRENT / 'se')['runtime']['process'], process)
        self.assertEqual(digest(self.bin), binary)
        self.assertEqual((self.state / 'standalone-install.json').read_bytes(), record)
        self.assertEqual(self.data(), before)
        stopped = self.json_cli('down', image=CURRENT / 'se')
        self.assertTrue(stopped['complete'], stopped)
        self.closed()
        self.exec(['/bin/sh', CURRENT / 'install.sh'])
        self.assertEqual(self.data(), before)
        self.uninstall()
        self.assertEqual(self.data(), before)

    def test_changed_older_executable_is_preserved_instead_of_replaced(self):
        """Protects: repair needs exact recorded file custody; a changed installed executable remains untouched."""
        self.seed_rollback()
        with self.bin.open('ab') as changed:
            changed.write(b'foreign change in disposable fixture\n')
        changed, record = digest(self.bin), (self.state / 'standalone-install.json').read_bytes()
        refused = self.exec(['/bin/sh', CURRENT / 'install.sh'], expected=None)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(digest(self.bin), changed)
        self.assertEqual((self.state / 'standalone-install.json').read_bytes(), record)
        self.assertEqual(self.data(), self.before)
        self.closed()

    def test_resolved_profile_conflict_retries_after_owned_assets_were_removed(self):
        """Bug: partial removal retry — resolving a PATH refusal must permit recovery when owned assets are now absent."""
        self.seed_rollback()
        profile = self.owner / '.profile'
        original = profile.read_bytes()
        conflicting = original + b'\xff\n'
        profile.write_bytes(conflicting)
        record_path = self.state / 'standalone-install.json'
        record = record_path.read_bytes()
        refused = self.exec(['/bin/sh', CURRENT / 'install.sh'], expected=None)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn(str(profile), (refused.stdout + refused.stderr).decode(errors='replace'))
        self.assertEqual(profile.read_bytes(), conflicting)
        self.assertEqual(digest(self.bin), digest(OLDER / 'se'))
        self.assertEqual(record_path.read_bytes(), record)
        missing = []
        for entry in json.loads(record)['files']:
            path = Path(entry['path'])
            try:
                path.lstat()
            except FileNotFoundError:
                missing.append(str(path))
        self.assertTrue(missing, 'precondition: public refusal really removed recorded assets')
        self.assertNotIn(str(self.bin), missing)
        self.assertEqual(self.data(), self.before)
        self.closed()
        profile.write_bytes(original)
        self.exec(['/bin/sh', CURRENT / 'install.sh'])
        self.assertEqual(digest(self.bin), digest(CURRENT / 'se'))
        for entry in json.loads(record_path.read_bytes())['files']:
            self.assertEqual(digest(Path(entry['path'])), entry['sha256'])
        self.assertEqual(self.data(), self.before)
        self.uninstall()
        self.assertEqual(self.data(), self.before)
        self.assertEqual(profile.read_bytes(), b'# User shell profile.\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--current-release', required=True, type=Path)
    p.add_argument('--older-release', required=True, type=Path)
    p.add_argument('--binary', type=Path)
    p.add_argument('--source-root', type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--case', choices=('recovery', 'live', 'changed', 'partial'), action='append')
    OPTIONS = p.parse_args()
    OPTIONS.output = OPTIONS.output.resolve()
    OPTIONS.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    CURRENT, OLDER = OPTIONS.output / 'current', OPTIONS.output / 'older'
    release(OPTIONS.current_release, CURRENT, OPTIONS.binary, OPTIONS.source_root)
    release(OPTIONS.older_release, OLDER)
    assert digest(CURRENT / 'se') != digest(OLDER / 'se'), 'need genuine different supported schema images'
    names = dict(recovery='test_current_installer_recovers_older_binary_without_touching_newer_data',
                 live='test_live_runtime_refuses_replacement_and_survives_until_public_down',
                 changed='test_changed_older_executable_is_preserved_instead_of_replaced',
                 partial='test_resolved_profile_conflict_retries_after_owned_assets_were_removed')
    suite = unittest.TestSuite(RollbackInstaller(names[n]) for n in OPTIONS.case or names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
