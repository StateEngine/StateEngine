#!/usr/bin/env python3
"""Linux public doctor judge: --archive ARCHIVE --binary SE --out NEW_DIRECTORY.

The real installer creates an isolated owner home; the candidate CLI performs
every diagnosis and repair. This does not qualify Windows or start a provider.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tarfile
import unittest


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DoctorPermissions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = OPTIONS.out.resolve()
        cls.out.mkdir(mode=0o700)
        cls.home = cls.out / 'owner home ü'
        cls.home.mkdir(mode=0o700)
        cls.repo = cls.home / 'repository'
        cls.repo.mkdir()
        (cls.repo / 'README.md').write_text('Doctor preserves this user work.\n')
        cls.state = cls.home / '.local/state/stateengine'
        cls.binary = OPTIONS.binary.resolve()
        cls.env = {'HOME': str(cls.home), 'PATH': '/usr/bin:/bin', 'SHELL': '/bin/sh',
                   'LANG': 'C.UTF-8', 'TERM': 'dumb', 'XDG_STATE_HOME': str(cls.home / '.local/state')}
        with tarfile.open(OPTIONS.archive) as archive:
            assert all(member.isfile() or member.isdir() for member in archive.getmembers())
            archive.extractall(cls.out / 'archive', filter='data')
        bundle, = (cls.out / 'archive').iterdir()
        cls.run_process('install', ['/bin/sh', str(bundle / 'install.sh')], expected=0)
        cls.run_process('git-init', ['git', 'init', '--quiet'], expected=0)
        cls.before_init = cls.call('before-init', ['doctor'])
        cls.call('init', ['init', '--repo', str(cls.repo), '--name', 'doctor-judge', '--agent', 'main', '--provider', 'claude'], expected=0)
        cls.db = cls.state / 'state.db'
        cls.credential = cls.state / 'credential'
        cls.child = cls.state / 'untouched child'
        cls.child.write_bytes(b'Descendants are not repair targets.\n')
        cls.child.chmod(0o640)
        cls.protected = [cls.db, cls.credential, cls.state / 'standalone-install.json', cls.child, cls.repo / 'README.md']
        cls.before = {str(path): digest(path) for path in cls.protected}
        cls.call('healthy-before', ['doctor'], expected=0)

    @classmethod
    def run_process(cls, label, argv, expected=None):
        completed = subprocess.run(argv, cwd=cls.repo, env=cls.env, capture_output=True, timeout=90)
        (cls.out / (label + '.stdout')).write_bytes(completed.stdout)
        (cls.out / (label + '.stderr')).write_bytes(completed.stderr)
        if expected is not None:
            assert completed.returncode == expected, (label, completed.returncode, completed.stderr.decode(errors='replace'))
        return completed

    @classmethod
    def call(cls, label, args, terminal=False, state=None, json_output=True, expected=None):
        argv = [str(cls.binary), *args, '--home', str(state or cls.state)]
        if json_output:
            argv.append('--json')
        if terminal:
            argv = ['/usr/bin/script', '-q', '-e', '-c', shlex.join(argv), '/dev/null']
        completed = cls.run_process(label, argv, expected)
        value = None
        for line in completed.stdout.decode(errors='replace').splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                pass
        if terminal and json_output and isinstance(value, dict) and 'plan' in value:
            objects = []
            for line in completed.stdout.decode(errors='replace').splitlines():
                try:
                    objects.append(json.loads(line))
                except ValueError:
                    pass
            assert objects.count(value['plan']) == 1, (label, 'pre-effect typed plan differs from receipt', objects)
            assert objects.index(value['plan']) < objects.index(value), (label, 'plan must precede receipt')
            assert ('Plan: repair ' + value['check_id']).encode() in completed.stdout + completed.stderr
        return completed, value

    def unchanged(self):
        self.assertEqual({str(path): digest(path) for path in self.protected}, self.before)
        self.assertEqual(stat.S_IMODE(self.child.stat().st_mode), 0o640)

    def test_installed_before_init_preserves_installation_and_path_diagnosis(self):
        completed, diagnosis = self.before_init
        self.assertNotEqual(completed.returncode, 0)
        self.assertIsInstance(diagnosis.get('checks'), list)
        checks = {row['id']: row for row in diagnosis['checks']}
        self.assertEqual(checks['store.open']['code'], 'setup-required')
        self.assertIn('init', checks['store.open']['fix']['argv'])
        self.assertEqual(checks['installation.record']['state'], 'ok')
        self.assertTrue(any(name.startswith('installation.path.') for name in checks))
        self.assertNotIn(b'repair-refused', completed.stderr)

    def tighten(self, target, check, mode, expected_mode):
        identity = (target.stat().st_dev, target.stat().st_ino, target.stat().st_uid)
        target.chmod(mode)
        try:
            _, diagnosis = self.call(check + '-diagnosis', ['doctor'], expected=1)
            self.assertTrue(any(row['id'] == check and row['state'] == 'failed' for row in diagnosis['checks']))
            completed, result = self.call(check + '-fix', ['doctor', '--fix', check], terminal=True, expected=0)
            self.assertTrue(result['complete'])
            self.assertEqual(len(result['applied']), 1)
            self.assertIn(('Plan: repair ' + check).encode(), completed.stdout + completed.stderr)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), expected_mode)
            self.assertEqual((target.stat().st_dev, target.stat().st_ino, target.stat().st_uid), identity)
            self.unchanged()
            _, noop = self.call(check + '-noop', ['doctor', '--fix', check], terminal=True, expected=0)
            self.assertTrue(noop['complete'])
            self.assertEqual(noop['applied'], [])
            self.assertEqual(len(noop['skipped']), 1)
            self.unchanged()
        finally:
            target.chmod(0o700 if target == self.state else 0o600)

    def test_root_tightens_only_the_named_object_and_noops(self):
        self.tighten(self.state, 'home.permissions', 0o755, 0o700)

    def test_database_tightens_only_the_named_object_and_noops(self):
        self.tighten(self.db, 'store.permissions', 0o644, 0o600)

    def test_credential_uses_normal_admission_and_preserves_bytes(self):
        self.tighten(self.credential, 'credential.permissions', 0o644, 0o600)

    def test_world_writable_root_can_recover_without_store_authority(self):
        self.state.chmod(0o777)
        try:
            _, result = self.call('world-writable-root', ['doctor', '--fix', 'home.permissions'], terminal=True, expected=0)
            self.assertTrue(result['complete'])
            self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
            self.unchanged()
        finally:
            self.state.chmod(0o700)

    def test_selected_home_without_record_reports_tightening_without_store_authority(self):
        other = self.home / 'uninstalled-selection' / 'stateengine'
        other.mkdir(parents=True, mode=0o755)
        other.chmod(0o755)
        previous = self.env['XDG_STATE_HOME']
        self.env['XDG_STATE_HOME'] = str(other.parent)
        try:
            completed, _ = self.call('uninstalled-selected-home', ['doctor', '--fix', 'home.permissions'], terminal=True, state=other)
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(stat.S_IMODE(other.stat().st_mode), 0o700)
            self.assertIn(b'state root now has owner-only protection', completed.stdout + completed.stderr)
            self.assertIn(b'no database or store access was attempted', completed.stdout + completed.stderr)
            self.assertEqual(list(other.iterdir()), [])
        finally:
            self.env['XDG_STATE_HOME'] = previous
            other.chmod(0o755)

    def test_root_recovery_does_not_depend_on_runtime_configuration(self):
        config = self.state / 'config.toml'
        original = config.read_bytes() if config.exists() else None
        invalid = b'This is deliberately invalid TOML.\n'
        config.write_bytes(invalid)
        config.chmod(0o600)
        self.state.chmod(0o755)
        try:
            _, result = self.call('invalid-config-root', ['doctor', '--fix', 'home.permissions'], terminal=True, expected=0)
            self.assertTrue(result['complete'])
            self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
            self.assertEqual(config.read_bytes(), invalid)
            self.unchanged()
        finally:
            self.state.chmod(0o700)
            if original is None:
                config.unlink()
            else:
                config.write_bytes(original)

    def test_root_repair_leaves_unreadable_store_incomplete(self):
        self.db.chmod(0)
        self.state.chmod(0o755)
        try:
            _, result = self.call('root-store-unreadable', ['doctor', '--fix', 'home.permissions'], terminal=True, expected=2)
            self.assertFalse(result['complete'])
            self.assertTrue(any(row['id'] == 'store.open' and row['state'] == 'unmeasured'
                                for row in result['remaining_checks']))
            self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(self.db.stat().st_mode), 0)
        finally:
            self.state.chmod(0o700)
            self.db.chmod(0o600)
        self.unchanged()

    def test_missing_owner_rights_are_never_added(self):
        self.db.chmod(0o400)
        try:
            completed, _ = self.call('missing-owner-write', ['doctor', '--fix', 'store.permissions'], terminal=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(stat.S_IMODE(self.db.stat().st_mode), 0o400)
            _, diagnosis = self.call('missing-owner-write-diagnosis', ['doctor'])
            check, = [row for row in diagnosis['checks'] if row['id'] == 'store.permissions']
            self.assertFalse(check['repairable'])
            self.assertEqual(check['fix']['argv'], ['chmod', '0600', '--', str(self.db)])
            self.assertIn('owner', check['fix']['text'])
            self.unchanged()
        finally:
            self.db.chmod(0o600)

    def test_owner_execute_is_retained(self):
        self.tighten(self.db, 'store.permissions', 0o755, 0o700)

    def test_symlink_root_is_refused_without_target_changes(self):
        linked = self.home / 'linked-state'
        linked.symlink_to(self.state, target_is_directory=True)
        try:
            completed, _ = self.call('linked-root', ['doctor', '--fix', 'home.permissions'], terminal=True, state=linked)
            self.assertNotEqual(completed.returncode, 0)
            self.assertTrue(linked.is_symlink())
            self.unchanged()
        finally:
            linked.unlink()

    def test_foreign_owner_is_refused_before_any_plan(self):
        # / is guaranteed to be root-owned on this non-root Linux consumer.
        self.assertNotEqual(os.getuid(), Path('/').stat().st_uid)
        before = Path('/').stat()
        completed, _ = self.call('foreign-owner', ['doctor', '--fix', 'home.permissions'], terminal=True, state=Path('/'))
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn(b'Plan:', completed.stdout + completed.stderr)
        self.assertEqual(Path('/').stat(), before)
        self.unchanged()

    def test_repair_requires_terminal_and_leaves_loose_object_untouched(self):
        self.state.chmod(0o755)
        try:
            completed, _ = self.call('no-terminal', ['doctor', '--fix', 'home.permissions'])
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o755)
            self.unchanged()
        finally:
            self.state.chmod(0o700)

    def test_unknown_check_refuses_and_plain_diagnosis_is_readable(self):
        completed, value = self.call('unknown-check', ['doctor', '--fix', 'unknown-judge-check'], terminal=True)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(value['code'], 'repair-refused')
        completed, _ = self.call('plain-diagnosis', ['doctor'], json_output=False, expected=0)
        self.assertIn(b'[credential.permissions]', completed.stdout)
        self.assertIn(b'ok:', completed.stdout)
        self.unchanged()

    def test_endpoint_permission_and_stale_retention_are_separate_repairs(self):
        endpoint = self.state / 'endpoint.json'
        original = b'{"doctor-judge":"retained endpoint bytes"}\n'
        endpoint.write_bytes(original)
        endpoint.chmod(0o644)
        try:
            _, diagnosis = self.call('endpoint-loose', ['doctor'], expected=1)
            self.assertTrue(any(row['id'] == 'runtime.endpoint.permissions' and row['state'] == 'failed' for row in diagnosis['checks']))
            self.assertTrue(any(row['id'] == 'runtime.endpoint' and row['state'] == 'unmeasured' for row in diagnosis['checks']))
            _, repaired = self.call('endpoint-protect', ['doctor', '--fix', 'runtime.endpoint.permissions'], terminal=True, expected=0)
            self.assertTrue(repaired['complete'])
            self.assertEqual(endpoint.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(endpoint.stat().st_mode), 0o600)
            self.assertTrue(any(row['id'] == 'runtime.endpoint' and row['state'] == 'failed' for row in repaired['remaining_checks']))
            _, retained = self.call('endpoint-retain', ['doctor', '--fix', 'runtime.endpoint'], terminal=True, expected=0)
            self.assertTrue(retained['complete'])
            self.assertFalse(endpoint.exists())
            self.assertEqual(Path(retained['applied'][0]['detail']).read_bytes(), original)
            self.unchanged()
        finally:
            if endpoint.exists():
                endpoint.unlink()

    def test_held_lease_prevents_endpoint_retention(self):
        endpoint = self.state / 'endpoint.json'
        original = b'{"doctor-judge":"held lease"}\n'
        endpoint.write_bytes(original)
        endpoint.chmod(0o600)
        try:
            with (self.state / 'runtime.lock').open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                completed, _ = self.call('endpoint-held-lease', ['doctor', '--fix', 'runtime.endpoint'], terminal=True)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(endpoint.read_bytes(), original)
            self.unchanged()
        finally:
            endpoint.unlink()

    def test_missing_credential_is_diagnosed_without_creation(self):
        backup = self.credential.with_name('credential.retained-judge')
        self.credential.rename(backup)
        try:
            _, diagnosis = self.call('credential-absent', ['doctor'], expected=1)
            self.assertTrue(any(row['id'] == 'credential.permissions' and row['state'] == 'failed' and not row['repairable'] for row in diagnosis['checks']))
            completed, _ = self.call('credential-absent-fix', ['doctor', '--fix', 'credential.permissions'], terminal=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(self.credential.exists())
        finally:
            backup.rename(self.credential)
        self.unchanged()

    def test_recorded_path_restoration_and_foreign_edit_preservation(self):
        record = json.loads((self.state / 'standalone-install.json').read_bytes())
        edit = record['path_edits'][0]
        profile = Path(edit['target'])
        original = profile.read_bytes()
        block = edit['block'].encode()
        self.assertEqual(original.count(block), 1)
        try:
            profile.write_bytes(original.replace(block, b'', 1))
            completed, result = self.call('path-restore', ['doctor', '--fix', 'installation.path.1'], terminal=True, expected=0)
            self.assertTrue(result['complete'])
            self.assertIn(b'Plan: repair installation.path.1', completed.stdout + completed.stderr)
            self.assertEqual(profile.read_bytes(), original)
            foreign = b'# Preserve all unrelated user edits.\n'
            profile.write_bytes(foreign)
            completed, _ = self.call('path-user-edits', ['doctor', '--fix', 'installation.path.1'], terminal=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(profile.read_bytes(), foreign)
            self.unchanged()
        finally:
            profile.write_bytes(original)

    @classmethod
    def tearDownClass(cls):
        assert not (cls.state / 'endpoint.json').exists()
        with (cls.state / 'runtime.lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (cls.out / 'outside.json').write_text(json.dumps({'binary_sha256': digest(cls.binary),
            'protected_bytes_unchanged': {str(path): digest(path) for path in cls.protected} == cls.before,
            'endpoint_present': False, 'runtime_lease': 'free'}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    OPTIONS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__, *remaining], verbosity=2)
