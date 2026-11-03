#!/usr/bin/env python3
"""Public pre-init doctor checks, without installing or starting a host.

Run with --binary SE --out NEW_DIRECTORY. The unsupported-permission check runs
on macOS; it never substitutes a Linux test double for that platform.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import unittest


class BeforeInit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = OPTIONS.out.resolve()
        cls.root.mkdir(mode=0o700)
        cls.home = cls.root / 'home'
        cls.home.mkdir(mode=0o700)
        cls.state = cls.home / '.local/state/stateengine'
        cls.binary = OPTIONS.binary.resolve(strict=True)
        cls.env = {'HOME': str(cls.home), 'XDG_STATE_HOME': str(cls.home / '.local/state'),
                   'PATH': '/usr/bin:/bin', 'SHELL': '/bin/sh', 'LANG': 'C.UTF-8'}

    def diagnose(self, label):
        result = subprocess.run([str(self.binary), 'doctor', '--home', str(self.state), '--json'],
                                cwd=self.home, env=self.env, capture_output=True, timeout=30)
        (self.root / (label + '.stdout')).write_bytes(result.stdout)
        (self.root / (label + '.stderr')).write_bytes(result.stderr)
        self.assertNotEqual(result.returncode, 0, 'missing setup must remain actionable')
        value = json.loads(result.stdout)
        self.assertIsInstance(value.get('checks'), list, value)
        checks = {row['id']: row for row in value['checks']}
        self.assertEqual(checks['store.open']['code'], 'setup-required')
        self.assertIn('init', checks['store.open']['fix']['argv'])
        self.assertIn('installation.record', checks)
        self.assertNotIn(b'repair-refused', result.stderr)
        return checks

    def test_absent_home_is_diagnosed_without_creation(self):
        self.assertFalse(self.state.exists())
        checks = self.diagnose('absent-home')
        self.assertIn('absent', checks['home.permissions']['observed'].lower())
        self.assertFalse(self.state.exists())

    def test_present_home_without_database_keeps_diagnosis_reachable(self):
        self.state.mkdir(parents=True, mode=0o700)
        try:
            self.diagnose('absent-database')
            self.assertEqual(list(self.state.iterdir()), [])
        finally:
            self.state.rmdir()

    @unittest.skipUnless(sys.platform == 'darwin', 'requires the actual macOS permission adapter')
    def test_unsupported_permission_adapter_does_not_abort_other_checks(self):
        initialized = subprocess.run([str(self.binary), 'init', '--repo', str(self.home),
            '--home', str(self.state), '--name', 'doctor-macos', '--agent', 'main',
            '--provider', 'claude', '--json'], cwd=self.home, env=self.env,
            capture_output=True, timeout=90)
        (self.root / 'macos-init.stdout').write_bytes(initialized.stdout)
        (self.root / 'macos-init.stderr').write_bytes(initialized.stderr)
        self.assertEqual(initialized.returncode, 0, initialized.stderr.decode(errors='replace'))
        result = subprocess.run([str(self.binary), 'doctor', '--home', str(self.state), '--json'],
            cwd=self.home, env=self.env, capture_output=True, timeout=30)
        (self.root / 'macos-unsupported.stdout').write_bytes(result.stdout)
        (self.root / 'macos-unsupported.stderr').write_bytes(result.stderr)
        value = json.loads(result.stdout)
        checks = {row['id']: row for row in value['checks']}
        for name in ['home.permissions', 'store.permissions', 'credential.permissions', 'runtime.endpoint.permissions']:
            self.assertEqual(checks[name]['state'], 'unmeasured')
            self.assertTrue(checks[name]['reason'])
        self.assertIn('installation.record', checks)
        self.assertIn('runtime.endpoint', checks)
        self.assertNotIn(b'repair-refused', result.stderr)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    OPTIONS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__, *remaining], verbosity=2)
