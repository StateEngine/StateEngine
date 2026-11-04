"""Independent public-consumer checks for the admitted onboarding/CLI fixes.

Run with an installed exact-candidate binary; no provider account or live host is
needed. Create a new owner-controlled --work-dir outside all other test homes.
  python3 onboarding_cli.py --se /absolute/installed/se --work-dir /new/owner/path
"""
import argparse
import base64
import itertools
import json
import os
import re
from pathlib import Path
import subprocess
import unittest

OPTIONS = None

class Onboarding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = OPTIONS.work_dir.resolve()
        cls.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        cls.home = cls.root / "state home with ' quote"
        cls.outside = cls.root / 'outside'
        cls.outside.mkdir()
        cls.env = {key: value for key, value in os.environ.items()
                   if not key.startswith(('STATEENGINE_', 'SECODE_', 'SE_'))
                   and key not in ['CLAUDECODE', 'CODEX_THREAD_ID', 'CODEX_CI']}
        user_home = cls.root / 'user home'
        user_home.mkdir(mode=0o700)
        cls.env.update(HOME=str(user_home), USERPROFILE=str(user_home),
                       XDG_STATE_HOME=str(user_home / '.local' / 'state'),
                       XDG_CONFIG_HOME=str(user_home / '.config'),
                       LOCALAPPDATA=str(user_home / 'AppData' / 'Local'))
        cls.se = str(OPTIONS.se.resolve(strict=True))
        cls.env['PATH'] = str(Path(cls.se).parent) + os.pathsep + cls.env.get('PATH', '')
        cls.logs = cls.root / 'logs'
        cls.logs.mkdir()
        cls.calls = 0
        cls.projects = {}
        for provider in ['claude', 'codex']:
            repo = cls.root / f'{provider} existing repository'
            repo.mkdir()
            marker = repo / 'existing.txt'
            marker.write_text('keep my existing work\n')
            reply = cls.call('init', '--repo', str(repo), '--name', f'{provider} first project',
                             '--agent', f'{provider} worker', '--provider', provider,
                             cwd=repo, json_mode=True)
            if reply.returncode:
                raise AssertionError(f'init setup refused: {reply.stdout}\n{reply.stderr}')
            cls.projects[provider] = {'repo': repo, 'init': json.loads(reply.stdout)}
            if marker.read_text() != 'keep my existing work\n':
                raise AssertionError('init changed pre-existing repository bytes')

    @classmethod
    def call(cls, *args, cwd=None, json_mode=False):
        cls.calls += 1
        command = [cls.se, '--home', str(cls.home)]
        if json_mode:
            command.append('--json')
        command.extend(args)
        result = subprocess.run(command, cwd=cwd or cls.outside, env=cls.env,
                                capture_output=True, text=True, timeout=30)
        stem = cls.logs / f'{cls.calls:03d}'
        stem.with_suffix('.command.json').write_text(json.dumps(command))
        stem.with_suffix('.stdout').write_text(result.stdout)
        stem.with_suffix('.stderr').write_text(result.stderr)
        stem.with_suffix('.exit').write_text(str(result.returncode))
        return result

    def ok_json(self, *args, **kwargs):
        reply = self.call(*args, json_mode=True, **kwargs)
        self.assertEqual(reply.returncode, 0, reply.stderr)
        return json.loads(reply.stdout)

    def test_init_gives_the_scoped_first_launch_for_each_provider(self):
        for provider, fixture in self.projects.items():
            with self.subTest(provider=provider):
                value = fixture['init']
                argv = value['next']['argv']
                self.assertEqual(argv[0], 'se')
                self.assertIn('launch', argv, 'init stops before the first actionable launch')
                self.assertIn('--detach', argv, 'the shipped first launch must be headless')
                self.assertEqual(argv[argv.index('--home') + 1], str(self.home))
                self.assertEqual(argv[argv.index('--project') + 1], value['project']['id'])
                self.assertIn(value['agent']['id'], argv)
                command = value['next']['command']
                self.assertIn('launch', command)
                # The same saved init must render the exact hint to a person.
                plain = self.call('init', '--repo', str(fixture['repo']), '--provider', provider,
                                  '--agent', f'{provider} worker', cwd=fixture['repo'])
                self.assertEqual(plain.returncode, 0, plain.stderr)
                self.assertIn(command, plain.stdout)
                # Exercise Clap's consumer with the supplied argv without launching a provider.
                help_reply = subprocess.run([self.se, *argv[1:], '--help'], env=self.env,
                                            cwd=self.outside, capture_output=True, text=True, timeout=30)
                self.assertEqual(help_reply.returncode, 0, help_reply.stderr)
                self.assertIn('Usage:', help_reply.stdout)

    def test_all_status_lists_every_project_in_plain_and_json(self):
        value = self.ok_json('status', '--all')
        self.assertEqual(value['scope'], 'all')
        self.assertIsNotNone(value['projects'], 'status --all discarded a nonempty project page')
        page = value['projects']
        self.assertTrue(page['window']['complete'])
        expected = {p['init']['project']['id'] for p in self.projects.values()}
        self.assertEqual({p['id'] for p in page['items']}, expected)
        plain = self.call('status', '--all')
        self.assertEqual(plain.returncode, 0, plain.stderr)
        for fixture in self.projects.values():
            self.assertIn(fixture['init']['project']['name'], plain.stdout)
            for row in page['items']:
                if row['id'] == fixture['init']['project']['id']:
                    self.assertEqual(Path(row['root']).resolve(), fixture['repo'].resolve())
                    self.assertEqual(row['agents_running'], 0)
                    self.assertEqual(row['owner_unread'], 0)

    def test_all_from_inside_one_project_still_lists_the_other(self):
        cwd = self.projects['claude']['repo']
        value = self.ok_json('status', '--all', cwd=cwd)
        self.assertIsNotNone(value['projects'])
        self.assertEqual(len(value['projects']['items']), 2)

    def test_outside_status_suggests_a_legal_read_command(self):
        value = self.ok_json('status')
        argv = value['next']['argv']
        self.assertEqual(argv[0], 'se')
        self.assertTrue(any(a in argv for a in ['status', 'agent']),
                        'outside status should list or select the saved projects')
        reply = subprocess.run([self.se, *argv[1:]], cwd=self.outside,
                               env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(reply.returncode, 0, f'status recommended a command that fails: {reply.stderr}')

    def test_bad_mail_cursor_names_the_actual_option_in_both_renderers(self):
        project = self.projects['claude']['init']['project']['id']
        for json_mode in [False, True]:
            with self.subTest(json=json_mode):
                reply = self.call('--project', project, 'msg', 'list', '--cursor', 'not-a-valid-cursor',
                                  json_mode=json_mode)
                self.assertEqual(reply.returncode, 64)
                if json_mode:
                    value = json.loads(reply.stdout)
                    self.assertEqual(value['code'], 'cursor-invalid')
                    remedy = value['remedy']['text']
                else:
                    remedy = reply.stderr
                self.assertIn('--cursor', remedy)
                self.assertNotIn('--since', remedy, 'mail cursor recovery names a different command option')

    def test_bad_cursor_does_not_damage_the_next_ordinary_mail_read(self):
        project = self.projects['claude']['init']['project']['id']
        reply = self.ok_json('--project', project, 'msg', 'list')
        self.assertEqual(reply['items'], [])
        self.assertTrue(reply['window']['complete'])

    def test_selected_never_launched_status_gives_the_scoped_launch(self):
        for provider, fixture in self.projects.items():
            with self.subTest(provider=provider):
                project = fixture['init']['project']['id']
                value = self.ok_json('--project', project, 'status')
                self.assertEqual(value['next']['argv'], fixture['init']['next']['argv'])
                plain = self.call('--project', project, 'status')
                self.assertEqual(plain.returncode, 0, plain.stderr)
                self.assertIn(value['next']['command'], plain.stdout)

    def test_z_project_unread_counts_are_real_and_isolated(self):
        project = self.projects['claude']['init']['project']['id']
        sent = self.call('--project', project, 'msg', 'send', 'owner',
                         'Independent fixture message for project unread counts.')
        self.assertEqual(sent.returncode, 0, sent.stderr)
        value = self.ok_json('status', '--all')
        counts = {row['id']: row['owner_unread'] for row in value['projects']['items']}
        self.assertEqual(counts[project], 1)
        self.assertEqual(counts[self.projects['codex']['init']['project']['id']], 0)

    @unittest.skipUnless(os.name == 'nt', 'requires native Windows cmd.exe and PowerShell')
    def test_windows_printed_scope_survives_cmd_and_powershell(self):
        # Run the real command through both parent shells. Replace only the
        # launch tail with a read: the printed quoting must select the same home
        # and project, without ever spending a provider account.
        for path in [self.se, str(self.home)]:
            self.assertFalse(any(c in path for c in '%!&|<>\r\n"'),
                             'use an owner-controlled shell fixture path without cmd expansions')

        def shell_run(shell, command):
            if shell == 'cmd':
                command = f'"{os.environ.get("COMSPEC", "cmd.exe")}" /d /s /c "{command}"'
            else:
                script = command + '\nexit $LASTEXITCODE'
                encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
                command = ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
                           '-EncodedCommand', encoded]
            return subprocess.run(command, cwd=self.outside, env=self.env,
                                  capture_output=True, text=True, timeout=30)

        def ps_word(word):
            return "'" + word.replace("'", "''") + "'"

        for shell, provider, operation in itertools.product(
                ['cmd', 'powershell'], self.projects, ['init', 'status']):
            with self.subTest(shell=shell, provider=provider, operation=operation):
                fixture = self.projects[provider]
                project = fixture['init']['project']['id']
                tail = (['--project', project, 'status'] if operation == 'status' else
                        ['init', '--repo', str(fixture['repo']), '--provider', provider,
                         '--agent', f'{provider} worker'])
                argv = [self.se, '--home', str(self.home), '--json', *tail]
                invocation = (subprocess.list2cmdline(argv) if shell == 'cmd'
                              else '& ' + ' '.join(ps_word(word) for word in argv))
                reply = shell_run(shell, invocation)
                self.assertEqual(reply.returncode, 0, reply.stderr)
                hint = json.loads(reply.stdout)['next']
                agent = re.escape(fixture['init']['agent']['id'])
                read, replaced = re.subn(r'\blaunch\s+' + agent + r'\s+--detach\b',
                                         'status --json', hint['command'])
                self.assertEqual(replaced, 1, 'refuse to execute an unrecognized launch hint')
                observed = shell_run(shell, read)
                self.assertEqual(observed.returncode, 0, observed.stderr)
                scoped = json.loads(observed.stdout)
                self.assertEqual(Path(scoped['setup']['home']).resolve(), self.home)
                self.assertEqual(scoped['project']['value']['id'], project)
                self.assertRegex(json.dumps(hint).lower(), r'\b(cmd|powershell|pwsh)(?:\.exe)?\b',
                                 'the printed command must name its target shell')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    OPTIONS = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Onboarding))
    raise SystemExit(0 if result.wasSuccessful() else 1)
