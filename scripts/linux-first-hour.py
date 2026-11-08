#!/usr/bin/env python3
"""Exercise archive installation and real attended work from a fresh ordinary user.

Requires Python 3.12 or later. Run in that user's desktop terminal after signing in to Claude Code
and Codex. Complete welcome, trust and edit prompts in the provider windows.
Supply a new private output directory outside the source tree. Results include
provider account details and conversation text and must not be published.
The step names, result shape and two real tasks mirror windows-first-hour.ps1.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(pid):
    proc = Path('/proc') / str(pid)
    return (proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19],
            proc.joinpath('cmdline').read_bytes())


def stop_owned(process, observed):
    if process.poll() is not None:
        return
    current = identity(process.pid)
    if current != observed:
        raise RuntimeError(f'Owned command identity changed; preserve PID {process.pid}')
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if identity(process.pid) != observed:
            raise RuntimeError(f'Owned command identity changed; preserve PID {process.pid}')
        process.kill()
        process.wait(timeout=10)


class Journey:
    def __init__(self, args):
        self.args = args
        self.output = args.output_directory.resolve()
        if self.output.exists():
            raise RuntimeError('Choose a new output directory; existing work is preserved.')
        self.output.mkdir(mode=0o700, parents=True)
        self.steps = []
        self.providers = []
        self.record = dict(source_commit=args.source_commit,
                           archive_sha256=args.archive_sha256,
                           os=platform.system() + ' ' + platform.release(),
                           user_id=os.getuid(), group_id=os.getgid(),
                           groups=os.getgroups(), administrator=os.geteuid() == 0,
                           process_id=os.getpid(), steps=self.steps,
                           providers=self.providers)
        self.se = Path.home() / '.local/bin/se'
        self.save()

    def save(self):
        temporary = self.output / 'result.json.partial'
        temporary.write_text(json.dumps(self.record, indent=2) + '\n')
        temporary.replace(self.output / 'result.json')

    def step(self, name, executable, arguments, timeout=120):
        prefix = self.output / f'{len(self.steps) + 1:02}-{name}'
        stdout = prefix.with_suffix('.stdout')
        stderr = prefix.with_suffix('.stderr')
        started = time.monotonic()
        row = dict(name=name, argv=[str(executable), *arguments], cwd=str(Path.cwd()),
                   exit_code=None, started_utc=datetime.now(timezone.utc).isoformat(),
                   stdout=str(stdout), stderr=str(stderr))
        self.steps.append(row)
        self.save()
        print('> ' + ' '.join(row['argv']), flush=True)
        with stdout.open('wb') as out, stderr.open('wb') as err:
            try:
                process = subprocess.Popen(row['argv'], stdout=out, stderr=err)
            except FileNotFoundError as error:
                err.write(str(error).encode())
                row['exit_code'] = 127
            else:
                try:
                    observed = identity(process.pid)
                except (FileNotFoundError, ProcessLookupError):
                    observed = None
                try:
                    row['exit_code'] = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    if observed is None:
                        observed = identity(process.pid)
                    stop_owned(process, observed)
                    row['exit_code'] = process.returncode
                    row['timed_out'] = True
        row['duration_seconds'] = time.monotonic() - started
        self.save()
        # Raw output stays in the private result directory, including refusals.
        print(f"  exit {row['exit_code']}; output: {stdout.name}, {stderr.name}", flush=True)
        return row

    def se_step(self, name, arguments):
        return self.step(name, self.se, arguments)

    @staticmethod
    def require(row):
        if row['exit_code'] != 0 or row.get('timed_out'):
            raise RuntimeError(f"Step failed: {row['name']} (exit {row['exit_code']}); see its retained output.")
        return row

    def read_json(self, row):
        self.require(row)
        return json.loads(Path(row['stdout']).read_text())

    def reply(self, provider, marker):
        cursor = None
        seen = set()
        while True:
            arguments = ['--json', 'history', '--agent', 'main',
                         '--kind', 'session.turn', '--limit', '100']
            if cursor is not None:
                arguments.extend(['--cursor', cursor])
            page = self.read_json(self.se_step(provider + '-reply-records', arguments))
            if any(item.get('kind') == 'session.turn' and
                   item.get('payload', {}).get('role') == 'assistant' and
                   item.get('payload', {}).get('body', {}).get('complete') is True and
                   marker in item.get('payload', {}).get('body', {}).get('text', '')
                   for item in page['items']):
                return True
            cursor = page['next']
            if cursor is None:
                if not page['window']['complete']:
                    raise RuntimeError('Reply history is incomplete; the task outcome cannot be determined.')
                return False
            if not isinstance(cursor, str) or cursor in seen:
                raise RuntimeError('Reply history did not provide a new continuation cursor.')
            seen.add(cursor)

    def await_task(self, provider, filename, marker, reopened=False):
        until = time.monotonic() + self.args.task_timeout_seconds
        while True:
            if not reopened:
                self.require(self.se_step(provider + '-status', ['status']))
            self.require(self.se_step(provider + ('-reopened-history' if reopened else '-history'),
                                     ['history', '--agent', 'main']))
            if Path(filename).is_file() and self.reply(provider, marker):
                return Path(filename).read_text()
            if time.monotonic() >= until:
                raise RuntimeError('The real task did not produce both its file and visible reply before the deadline.')
            time.sleep(5)

    def install(self):
        if not re.fullmatch('[0-9a-fA-F]{64}', self.args.archive_sha256):
            raise RuntimeError('Supply an exact archive SHA-256.')
        if not re.fullmatch('[0-9a-f]{40}', self.args.source_commit):
            raise RuntimeError('Supply an exact source commit.')
        if digest(self.args.archive) != self.args.archive_sha256.lower():
            raise RuntimeError('Archive checksum differs; nothing was installed.')
        extract = self.output / 'archive'
        extract.mkdir()
        with tarfile.open(self.args.archive, 'r:gz') as archive:
            for item in archive.getmembers():
                path = Path(item.name)
                if path.is_absolute() or '..' in path.parts or not (item.isfile() or item.isdir()):
                    raise RuntimeError('Archive contains an unsafe path or non-regular member.')
            archive.extractall(extract, filter='data')
        packages = list(extract.iterdir())
        if len(packages) != 1 or not packages[0].is_dir():
            raise RuntimeError('Expected one extracted package directory.')
        package = packages[0]
        manifest = json.loads((package / 'manifest.json').read_text())
        if manifest['source_commit'] != self.args.source_commit or manifest['target'] != 'x86_64-unknown-linux-gnu':
            raise RuntimeError('Archive source or target differs from the requested release.')
        state = Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state')) / 'stateengine'
        if os.environ.get('SE_HOME') or state.exists() or self.se.exists():
            raise RuntimeError('Use a fresh user with the default state home and no existing installation.')
        previous = Path.cwd()
        try:
            os.chdir(package)
            self.require(self.step('install', 'sh', ['./install.sh']))
        finally:
            os.chdir(previous)
        self.record['installation'] = 'installed from archive'
        os.environ['PATH'] = str(self.se.parent) + os.pathsep + os.environ.get('PATH', '')
        self.require(self.se_step('installed-version', ['--version']))
        installed = digest(self.se)
        if installed != manifest['files']['se']['sha256']:
            raise RuntimeError('Installed executable differs from the archive manifest.')
        self.record['installed_sha256'] = installed
        self.save()
        self.require(self.se_step('launch-help', ['launch', '--help']))

    def provider(self, provider):
        result = dict(provider=provider, outcome='not-started')
        self.providers.append(result)
        self.save()
        repo = self.output / (provider + '-repo')
        repo.mkdir()
        result['repository'] = str(repo)
        (repo / 'README.md').write_text('A small project for recording one-sentence notes.\n')
        previous = Path.cwd()
        os.chdir(repo)
        try:
            self.require(self.step(provider + '-git-init', 'git', ['init']))
            login = ['auth', 'status'] if provider == 'claude' else ['login', 'status']
            self.require(self.step(provider + '-login', provider, login))
            self.require(self.se_step(provider + '-init', ['init', '--provider', provider]))
            self.read_json(self.se_step(provider + '-agent-before', ['--json', 'agent', 'show', 'main']))
            task = 'Read README.md, then create notes.md containing exactly: This project records one-sentence notes. Reply FIRST_HOUR_DONE after writing it.'
            launch = self.se_step(provider + '-launch', ['launch', 'main', '--task', task])
            if provider == 'claude' and launch['exit_code'] == 2 and 'launch-readiness-timeout' in Path(launch['stderr']).read_text():
                result['launch'] = 'pending native onboarding; initial CLI wait expired'
                print('Complete welcome, trust and edit prompts in the retained provider window.', flush=True)
            else:
                self.require(launch)
            contents = self.await_task(provider, 'notes.md', 'FIRST_HOUR_DONE')
            if contents.strip() != 'This project records one-sentence notes.':
                raise RuntimeError('Created file does not contain the requested sentence.')
            result['file_sha256'] = digest(repo / 'notes.md')
            before = self.read_json(self.se_step(provider + '-agent-running', ['--json', 'agent', 'show', 'main']))
            self.require(self.se_step(provider + '-stop', ['stop', 'main']))
            self.require(self.se_step(provider + '-resume-preview', ['resume', '--preview', 'main']))
            followup = 'Use our prior conversation to create resumed.md with the same sentence you wrote in notes.md. Reply FIRST_HOUR_RESUMED after writing it.'
            self.require(self.se_step(provider + '-reopen', ['launch', 'main', '--task', followup]))
            after = self.read_json(self.se_step(provider + '-agent-reopened', ['--json', 'agent', 'show', 'main']))
            old = before['agent']['value']['conversation']['id']
            new = after['agent']['value']['conversation']['id']
            if not old or new != old:
                raise RuntimeError('Reopen did not retain the saved provider conversation.')
            result['conversation'] = new
            resumed = self.await_task(provider, 'resumed.md', 'FIRST_HOUR_RESUMED', reopened=True)
            if resumed.strip() != contents.strip():
                raise RuntimeError('Resumed task did not retain the requested sentence.')
            self.require(self.se_step(provider + '-final-stop', ['stop', 'main']))
            result['outcome'] = 'passed'
        except Exception as error:
            result.update(outcome='failed', reason=str(error))
            print(provider + ': ' + str(error), flush=True)
        finally:
            try:
                cleanup = self.se_step(provider + '-down', ['down'])
                result['cleanup_exit'] = cleanup['exit_code']
            except Exception as error:
                result['cleanup_error'] = str(error)
            self.save()
            os.chdir(previous)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--providers', nargs='+', choices=['claude', 'codex'], default=['claude', 'codex'])
    parser.add_argument('--task-timeout-seconds', type=int, default=300)
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        parser.error('Use Python 3.12 or later to run the archive journey.')
    if platform.system() != 'Linux' or os.geteuid() == 0:
        parser.error('Run this journey on Linux as a fresh ordinary user, not root.')
    if not sys.stdin.isatty():
        parser.error('Open a normal desktop terminal; attended launch needs console input.')
    if not 30 <= args.task_timeout_seconds <= 900:
        parser.error('Task timeout must be between 30 and 900 seconds.')
    os.umask(0o077)
    args.archive = args.archive.resolve()
    journey = Journey(args)
    try:
        journey.install()
        for provider in args.providers:
            journey.provider(provider)
    except Exception as error:
        journey.record['error'] = str(error)
        journey.save()
        raise
    failed = sum(p['outcome'] != 'passed' or p.get('cleanup_exit') != 0 for p in journey.providers)
    print(f'Journey: {len(journey.providers) - failed} passed, {failed} failed; {journey.output / "result.json"}')
    return int(failed != 0)


if __name__ == '__main__':
    sys.exit(main())
