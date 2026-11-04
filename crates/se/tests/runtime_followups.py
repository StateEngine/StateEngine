#!/usr/bin/env python3
"""Protects: G6 — foreground termination drains; unavailable counters preserve hosted status.

Linux public-CLI/MCP consumers, with the existing Claude protocol fixture and
real native processes. --cleanup-se may pin a compatible cleanup binary for
negative baseline cases; no durable custody/endpoint bytes are edited.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import shutil
import signal
import subprocess
import sys
import tempfile
import termios
import time
import urllib.request
sys.path.insert(0, str(Path(__file__).parent / 'judges'))
from mail_cli import Fixture


def native(pid):
    try:
        root = Path('/proc') / str(pid)
        row = root.joinpath('stat').read_text().rsplit(') ', 1)[1].split()
        return {'pid': pid, 'birth': row[19], 'state': row[0],
                'argv_hex': root.joinpath('cmdline').read_bytes().hex()}
    except FileNotFoundError:
        return None


def same(old):
    row = native(old['pid'])
    return row is not None and row['birth'] == old['birth'] and row['argv_hex'] == old['argv_hex']


def terminal():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def wait_until(check, label, seconds=20):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = check()
        if value:
            return value
        time.sleep(.03)
    raise TimeoutError(label)


class Case:
    def __init__(self, options, directory, label):
        self.options, self.directory, self.label = options, directory, label
        self.f = Fixture(options.se, directory / label)
        self.f.env = {k: v for k, v in self.f.env.items()
                      if k in ('HOME', 'USERPROFILE', 'PATH', 'LANG', 'SHELL', 'TMPDIR')
                      or k.startswith('XDG_')}
        self.user = self.f.repo / 'user.txt'
        self.user.write_bytes(b'Keep user work.\n')
        self.root = self.host = self.master = self.log = None
        self.known, self.failures, self.cleanup = [], [], []

    def foreground(self, deny=None):
        args = [str(self.f.se), '--home', str(self.f.home),
                'up', '--foreground', '--json']
        if deny:
            args.insert(0, str(deny))
        self.master, slave = pty.openpty()
        self.log = (self.f.root / 'foreground.log').open('wb')
        self.root = subprocess.Popen(args, env=self.f.env, cwd=self.f.repo, stdin=slave,
                                     stdout=self.log, stderr=self.log, preexec_fn=terminal)
        os.close(slave)
        def ready():
            code = self.root.poll()
            if code not in (None, 0):
                raise RuntimeError(f'foreground startup exited {code}; retained foreground.log')
            return (self.f.home / 'endpoint.json').exists()
        wait_until(ready, 'host endpoint not published')
        endpoint = json.loads((self.f.home / 'endpoint.json').read_text())
        self.host = native(endpoint['epoch']['owner']['pid'])
        if not self.host or self.host['state'] == 'Z':
            raise AssertionError('published host has no real live native identity')
        self.known.append(self.host)
        if self.host['pid'] != self.root.pid or self.root.poll() is not None:
            self.failures.append('foreground command detached instead of retaining the real host')

    def provider(self):
        self.f.launch()
        for pid, birth in self.f.processes:
            row = native(pid)
            if row is None or row['birth'] != birth or row['state'] == 'Z':
                raise AssertionError('managed root/helper precondition not natively live')
            self.known.append(row)
        if len(self.f.processes) != 2:
            raise AssertionError('real managed root and helper were not both observed')

    def reap(self):
        if self.root is not None and self.root.poll() is not None:
            self.root.wait()
        for old in self.known:
            try:
                os.waitpid(old['pid'], os.WNOHANG)
            except ChildProcessError:
                pass

    def closed(self):
        self.reap()
        return all((row := native(old['pid'])) is None or row['birth'] != old['birth']
                   for old in self.known)

    def finish(self):
        # Observe regression failures before public recovery changes anything.
        try:
            if (self.f.home / 'endpoint.json').exists() or not self.closed():
                original = self.f.se
                self.f.se = self.options.cleanup_se
                try:
                    up = self.f.call('up')
                    if up.returncode != 0:
                        self.cleanup.append('public recovery up failed')
                    observed = self.f.call('status')
                    if observed.returncode == 0:
                        process = json.loads(observed.stdout).get('runtime', {}).get('process')
                        if process and (current := native(process['pid'])) is not None:
                            if not any(p['pid'] == current['pid'] and p['birth'] == current['birth'] for p in self.known):
                                self.known.append(current)
                    if self.f.processes:
                        stopped = self.f.call('--project', self.f.project, 'stop', self.f.agent)
                        if stopped.returncode != 0:
                            self.cleanup.append('public recovery stop failed')
                    down = self.f.call('down')
                    if down.returncode != 0:
                        self.cleanup.append('public recovery down failed')
                finally:
                    self.f.se = original
            try:
                wait_until(self.closed, 'known process instances remain after cleanup', 12)
            except TimeoutError as error:
                self.cleanup.append(str(error))
                # Last resort ends only independently pinned owned instances.
                # It never turns failed public cleanup into a passing case.
                for old in self.known:
                    if same(old):
                        os.kill(old['pid'], signal.SIGKILL)
                wait_until(self.closed, 'owned exact-instance fallback could not reap', 10)
            if (self.f.home / 'endpoint.json').exists():
                self.cleanup.append('endpoint retained after cleanup')
            with (self.f.home / 'runtime.lock').open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.user.read_bytes() != b'Keep user work.\n':
                self.cleanup.append('user work changed')
        except Exception as error:
            self.cleanup.append(f'{type(error).__name__}: {error}')
        finally:
            if self.root is not None:
                self.root.wait(timeout=5)
            if self.master is not None:
                os.close(self.master)
            if self.log is not None:
                self.log.close()
        return {'case': self.label, 'passed': not self.failures and not self.cleanup,
                'failures': self.failures, 'cleanup_errors': self.cleanup,
                'known_instances': self.known, 'fixture': str(self.f.root)}


def termination(case, selected):
    """Protects: G6 — SIGTERM/SIGHUP drains the actual foreground host and its children."""
    case.foreground()
    case.provider()
    if not same(case.host):
        raise AssertionError('host changed before exact-instance signal')
    os.kill(case.host['pid'], selected)
    try:
        wait_until(case.closed, 'host or managed children survived the termination event', 12)
    except TimeoutError as error:
        case.failures.append(str(error))
    if (case.f.home / 'endpoint.json').exists():
        case.failures.append('termination left the protected endpoint')
    with (case.f.home / 'runtime.lock').open('rb') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            case.failures.append('termination left the runtime lease held')


def resource_failure(case, deny):
    """Protects: G4 — real EPERM from host getrusage cannot erase otherwise readable status."""
    case.foreground(deny)
    status = Path('/proc') / str(case.host['pid']) / 'status'
    if 'Seccomp:\t2' not in status.read_text():
        raise AssertionError('native syscall-denial filter was not active in the actual host')
    case.provider()
    check_resources(case, 'stdio', case.f.rpc('stateengine_status', {}))
    arguments = (case.f.repo / 'provider-argv.txt').read_text().splitlines()
    config = json.loads(Path(arguments[arguments.index('--mcp-config') + 1]).read_text())
    server = config['mcpServers']['stateengine']
    request = urllib.request.Request(server['url'], data=json.dumps({
        'jsonrpc': '2.0', 'id': 91, 'method': 'tools/call',
        'params': {'name': 'stateengine_status', 'arguments': {}}}).encode(),
        headers={**server['headers'], 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=15) as response:
        reply = json.load(response)
    if 'result' not in reply:
        raise AssertionError('HTTP status had no protocol result')
    check_resources(case, 'http', reply['result'])


def check_resources(case, transport, result):
    (case.f.root / ('hosted-status-' + transport + '.json')).write_text(json.dumps(result, indent=2))
    value = result.get('structuredContent', {})
    if result.get('isError') or value.get('schema') != 'se.status/v1':
        case.failures.append('native resource failure made hosted status an error')
        return
    runtime = value.get('runtime', {})
    if runtime.get('state') != 'running' or runtime.get('process', {}).get('pid') != case.host['pid']:
        case.failures.append('resource failure lost the exact serving-host identity')
    if runtime.get('resources') is not None:
        case.failures.append('failed native counters became a resource sample')
    reason = runtime.get('resources_unavailable')
    if not isinstance(reason, str) or not reason.strip() or not any(w in reason.lower() for w in ('resource', 'getrusage')):
        case.failures.append('absent resources lack their named native reason')


def already_running(case):
    """Protects: G8 — a second foreground request names the existing host without displacing it."""
    first = case.f.ok('up')
    case.host = native(first['process']['pid'])
    if case.host is None:
        raise AssertionError('existing native host unavailable')
    case.known.append(case.host)
    before = (case.f.home / 'endpoint.json').read_bytes()
    result = case.f.call('up', '--foreground')
    text = (result.stdout + result.stderr).decode(errors='replace').lower()
    if (result.returncode == 0 or 'already running' not in text
            or str(case.host['pid']) not in text
            or not any(w in text for w in ('se status', 'endpoint', 'connect', 'reach'))):
        case.failures.append('second foreground request lacks the named host and legal way to reach it')
    if 'lease unreadable' in text or not same(case.host):
        case.failures.append('existing host became an unreadable lease or was displaced')
    if (case.f.home / 'endpoint.json').read_bytes() != before:
        case.failures.append('refused second foreground request replaced the endpoint')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--cleanup-se', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--case', choices=['all', 'term', 'hup', 'resources', 'running'], default='all')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Linux native observers required; Windows uses the separate console kit')
    args.se = args.se.resolve(strict=True)
    args.cleanup_se = (args.cleanup_se or args.se).resolve(strict=True)
    args.out.mkdir(mode=0o700)
    directory = Path(tempfile.mkdtemp(prefix='5d-runtime-followups-', dir=Path.home()))
    image = directory / 'se'
    shutil.copy2(args.se, image)
    source_hash = hashlib.sha256(args.se.read_bytes()).hexdigest()
    args.se = image
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0):
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')
    deny = directory / 'deny-self-resources'
    subprocess.run(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                    str(Path(__file__).parent / 'support/deny_self_resources.c'), '-o', str(deny)],
                   check=True, capture_output=True)
    selected = [('term', lambda c: termination(c, signal.SIGTERM)),
                ('hup', lambda c: termination(c, signal.SIGHUP)),
                ('resources', lambda c: resource_failure(c, deny)), ('running', already_running)]
    rows = []
    for name, check in selected:
        if args.case not in ('all', name):
            continue
        case = Case(args, directory, name)
        try:
            check(case)
        except Exception as error:
            case.failures.append(f'{type(error).__name__}: {error}')
        finally:
            row = case.finish()
            rows.append(row)
        print(('PASS' if row['passed'] else 'FAIL') + ': ' + name, flush=True)
        report = {'binary_sha256': source_hash, 'cases': rows, 'passed': sum(r['passed'] for r in rows),
                  'failed': sum(not r['passed'] for r in rows),
                  'bounds': 'Synthetic Claude protocol; real native managed root/helper and public CLI/MCP. No paid provider or budget claim.'}
        (args.out / 'results.json').write_text(json.dumps(report, indent=2))
    print(f"runtime follow-ups: {report['passed']} passed, {report['failed']} failed", flush=True)
    return 1 if report['failed'] else 0


if __name__ == '__main__':
    sys.exit(main())
