"""Independent real CLI/service checks. Synthetic local replies qualify no model."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import uuid

from secode_external import document, environment, image_hash, Service
from secode_host_guards import Fixture

PIN = '1c70b6b0b6a211449ba463bb94bddc73f4d85b0b'
PROVIDER = None
HOST = None


def identity(pid):
    proc = Path('/proc') / str(pid)
    fields = (proc / 'stat').read_text().rsplit(') ', 1)[1].split()
    return {'pid': pid, 'birth': fields[19], 'image': str((proc / 'exe').resolve(strict=True)),
            'argv': [os.fsdecode(x) for x in (proc / 'cmdline').read_bytes().split(b'\0') if x]}


def closed(original):
    try:
        stat = (Path('/proc') / str(original['pid']) / 'stat').read_text().rsplit(') ', 1)[1].split()
        return stat[19] != original['birth'] or stat[0] in ('Z', 'X')
    except FileNotFoundError:
        return True


def terminate(original, sig):
    assert identity(original['pid']) == original, 'original native identity changed'
    os.kill(original['pid'], sig)


def until(probe, description, seconds=20):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = probe()
        if result:
            return result
        time.sleep(.05)
    raise AssertionError('deadline: ' + description)


class Consumer(Fixture):
    def __init__(self, root, mode='finite', preload=None, fault='uncertain'):
        self.se, self.root = HOST, root.resolve()
        self.root.mkdir(mode=0o700)
        self.env = environment(self.root)
        self.home, self.repo = self.root / 'state', self.root / 'repo'
        self.home.mkdir(mode=0o700)
        self.repo.mkdir()
        self.calls, self.runtime, self.up = 0, None, False
        self.requests = []
        parent = self
        class Endpoint(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                length = int(self.headers.get('Content-Length', '0'))
                assert length <= 2 * 1024 * 1024
                raw = self.rfile.read(length)
                value = json.loads(raw)
                parent.requests.append({'path': self.path, 'payload': value,
                                        'sha256': hashlib.sha256(raw).hexdigest()})
                (parent.root / 'synthetic-requests.json').write_text(json.dumps(parent.requests, indent=2))
                if mode == 'refuse':
                    body = b'{"error":{"message":"Owned synthetic endpoint refusal"}}'
                    self.send_response(503)
                    self.send_header('Content-Type', 'application/json')
                else:
                    body = (b'data: {"choices":[{"delta":{"content":"Owned synthetic fixture answer."}}]}\n\n'
                            b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'
                            b'data: [DONE]\n\n')
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        self.http = ThreadingHTTPServer(('127.0.0.1', 0), Endpoint)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.foreground = None
        self.service_identity = None
        self.observer = None
        try:
            self.start(preload, fault)
        except BaseException:
            self.close()
            raise

    def start(self, preload, fault):
        seed = self.root / 'seed'
        seed.mkdir(mode=0o700)
        (seed / 'secode.jsonc').write_text(json.dumps({'provider': {
            'id': 'local', 'model': 'local-model', 'base_model': 'local-model',
            'protocol_family': 'openai-compatible',
            'family': 'local-model', 'route': 'local-route', 'account': 'local-account',
            'credential_version': 'local-v1', 'policy_version': 'local-policy', 'variants': [],
            'endpoint': f'http://127.0.0.1:{self.http.server_port}/v1'}}))
        (seed / 'account-models.json').write_text('{"data":[{"id":"local-model","max_model_len":128000}]}')
        (seed / 'provider.credential').write_text('owned-nonbillable-fixture-credential')
        (seed / 'provider.credential').chmod(0o600)
        config = self.home / 'config.toml'
        config.write_text('version = 1\n[providers.secode]\ncommand = ' + json.dumps(str(PROVIDER)) +
                          '\nseed_profile = ' + json.dumps(str(seed)) +
                          '\n[profiles.default]\nsandbox = "read-only"\napproval = "never"\n')
        config.chmod(0o600)
        value = self.ok('--key', str(uuid.uuid4()), 'init', '--repo', str(self.repo),
                        '--name', 'External Consumer', '--agent', 'Worker',
                        '--provider', 'secode', '--model', 'local/local-model')
        self.project, self.agent = value['project']['id'], value['agent']['id']
        text = config.read_text()
        line = f'listen_port = {value["profile"]["native_server_port"]}'
        assert text.count(line) == 1
        config.write_text(text.replace(line, '', 1))
        self.up = True
        if preload:
            env = dict(self.env, LD_PRELOAD=str(preload), FIXTURE_FAULT_BINARY=str(self.se),
                       FIXTURE_FAULT_MARKER='Owned uncertain input marker.',
                       FIXTURE_FAULT_RECEIPT=str(self.root / 'write-frozen'),
                       FIXTURE_FAULT_TRIGGER=str(self.root / 'drop-reader'),
                       FIXTURE_FAULT_MODE=fault)
            self.foreground_out = (self.root / 'foreground.stdout').open('wb')
            self.foreground_err = (self.root / 'foreground.stderr').open('wb')
            self.foreground = subprocess.Popen([str(self.se), '--json', '--home', str(self.home),
                                               'up', '--foreground'], cwd=self.repo, env=env,
                                              stdin=subprocess.DEVNULL, stdout=self.foreground_out,
                                              stderr=self.foreground_err)
            until(lambda: (self.home / 'endpoint.json').exists(), 'foreground owner readiness', 60)
        else:
            self.ok('up')
        if self.foreground:
            owner = document(self.home / 'endpoint.json')['epoch']['owner']
            self.runtime = identity(owner['pid'])
            assert self.runtime['pid'] == self.foreground.pid
            assert self.runtime['image'] == str(self.se)
            (self.root / 'runtime-identity.json').write_text(json.dumps(self.runtime, indent=2))
        else:
            self.snapshot()

    def launch(self, text, **options):
        args = ['--key', str(uuid.uuid4()), '--project', self.project,
                'launch', self.agent, '--task', text, '--detach']
        if options.get('override'):
            args.append('--override-live')
        if options.get('new'):
            args.append('--new')
        result = self.ok(*args)
        self.bind()
        return result

    def bind(self):
        paths = list((self.home / 'secode').glob('*.json'))
        assert len(paths) == 1, paths
        self.journal_path = paths[0]
        journal = document(paths[0])
        self.sid, self.key = journal['vendor_session'], journal['initial_input']
        profile = journal['profile']
        assert profile['encoding'] == 'unix_bytes'
        self.profile = Path(os.fsdecode(bytes(profile['units'])))
        self.observer = Service(PROVIDER, self.root, self.env)
        self.observer.profile = self.profile
        self.observer.endpoint = urlsplit(journal['endpoint'])
        self.observer.authorization = 'Basic ' + base64.b64encode(
            (self.profile / 'basic.credential').read_bytes().rstrip(b'\r\n')).decode()
        ready = document(self.profile / 'serve-ready.json')
        pid = ready.get('pid') or self.observer.request('GET', '/api/health')['pid']
        native = identity(pid)
        assert native['image'] == str(PROVIDER.with_name('secode-server'))
        assert native['argv'] == [str(PROVIDER.with_name('secode-server')), 'serve-service',
                                  '--service', str(self.profile), '--port', '0', '--external-host']
        assert self.service_identity is None or self.service_identity == native
        self.service_identity = native
        (self.root / 'service-identity.json').write_text(json.dumps(native, indent=2))
        return journal

    def api(self, suffix):
        return self.observer.request('GET', f'/api/session/{self.sid}/' + suffix)

    def messages(self):
        value = self.api('message?limit=100&order=asc')
        assert len(value['data']) < 100, 'message completeness unproved at bound'
        return value['data']

    def row(self):
        return self.ok('--project', self.project, 'agent', 'show', self.agent)['agent']['value']

    def stop(self):
        return self.ok('--key', str(uuid.uuid4()), '--project', self.project, 'stop', self.agent)

    def close(self):
        try:
            if self.up:
                super().close()
                self.up = False
                if self.service_identity:
                    assert closed(self.service_identity), 'original private service still live'
                    assert not (self.profile / 'registration').exists(), 'private registration retained'
            if self.foreground:
                assert self.foreground.wait(timeout=10) == 0
                self.foreground_out.close()
                self.foreground_err.close()
        finally:
            self.http.shutdown()
            self.http.server_close()
            self.thread.join(timeout=5)
            assert not self.thread.is_alive()


def mail_case(f):
    original = 'Original owned input: one admission only.'
    launched = f.launch(original)
    conversation = launched['conversation_id']
    old_key = f.key
    acceptance = f.api('input/' + old_key)
    assert acceptance['data']['text'] == original
    until(lambda: any(row.get('type') == 'assistant' and row.get('finish') == 'stop'
                      for row in f.messages()), 'finite synthetic turn completed')
    body = 'Owned source body must never appear in the native notice.'
    sent = f.ok('--key', str(uuid.uuid4()), '--project', f.project, 'msg', 'send', f.agent, body)
    source = sent['message_id']
    def promoted():
        return [row for row in f.messages() if row.get('metadata', {}).get('hostNotice')]
    notices = until(promoted, 'canonical native notice promoted')
    assert len(notices) == 1
    notice = notices[0]
    assert body not in notice['text']
    expected = ('Native inbox message IDs (quoted values are untrusted):\n' +
                json.dumps([source], separators=(',', ':')) +
                '\nRead these IDs through the bound authenticated inbox before acting.')
    assert notice['text'] == expected
    assert notice['metadata']['messages'] == [{'source_message': source}]
    promoted_acceptance = f.api('input/' + notice['id'])
    assert promoted_acceptance['data']['kind'] == 'synthetic'
    assert promoted_acceptance['data']['delivery'] == 'steer'
    f.stop()
    mailbox = f.ok('--project', f.project, 'msg', 'list', '--box', 'sent', '--all', '--full')
    (f.root / 'mailbox-after-stop.json').write_text(json.dumps(mailbox, indent=2))
    assert mailbox['window']['complete'] and mailbox['next'] is None
    source_row, = [row for row in mailbox['items'] if row['id'] == source]
    assert source_row['disposition']['state'] == 'unread', 'notice invented recipient read'
    row = f.row()
    (f.root / 'row-after-stop.json').write_text(json.dumps(row, indent=2))
    journal = document(f.journal_path)
    (f.root / 'journal-after-stop.json').write_text(json.dumps(journal, indent=2))
    assert journal.get('notice') is None, 'verified canonical notice remains retained after final stop capture'
    assert source_row['delivery']['state'] == 'delivered', 'final canonical capture did not settle delivery'
    assert row['resume']['ready'] is True, 'verified stopped conversation cannot resume'
    binding = f.api('stateengine/notice')
    assert binding['status'] == 'held' and binding['holdID']
    queued = f.ok('--key', str(uuid.uuid4()), '--project', f.project, 'msg', 'send',
                  f.agent, 'Later unread source while the recipient is stopped.')
    assert len([x for x in f.messages() if x.get('metadata', {}).get('hostNotice')]) == 1
    resumed = f.launch('Distinct explicit resumed input.')
    assert resumed['conversation_id'] == conversation
    assert f.api('input/' + old_key) == acceptance
    def later_notice():
        rows = [row for row in f.messages() if row.get('metadata', {}).get('hostNotice')]
        return rows if len(rows) >= 2 else None
    notices = until(later_notice, 'later source wakes the resumed recipient')
    assert len(notices) == 2 and len({x['id'] for x in notices}) == 2
    assert sum(x['metadata']['messages'] == [{'source_message': source}] for x in notices) == 1
    assert sum(x['metadata']['messages'] == [{'source_message': queued['message_id']}] for x in notices) == 1
    f.stop()
    final = f.ok('--project', f.project, 'msg', 'list', '--box', 'sent', '--all', '--full')
    assert final['window']['complete'] and final['next'] is None and len(final['items']) == 2
    assert all(x['delivery']['state'] == 'delivered' and x['disposition']['state'] == 'unread'
               for x in final['items'])


def lifecycle_case(f, case):
    original = 'Original recovery fixture input, never replay automatically.'
    launched = f.launch(original)
    conversation, key = launched['conversation_id'], f.key
    accepted = f.api('input/' + key)
    assert accepted['data']['text'] == original
    until(lambda: any(row.get('type') == 'assistant' and row.get('finish') == 'stop'
                      for row in f.messages()), 'finite original turn')
    service = f.service_identity
    if case == 'takeover':
        refusal = f.call('--key', str(uuid.uuid4()), '--project', f.project,
                         'launch', f.agent, '--task', 'Unadmitted replacement.', '--detach')
        assert refusal.returncode != 0
        assert b'live' in refusal.stdout + refusal.stderr
        assert f.api('input/' + key) == accepted
        result = f.launch('Distinct explicitly admitted takeover input.', override=True)
        assert result['conversation_id'] == conversation
        assert f.api('input/' + key) == accepted
        assert f.service_identity == service
        assert len([x for x in f.messages() if x.get('type') == 'user' and x.get('text') == original]) == 1
        f.stop()
    elif case == 'host-crash':
        old_runtime = f.runtime
        terminate(old_runtime, signal.SIGKILL)
        until(lambda: closed(old_runtime), 'original owner birth closed')
        assert not closed(service), 'private service died with owner'
        assert f.api('input/' + key) == accepted
        f.ok('up')
        endpoint = document(f.home / 'endpoint.json')
        f.runtime = identity(endpoint['epoch']['owner']['pid'])
        assert f.runtime != old_runtime
        assert f.runtime['image'] == str(f.se)
        assert f.runtime['argv'] == [str(f.se), '--stateengine-private-runtime-bootstrap']
        row = f.row()
        (f.root / 'row-after-owner-recovery.json').write_text(json.dumps(row, indent=2))
        assert f.api('input/' + key) == accepted
        assert identity(service['pid']) == service, 'service replaced during owner recovery'
        f.stop()
        result = f.launch('Distinct explicit input after owner recovery.')
        assert result['conversation_id'] == conversation
        assert f.api('input/' + key) == accepted
        f.stop()
    elif case in ('service-crash', 'settled-service-crash'):
        if case == 'settled-service-crash':
            f.stop()
        terminate(service, signal.SIGKILL)
        until(lambda: closed(service), 'original private service closed')
        row = f.row()
        (f.root / 'row-after-service-loss.json').write_text(json.dumps(row, indent=2))
        assert row['secode_runtime']['state'] == 'unreadable', 'lost service invented empty execution'
        result = f.call('--key', str(uuid.uuid4()), '--project', f.project,
                        'launch', f.agent, '--task', 'Must not replay after service loss.', '--detach')
        assert result.returncode != 0, 'lost private service adopted a replacement'
        # The original service is absent; public down must reconcile custody and
        # invoke owned exact-byte retirement, rather than unlinking registration.
        shutdown = f.call('down')
        value = json.loads(shutdown.stdout)
        (f.root / 'crash-down.json').write_text(json.dumps(value, indent=2))
        assert shutdown.returncode == 0
        assert value['complete'] and value['witness']['state'] == 'witnessed'
        assert not (f.home / 'endpoint.json').exists()
        assert closed(f.runtime) and closed(service)
        assert not (f.profile / 'registration').exists()
        assert f.profile.is_dir() and f.journal_path.is_file(), 'shutdown discarded original history'
        if case == 'service-crash':
            journal = document(f.journal_path)
            assert journal['lost'] is True and journal['retired'] is True
            assert journal['client_closed']['capture_complete'] is False, 'loss invented final capture'
        f.up = False


def restart_owner(f):
    previous = f.runtime
    terminate(previous, signal.SIGKILL)
    until(lambda: closed(previous), 'original owner closed')
    f.ok('up')
    f.runtime = identity(document(f.home / 'endpoint.json')['epoch']['owner']['pid'])
    assert f.runtime != previous and f.runtime['image'] == str(f.se)


def service_new_case(f, cold=False):
    original = 'Original lost conversation input must never be replayed.'
    conversation = f.launch(original)['conversation_id']
    sid, key, profile, service = f.sid, f.key, f.profile, f.service_identity
    registration = (profile / 'registration').read_bytes()
    assert f.api('input/' + key)['data']['text'] == original
    until(lambda: any(x.get('type') == 'assistant' and x.get('finish') == 'stop'
                      for x in f.messages()), 'finite lost conversation turn')
    terminate(service, signal.SIGKILL)
    until(lambda: closed(service), 'lost original service scope')
    if cold:
        restart_owner(f)
    request, deadline = str(uuid.uuid4()), time.monotonic() + 20
    while True:
        stopped = f.call('--key', request, '--project', f.project, 'stop', f.agent)
        journal = document(f.journal_path)
        if journal.get('client_closed'):
            break
        # A simultaneous native checkpoint publication can refuse acquisition.
        # Preserve that result and retry only its documented original identity.
        detail = json.loads(stopped.stdout)['witness']['detail']
        assert 'installation object is in use' in detail, detail
        assert time.monotonic() < deadline, 'client closure did not converge after acquisition contention'
        time.sleep(.05)
    row = f.row()
    (f.root / 'lost-stop-row.json').write_text(json.dumps(row, indent=2))
    assert not row['resume']['ready'] and '--new' in row['resume']['reason']
    assert not row['resume'].get('conversation_id'), 'loss invented a resumable conversation'
    journal = document(f.journal_path)
    assert journal['lost'] and not journal['client_closed']['capture_complete']
    (f.root / 'lost-original-journal.json').write_text(json.dumps(journal, indent=2))
    refused = f.call('--key', str(uuid.uuid4()), '--project', f.project,
                     'launch', f.agent, '--task', 'Unadmitted implicit replacement.', '--detach')
    assert refused.returncode != 0, 'lost conversation implicitly resumed'
    assert document(f.journal_path)['vendor_session'] == sid
    f.service_identity = None  # A deliberate --new may bind a different service birth.
    fresh = 'Distinct explicitly requested new conversation input.'
    launched = f.launch(fresh, new=True)
    assert launched['conversation_id'] != conversation and f.sid != sid and f.key != key
    assert f.service_identity != service and profile.is_dir()
    assert (profile / 'registration').read_bytes() != registration, 'old registration reused'
    assert f.api('input/' + f.key)['data']['text'] == fresh
    messages = f.messages()
    assert any(x.get('type') == 'user' and x.get('text') == fresh for x in messages)
    assert all(x.get('text') != original for x in messages), 'original input replayed into --new'
    previous = f.observer.request('GET', f'/api/session/{sid}/message?limit=100&order=asc')['data']
    assert len(previous) < 100
    assert sum(x.get('type') == 'user' and x.get('text') == original for x in previous) == 1
    f.stop()


def unavailable_case(f):
    original = 'Live unavailable HTTP is not an exited native service.'
    f.launch(original)
    until(lambda: any(x.get('type') == 'assistant' and x.get('finish') == 'stop'
                      for x in f.messages()), 'finite unavailable-service turn')
    service, sid = f.service_identity, f.sid
    terminate(service, signal.SIGSTOP)
    try:
        assert not closed(service)
        f.call('--key', str(uuid.uuid4()), '--project', f.project, 'stop', f.agent)
        journal = document(f.journal_path)
        assert journal.get('lost', False) is False, 'unavailable HTTP manufactured scope exit'
        assert journal.get('retired', False) is False and (f.profile / 'registration').exists()
        refused = f.call('--key', str(uuid.uuid4()), '--project', f.project,
                         'launch', f.agent, '--task', 'Must not replace a live scope.', '--detach', '--new')
        assert refused.returncode != 0 and document(f.journal_path)['vendor_session'] == sid
        assert identity(service['pid']) == service
    finally:
        if not closed(service):
            terminate(service, signal.SIGCONT)
    assert f.api('input/' + f.key)['data']['text'] == original
    f.stop()


def artifact_case(f):
    f.launch('Owned inventory recovery input.')
    directory = f.journal_path.parent
    artifacts = []
    for prefix in ('.se-stage-', '.se-edit-backup-', '.se-edit-'):
        path = directory / (prefix + uuid.uuid4().hex)
        path.write_bytes(b'Preserved staging bytes are never service authority.')
        path.chmod(0o600)
        artifacts.append((path, path.read_bytes(), path.stat().st_ino))
    service = f.service_identity
    restart_owner(f)
    assert identity(service['pid']) == service
    f.stop()
    for path, contents, inode in artifacts:
        assert path.read_bytes() == contents and path.stat().st_ino == inode
    target = f.root / 'unrelated-protected-input'
    target.write_bytes(b'Unrelated fixture bytes must remain unchanged.')
    target.chmod(0o600)
    for name, link in [('unknown-file', False), ('.se-stage-' + uuid.uuid4().hex, True)]:
        path = directory / name
        if link:
            path.symlink_to(target)
        else:
            path.write_bytes(b'Unknown inventory is not authority.')
            path.chmod(0o600)
        try:
            restart_owner(f)
            result = f.call('--key', str(uuid.uuid4()), '--project', f.project,
                            'launch', f.agent, '--task', 'Must refuse unsafe inventory.', '--detach')
            assert result.returncode != 0, 'unknown or unsafe artifact granted service authority'
            if link:
                assert path.is_symlink()
            else:
                assert path.read_bytes() == b'Unknown inventory is not authority.'
            assert target.read_bytes() == b'Unrelated fixture bytes must remain unchanged.'
        finally:
            path.unlink()
    restart_owner(f)


def uncertain_case(f):
    task, request = 'Owned uncertain input marker.', str(uuid.uuid4())
    argv = [str(f.se), '--json', '--home', str(f.home), '--key', request, '--project',
            f.project, 'launch', f.agent, '--task', task, '--detach']
    with (f.root / 'uncertain-launch.stdout').open('wb') as out, \
            (f.root / 'uncertain-launch.stderr').open('wb') as err:
        caller = subprocess.Popen(argv, cwd=f.repo, env=f.env, stdin=subprocess.DEVNULL,
                                  stdout=out, stderr=err)
        try:
            until(lambda: (f.root / 'write-frozen').exists(), 'original pipe write barrier', 40)
            frozen_pid, fd, count = (f.root / 'write-frozen').read_text().split()
            assert int(frozen_pid) == f.runtime['pid'] and int(count) == len(task)
            journal = f.bind()
            assert journal['initial_offered'] is True
            key = f.key
            accepted = until(lambda: f.api('input/' + key)['data'], 'original native admission')
            assert accepted['text'] == task
            old_runtime = f.runtime
            terminate(old_runtime, signal.SIGKILL)
            assert f.foreground.wait(timeout=10) == -signal.SIGKILL
            f.foreground_out.close()
            f.foreground_err.close()
            f.foreground = None
            assert caller.wait(timeout=15) != 0, 'uncertain launch manufactured success'
        finally:
            if caller.poll() is None:
                original = identity(caller.pid)
                assert original['argv'] == argv
                terminate(original, signal.SIGKILL)
                caller.wait(timeout=5)
    f.ok('up')
    endpoint = document(f.home / 'endpoint.json')
    f.runtime = identity(endpoint['epoch']['owner']['pid'])
    assert f.runtime != old_runtime
    assert f.api('input/' + key)['data'] == accepted
    retry = f.call('--key', request, '--project', f.project, 'launch', f.agent,
                   '--task', task, '--detach')
    (f.root / 'original-retry-result.json').write_text(json.dumps({'exit': retry.returncode}))
    assert f.api('input/' + key)['data'] == accepted
    assert len([x for x in f.messages() if x.get('type') == 'user' and x.get('text') == task]) == 1
    f.stop()


def reader_case(f):
    f.launch('Owned uncertain input marker.')
    row = f.row()
    client = row['session']['process']['pid']
    native = identity(client)
    pipe = os.readlink(Path('/proc') / str(client) / 'fd/1')
    (f.root / 'client-before-reader-loss.json').write_text(json.dumps(native, indent=2))
    assert pipe.startswith('pipe:[')
    (f.root / 'drop-reader').write_text('lose this owned reader after the next native frame')
    sent = f.ok('--key', str(uuid.uuid4()), '--project', f.project, 'msg', 'send', f.agent,
                'Synthetic later source for the owned reader-loss check.')
    until(lambda: (f.root / 'write-frozen').exists(), 'owned stdout reader loss')
    pid, descriptor, inode = (f.root / 'write-frozen').read_text().split()
    assert int(pid) == f.runtime['pid']
    assert native['image'] == str(PROVIDER)
    assert native['argv'] == [str(PROVIDER), 'run', '--service', str(f.profile),
                              '--session', f.sid, '--stdin', '--jsonl', '--resident',
                              '--input-id', f.key]
    assert pipe == 'pipe:[' + inode + ']'
    assert os.readlink(Path('/proc') / pid / ('fd/' + descriptor)) == '/dev/null'
    assert not closed(f.service_identity) and not closed(f.runtime)
    row = f.row()
    assert row['secode_runtime']['state'] == 'present'
    (f.root / 'row-after-reader-loss.json').write_text(json.dumps(row, indent=2))
    until(lambda: any(x.get('type') == 'assistant' and x.get('finish') == 'stop'
                      for x in f.messages()), 'canonical answer survives lost reader')
    f.stop()
    history = f.ok('--project', f.project, 'history', '--agent', f.agent,
                   '--kind', 'session.turn', '--limit', '100')
    assert history['window']['complete'] and history['next'] is None
    assert any(x.get('payload', {}).get('role') == 'user'
               and x['payload']['body'].get('complete') is True
               and sent['message_id'] in x['payload']['body'].get('text', '')
               for x in history['items']), 'post-loss native notice was not canonically captured'
    assert any(x.get('payload', {}).get('role') == 'assistant'
               and x['payload']['body'].get('complete') is True
               and 'Owned synthetic fixture answer.' in x['payload']['body'].get('text', '')
               for x in history['items'])


def main():
    global HOST, PROVIDER
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--case', choices=['mail', 'takeover', 'host-crash', 'service-crash', 'settled-service-crash', 'service-new', 'cold-service-new', 'service-unavailable', 'artifacts', 'uncertain', 'reader'], default='mail')
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--secode', type=Path, required=True)
    parser.add_argument('--pin', default=PIN)
    args = parser.parse_args()
    if sys.platform != 'linux':
        raise RuntimeError('REFUSE: this native fault judge requires Linux; Windows needs its native worker')
    if args.pin != PIN:
        raise RuntimeError('REFUSE: judge requires its original external-service pin')
    PROVIDER = args.secode.resolve()
    receipt = document(PROVIDER.parent / 'build-receipt.json')
    assert all(receipt[key] == PIN for key in ('source_commit', 'commit_before', 'commit_after'))
    assert all(receipt[key] is False for key in ('tree_dirty', 'tree_dirty_before', 'tree_dirty_after'))
    for name in ('secode', 'secode-server'):
        path = PROVIDER.with_name(name)
        assert path.stat().st_size == receipt['outputs'][name]['bytes']
        assert image_hash(path) == receipt['outputs'][name]['sha256']
    HOST = args.se.resolve()
    preload = None
    if args.case in ('uncertain', 'reader'):
        fault_root = args.output.resolve().with_name(args.output.name + '-fault')
        fault_root.mkdir(mode=0o700)
        preload = fault_root / (args.case + '.so')
        subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                        str(Path(__file__).with_name('secode_managed_fault.c')), '-ldl', '-o', str(preload)],
                       check=True, capture_output=True, timeout=30)
    fixture = Consumer(args.output, preload=preload, fault=args.case)
    print('1..1', flush=True)
    try:
        if args.case in ('service-new', 'cold-service-new'):
            service_new_case(fixture, cold=args.case == 'cold-service-new')
        elif args.case == 'service-unavailable':
            unavailable_case(fixture)
        elif args.case == 'artifacts':
            artifact_case(fixture)
        elif args.case == 'reader':
            reader_case(fixture)
        elif args.case == 'uncertain':
            uncertain_case(fixture)
        elif args.case == 'mail':
            mail_case(fixture)
        else:
            lifecycle_case(fixture, args.case)
        print('ok 1 - ' + args.case + ' preserves original identities and reports custody honestly', flush=True)
    finally:
        fixture.close()


if __name__ == '__main__':
    main()
