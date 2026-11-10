"""Pinned external-service observer for the headless host acceptance consumer.

This entry point qualifies only service interfaces. It does not qualify the
StateEngine adapter, paid providers, or Windows service cancellation.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from urllib.parse import urlsplit


PIN = '48c886300000f098f2c33a4001f2b11375fe7a02'
BOUND = 2 * 1024 * 1024


def document(path, bound=BOUND):
    with path.open('rb') as source:
        raw = source.read(bound + 1)
    if len(raw) > bound:
        raise RuntimeError('document exceeds read bound: ' + str(path))
    return json.loads(raw)


def image_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def package(secode, pin):
    if pin != PIN:
        raise RuntimeError('judge contract requires its original SE Code pin')
    receipt = document(secode.parent / 'build-receipt.json', 64 * 1024)
    if (any(receipt.get(key) != pin for key in ('source_commit', 'commit_before', 'commit_after'))
            or any(receipt.get(key) is not False
                   for key in ('tree_dirty', 'tree_dirty_before', 'tree_dirty_after'))):
        raise RuntimeError('package source identity or clean build binding is unproved')
    hashes = {}
    suffix = '.exe' if os.name == 'nt' else ''
    for name in ('secode', 'secode-server'):
        path = secode.parent / (name + suffix)
        expected = receipt['outputs'][name]
        if path.stat().st_size != expected['bytes']:
            raise RuntimeError('packaged image size differs: ' + name)
        hashes[name] = image_hash(path)
        if hashes[name] != expected['sha256']:
            raise RuntimeError('packaged image hash differs: ' + name)
    return hashes


def environment(root):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('STATEENGINE_', 'SECODE_', 'SE_', 'CLAUDE',
                                  'ANTHROPIC', 'OPENAI', 'CODEX', 'OTEL_'))}
    owner = root / 'owner'
    owner.mkdir()
    env.update(HOME=str(owner), USERPROFILE=str(owner),
               XDG_CONFIG_HOME=str(owner / 'config'), XDG_DATA_HOME=str(owner / 'data'))
    return env


def invoke(argv, root, env, name):
    with (root / (name + '.stdout')).open('wb') as out, \
            (root / (name + '.stderr')).open('wb') as err:
        result = subprocess.run([str(x) for x in argv], env=env, cwd=root,
                                stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=30)
    if result.returncode:
        raise RuntimeError(name + ' refused; see retained stdout/stderr')
    return document(root / (name + '.stdout'))


def capabilities(value):
    if (value.get('schema') != 'secode.external-host-capabilities.v1'
            or value.get('external_host') is not True
            or value.get('stateengine', {}).get('embedded_owner_composed') is not False
            or value.get('stateengine', {}).get('owner') != 'external'
            or value.get('initial_input', {}).get('cli_argument') != '--input-id'
            or value.get('initial_input', {}).get('uncertain_write') != 'pending-no-replay'
            or value.get('native_notice', {}).get('body_delivery') is not False
            or value.get('native_notice', {}).get('message_limit') != 32):
        raise RuntimeError('external host, keyed input or native notice capability differs')


def account_fixture(root):
    """Explicit disposable configuration imported through the public initializer."""
    source = root / 'account-fixture'
    source.mkdir()
    (source / 'secode.jsonc').write_text(json.dumps({
        'store': {'authority': 'open-ready'},
        'provider': {'id': 'openai', 'model': 'gpt-live', 'base_model': 'gpt-live',
                     'family': 'openai-responses', 'route': 'route-live', 'account': 'account-a',
                     'credential_version': 'credential-v1', 'policy_version': 'live-policy-v1',
                     'variants': []}, 'catalog': {'source': 'models.dev-chatgpt'}, 'compaction': {}}))
    (source / 'provider.credential').write_text('owned-nonbillable-fixture')
    (source / 'model-catalog.json').write_text(json.dumps({'openai': {
        'id': 'openai', 'name': 'OpenAI', 'npm': '@ai-sdk/openai', 'models': {'gpt-live': {
            'id': 'gpt-live', 'name': 'Fixture', 'family': 'gpt-5', 'tool_call': True,
            'modalities': {'input': ['text'], 'output': ['text']}, 'limit': {'output': 32000}}}}}))
    (source / 'account-models.json').write_text(json.dumps({'models': [{
        'slug': 'gpt-live', 'visibility': 'list', 'context_window': 128000,
        'supported_reasoning_levels': []}]}))
    return source


class Service:
    def __init__(self, secode, root, env):
        self.secode, self.root, self.env = secode, root, env
        self.profile = root / 'service'
        self.process = None
        self.stdout = self.stderr = None
        self.endpoint = self.authorization = None
        self.pid_birth = None
        self.calls = 0
        self.initialized = False

    def start(self):
        suffix = '.exe' if os.name == 'nt' else ''
        server = self.secode.parent / ('secode-server' + suffix)
        # Profile creation is supported public bootstrap, never a database edit.
        if not self.initialized:
            seed = account_fixture(self.root)
            with (self.root / 'init.stdout').open('wb') as out, \
                    (self.root / 'init.stderr').open('wb') as err:
                done = subprocess.run([str(server), 'init-profile', '--service', str(self.profile),
                                       '--from', str(seed)],
                                      env=self.env, cwd=self.root, stdin=subprocess.DEVNULL,
                                      stdout=out, stderr=err, timeout=30)
            if done.returncode:
                raise RuntimeError('private profile initialization refused; see init.stderr')
            self.initialized = True
        if os.name != 'posix':
            raise RuntimeError('REFUSE: Windows service Ctrl+C qualification belongs to the native worker')
        self.stdout = (self.root / 'service.stdout').open('ab')
        self.stderr = (self.root / 'service.stderr').open('ab')
        self.process = subprocess.Popen([str(server), 'serve-service', '--service', str(self.profile),
                                         '--port', '0', '--external-host'], env=self.env,
                                        cwd=self.root, stdin=subprocess.DEVNULL,
                                        stdout=self.stdout, stderr=self.stderr, start_new_session=True)
        self.pid_birth = self.identity()
        until, last = time.monotonic() + 30, None
        while time.monotonic() < until:
            if self.process.poll() is not None:
                raise RuntimeError('external service exited before readiness; see service.stderr')
            try:
                ready = document(self.profile / 'serve-ready.json')
                self.endpoint = urlsplit(ready['observed_endpoint'])
                if (self.endpoint.scheme != 'http'
                        or self.endpoint.hostname not in ('127.0.0.1', '::1', 'localhost')
                        or not self.endpoint.port or self.endpoint.username or self.endpoint.password):
                    raise RuntimeError('private service endpoint is not plain loopback')
                credential = (self.profile / 'basic.credential').read_bytes()
                if not 0 < len(credential) <= 8192 or b'\0' in credential:
                    raise RuntimeError('private service credential is invalid')
                self.authorization = 'Basic ' + base64.b64encode(credential.rstrip(b'\r\n')).decode()
                health = self.request('GET', '/api/health')
                if health.get('pid') != self.process.pid:
                    raise RuntimeError('authenticated health names another process')
                self.verify_identity()
                return ready
            except (FileNotFoundError, json.JSONDecodeError, ConnectionError) as error:
                last = type(error).__name__
                time.sleep(.05)
        raise RuntimeError('external service readiness deadline expired; last=' + str(last))

    def identity(self):
        source = Path('/proc') / str(self.process.pid)
        stat = (source / 'stat').read_text().rsplit(') ', 1)[1].split()
        argv = (source / 'cmdline').read_bytes().split(b'\0')
        argv = [os.fsdecode(value) for value in argv if value]
        server = self.secode.with_name('secode-server')
        if (not argv or Path(argv[0]).resolve() != server
                or '--service' not in argv
                or argv[argv.index('--service') + 1] != str(self.profile)):
            raise RuntimeError('full owned service command line does not match its private profile')
        return {'pid': self.process.pid, 'birth': stat[19],
                'image': str((source / 'exe').resolve(strict=True)), 'argv': argv}

    def verify_identity(self):
        if self.identity() != self.pid_birth:
            raise RuntimeError('owned service identity changed')

    def request(self, method, path, body=None, expected=200):
        if not path.startswith('/api/'):
            raise RuntimeError('unsupported external-service route')
        connection = http.client.HTTPConnection(self.endpoint.hostname, self.endpoint.port, timeout=10)
        try:
            connection.request(method, path, body=None if body is None else json.dumps(body), headers={
                'Authorization': self.authorization, 'Content-Type': 'application/json'})
            response = connection.getresponse()
            raw = response.read(BOUND + 1)
            self.calls += 1
            stem = self.root / f'http-{self.calls:02}'
            stem.with_suffix('.json').write_text(json.dumps({
                'method': method, 'path': path, 'status': response.status,
                'body_bytes': len(raw), 'truncated': len(raw) > BOUND}))
            stem.with_suffix('.body').write_bytes(raw[:BOUND])
            if len(raw) > BOUND:
                raise RuntimeError('authenticated response exceeds read bound')
            if response.status != expected:
                raise RuntimeError(f'authenticated {method} {path} returned {response.status}, expected {expected}')
            return None if expected == 204 else json.loads(raw)
        finally:
            connection.close()

    def close(self):
        forced = False
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    self.verify_identity()
                    self.process.send_signal(signal.SIGTERM)
                try:
                    code = self.process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    self.verify_identity()
                    self.process.kill()
                    self.process.wait(timeout=10)
                    forced = True
                    raise RuntimeError('private service required forced cleanup')
                if code or (self.profile / 'registration').exists():
                    raise RuntimeError('service exit or registration retirement is unproved')
                closed = {'pid': self.process.pid, 'exit': code, 'forced': forced,
                          'registration_absent': True}
                self.process = None
                return closed
            return {'created': False}
        finally:
            for output in (self.stdout, self.stderr):
                if output is not None:
                    output.close()


def service_identity(value):
    result = value['service']
    for key in ('incarnation', 'serviceInstance', 'registrationVersion'):
        if not isinstance(result.get(key), str) or not result[key]:
            raise RuntimeError('authenticated service identity lacks ' + key)
    if type(result.get('generation')) is not int or result['generation'] < 0:
        raise RuntimeError('authenticated service generation is invalid')
    return {key: result[key] for key in ('incarnation', 'serviceInstance', 'generation', 'registrationVersion')}


def acceptance(value, service, session, key, text):
    if service_identity(value) != service:
        raise RuntimeError('acceptance comes from a changed service incarnation')
    row = value['data']
    if row is None:
        raise RuntimeError('acceptance is absent in this service; uncertain input must not be replayed')
    if (row.get('id') != key or row.get('sessionID') != session or row.get('text') != text
            or type(row.get('admittedSeq')) is not int or row['admittedSeq'] < 1
            or row.get('delivery') != 'queue' or row.get('metadata') != {'origin': 'seat-startup'}):
        raise RuntimeError('original keyed acceptance coordinates differ')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--secode', required=True, type=Path)
    parser.add_argument('--secode-pin', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    os.chmod(args.output, 0o700)
    env = environment(args.output)
    # The model is not used by admit-only checks; any accidental execution can
    # reach only this explicit loopback refusal, never a real provider account.
    env['SECODE_LIVE_HEADLESS_LOOPBACK'] = 'http://127.0.0.1:9'
    result = {'secode_pin': args.secode_pin, 'checks': [], 'outcome': 'failed',
              'bounds': 'external-interface dependency only; no StateEngine launch qualification'}
    service = Service(args.secode.resolve(), args.output, env)
    try:
        result['images'] = package(args.secode.resolve(), args.secode_pin)
        capabilities(invoke([args.secode.resolve().with_name('secode-server'),
                             '--external-host-capabilities'], args.output, env, 'capabilities'))
        result['checks'].append('exact clean-source package and required capabilities bound')
        result['ready'] = service.start()
        result['checks'].append('supported private startup has authenticated same-process health')
        status = invoke([args.secode.resolve(), 'status', '--service', service.profile, '--jsonl'],
                        args.output, env, 'status')
        result['status'] = status
        result['checks'].append('public status authenticates the independently owned service')
        created = service.request('POST', '/api/session', {'location': {'directory': str(args.output)}})
        session = created['data']['id']
        key, text = 'msg_judge_initial', 'Retain this original keyed input.'
        path = f'/api/session/{session}/input/{key}'
        absent = service.request('GET', path)
        identity = service_identity(absent)
        if absent['data'] is not None:
            raise RuntimeError('fresh keyed input unexpectedly exists')
        service.request('POST', f'/api/session/{session}/prompt', {
            'id': key, 'text': text, 'delivery': 'queue', 'resume': False,
            'metadata': {'origin': 'seat-startup'}})
        first = acceptance(service.request('GET', path), identity, session, key, text)
        second = acceptance(service.request('GET', path), identity, session, key, text)
        if first != second:
            raise RuntimeError('read-only keyed lookup changed its durable admission')
        result['checks'].append('keyed admission and independent lookup preserve original coordinates')
        notice_path = f'/api/session/{session}/stateengine/notice'
        unbound = service.request('GET', notice_path)
        if unbound['status'] != 'rebind-required' or service_identity(unbound) != identity:
            raise RuntimeError('fresh session falsely claims a native notice binding')
        service.request('PUT', f'/api/session/{session}/instructions/entries/stateengine-identity', {
            'value': {'project_id': 'judge-project', 'agent_id': 'judge-agent', 'scope': 'project'}}, 204)
        service.request('PUT', f'/api/session/{session}/stateengine/capability',
                        {'capability': 'isolated-interface-fixture'}, 204)
        binding = service.request('GET', notice_path)
        if (binding['status'] != 'ready' or service_identity(binding) != identity
                or not binding.get('targetID') or not binding.get('binding')):
            raise RuntimeError('native notice binding is absent or belongs to another service')
        result['checks'].append('authenticated native notice binding distinguishes absent from ready')
        notice = {'id': 'msg_judge_notice', 'targetID': binding['targetID'],
                  'binding': binding['binding'], 'messages': ['source-committed-fixture'], **identity}
        notice_read = f'/api/session/{session}/input/{notice["id"]}'
        for field, foreign in (('incarnation', 'foreign-incarnation'),
                               ('serviceInstance', 'foreign-instance'), ('targetID', 'evt_foreign')):
            service.request('POST', notice_path, {**notice, field: foreign}, 409)
            absent = service.request('GET', notice_read)
            if service_identity(absent) != identity or absent['data'] is not None:
                raise RuntimeError('rejected notice acquired durable admission')
        result['checks'].append('foreign incarnation, service and target refuse without admission')
        offered = service.request('POST', notice_path, notice)
        replay = service.request('POST', notice_path, notice)
        readback = service.request('GET', notice_read)
        if (any(service_identity(value) != identity for value in (offered, replay, readback))
                or offered['data'] != replay['data'] or replay['data'] != readback['data']
                or readback['data']['id'] != notice['id']
                or readback['data']['sessionID'] != session or readback['data']['kind'] != 'synthetic'):
            raise RuntimeError('native notice retry/readback changed the original admission')
        result['checks'].append('notice retry and read-only acceptance retain one synthetic admission')
        service.request('PUT', f'/api/session/{session}/stateengine/capability',
                        {'capability': 'replacement-isolated-fixture'}, 204)
        service.request('POST', notice_path, notice, 409)
        if service.request('GET', notice_read)['data'] != offered['data']:
            raise RuntimeError('old notice migrated across binding replacement')
        result['checks'].append('binding replacement fences the old notice without rewriting its acceptance')
        result['first_shutdown'] = service.close()
        result['restarted_ready'] = service.start()
        after = service_identity(service.request('GET', notice_path))
        if after['incarnation'] == identity['incarnation']:
            raise RuntimeError('clean restart reused the authenticated service incarnation')
        service.request('POST', notice_path, {**notice, **after,
                                           'incarnation': identity['incarnation']}, 409)
        result['checks'].append('clean service restart changes incarnation and fences old-lifetime offers')
        result['outcome'] = 'passed'
    finally:
        try:
            result['cleanup'] = service.close()
        except Exception as error:
            result['cleanup_error'] = str(error)
            result['outcome'] = 'failed'
            raise
        finally:
            (args.output / 'result.json').write_text(json.dumps(result, indent=2))
            print(f"external interfaces: {len(result['checks'])} passed; outcome={result['outcome']}")


if __name__ == '__main__':
    main()
