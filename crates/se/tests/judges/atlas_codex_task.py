"""Protects: B4 follows real Codex file work and captured history in a live session.

The loopback Responses framing follows the native provider review fixture.
The real installed Codex executes the tool; this is not a paid-model witness.
"""
import ctypes
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shlex
import subprocess
import threading
import time
import uuid

from atlas_memory import process


class TaskModel:
    def __init__(self, output, repo, token):
        self.output, self.repo, self.token = output, repo, token
        self.requests, self.failures, self.step = [], [], 0
        self.lock = threading.Lock()
        model = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                body = json.dumps({'object': 'list', 'data': []}).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    assert 0 < length <= 4 * 1024 * 1024, 'fixture request exceeded bound'
                    raw = self.rfile.read(length)
                    if self.headers.get('Content-Encoding') == 'zstd':
                        zstd = ctypes.CDLL('libzstd.so.1')
                        zstd.ZSTD_decompress.restype = ctypes.c_size_t
                        zstd.ZSTD_isError.argtypes = [ctypes.c_size_t]
                        output = ctypes.create_string_buffer(16 * 1024 * 1024)
                        size = zstd.ZSTD_decompress(output, len(output), raw, len(raw))
                        assert not zstd.ZSTD_isError(size), 'invalid compressed fixture request'
                        raw = output.raw[:size]
                    model.respond(self, json.loads(raw))
                except Exception as error:
                    model.failures.append(str(error))
                    self.send_error(500)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def respond(self, handler, request):
        with self.lock:
            self.requests.append(request)
            (self.output / 'model-requests.json').write_text(json.dumps(self.requests, indent=2))
            metadata = json.loads(request.get('client_metadata', {}).get('x-codex-turn-metadata', '{}'))
            title = metadata.get('thread_source') == 'thread_title'
            if title:
                text = json.dumps({'title': 'Atlas native memory task'})
            elif self.step == 0:
                script = ("from pathlib import Path;print(Path('ordinary.py').read_text());"
                          "p=Path('b4-task.txt');p.write_text(" + repr(self.token + '\n') +
                          ");print('Task effect: '+p.read_text().strip())")
                code = 'text(await tools.exec_command(' + json.dumps({
                    'cmd': 'python3 -c ' + shlex.quote(script), 'workdir': str(self.repo),
                    'max_output_tokens': 1200}) + '));'
                item = {'type': 'custom_tool_call', 'id': 'ctc_' + uuid.uuid4().hex,
                        'call_id': 'call_' + uuid.uuid4().hex, 'namespace': 'functions',
                        'name': 'exec', 'input': code, 'status': 'completed'}
                self.step += 1
                text = None
            else:
                assert 'Task effect: ' + self.token in json.dumps(request.get('input', [])), (
                    'native tool write/read result was not returned to the real provider')
                text = 'Atlas memory task completed: ' + self.token
                self.step += 1
            if text is not None:
                item = {'type': 'message', 'id': 'msg_' + uuid.uuid4().hex, 'role': 'assistant',
                        'phase': 'final_answer', 'status': 'completed',
                        'content': [{'type': 'output_text', 'text': text,
                                     'annotations': [], 'logprobs': []}]}
        response = {'id': 'resp_' + uuid.uuid4().hex, 'object': 'response',
                    'created_at': int(time.time()), 'model': request.get('model', 'fixture'),
                    'status': 'in_progress', 'output': []}
        events = [
            ('response.created', {'response': response}),
            ('response.output_item.added', {'output_index': 0,
                                           'item': item | {'status': 'in_progress'}}),
            ('response.output_item.done', {'output_index': 0, 'item': item}),
            ('response.completed', {'response': response | {'status': 'completed', 'output': [item],
                 'usage': {'input_tokens': 100, 'output_tokens': 50, 'total_tokens': 150,
                           'output_tokens_details': {'reasoning_tokens': 0}}}})]
        encoded = ''.join('event: ' + name + '\ndata: ' + json.dumps(
            data | {'type': name, 'sequence_number': i}) + '\n\n'
            for i, (name, data) in enumerate(events)).encode()
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/event-stream')
        handler.send_header('Content-Length', str(len(encoded)))
        handler.end_headers()
        handler.wfile.write(encoded)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        assert not self.thread.is_alive(), 'loopback model did not close'


class CodexTask:
    def __init__(self, binary, se, home, owner, env, output):
        self.binary, self.se, self.home = binary, se, home
        self.owner, self.env, self.output = owner, dict(env), output
        self.provider = self.native = self.model = None
        self.token = 'atlas-task-' + uuid.uuid4().hex

    def start(self, selected, ok):
        self.model = TaskModel(self.output, selected['repo'], self.token)
        directory = self.owner / '.codex'
        directory.mkdir(mode=0o700, exist_ok=True)
        (directory / 'config.toml').write_text('model_provider="atlas-loopback"\n'
            '[model_providers.atlas-loopback]\nname="Owned Atlas native task"\n'
            'base_url=' + json.dumps(f'http://127.0.0.1:{self.model.server.server_address[1]}/v1') +
            '\nwire_api="responses"\nrequires_openai_auth=false\n')
        version = subprocess.run([str(self.binary), '--version'], env=self.env,
                                 capture_output=True, timeout=15, check=True)
        (self.output / 'codex-version.txt').write_bytes(version.stdout)
        login = subprocess.run([str(self.binary), 'login', '--with-api-key'],
            input=b'sk-owned-atlas-loopback-no-account\n', env=self.env,
            capture_output=True, timeout=15)
        (self.output / 'codex-login.stdout').write_bytes(login.stdout)
        (self.output / 'codex-login.stderr').write_bytes(login.stderr)
        assert login.returncode == 0, 'native fixture login failed; see retained logs'
        config = self.home / 'config.toml'
        text = config.read_text()
        assert text.count('[providers.codex]') == 1, 'native provider config section unavailable'
        config.write_text(text.replace('[providers.codex]', '[providers.codex]\ncommand = ' +
                                      json.dumps(str(self.binary)), 1))
        self.launch = ok('--project', selected['project'], 'launch', selected['agent'], '--detach',
            '--task', 'Read ordinary.py, then write b4-task.txt containing ' + self.token +
            '. Read the file back and confirm completion; do not change other files.')
        self.provider = process(self.launch['process']['pid'])
        # Public launch custody names the stable alias supervisor. Verify the
        # installed provider independently within that exact native ancestry.
        deadline = time.monotonic() + 10
        while True:
            rows = {}
            for directory in Path('/proc').iterdir():
                if directory.name.isdigit():
                    try:
                        row = process(int(directory.name))
                        if row['state'] != 'absent':
                            rows[row['pid']] = row
                    except (FileNotFoundError, ProcessLookupError):
                        pass
            root = rows.get(self.provider['pid'])
            assert root and root['birth'] == self.provider['birth'], 'provider scope changed'
            scope = {self.provider['pid']}
            while True:
                children = {pid for pid, row in rows.items() if row['parent'] in scope}
                if children <= scope:
                    break
                scope |= children
            matches = [rows[pid] for pid in scope if rows[pid].get('image') == str(self.binary)
                       and rows[pid]['state'] != 'Z']
            if matches:
                assert len(matches) == 1, matches
                self.native = matches[0]
                break
            assert time.monotonic() < deadline, 'installed Codex absent from owned provider scope'
            time.sleep(.05)

    def verify(self, selected, ok, wait_seconds):
        deadline = time.monotonic() + wait_seconds
        while True:
            assert not self.model.failures, self.model.failures
            history = ok('--project', selected['project'], 'history', '--agent', selected['agent'],
                         '--kind', 'session.turn', '--limit', '100')
            file = selected['repo'] / 'b4-task.txt'
            if file.exists() and file.read_text() == self.token + '\n' and (
                    'Atlas memory task completed: ' + self.token in json.dumps(history)):
                break
            assert time.monotonic() < deadline, 'real file task/captured reply did not complete'
            time.sleep(.2)
        status = ok('--project', selected['project'], 'agent', 'show', selected['agent'])
        row = status['agent']['value']
        assert row['session']['state'] == 'running', status
        assert row['session']['process']['pid'] == self.provider['pid'], status
        return {'provider': self.provider, 'native_codex': self.native, 'conversation': self.launch['conversation_id'],
                'effect_sha256': hashlib.sha256(file.read_bytes()).hexdigest(),
                'captured_reply': True, 'one_live_session': True,
                'model': 'owned loopback Responses fixture; real installed Codex, no paid model'}

    def close(self):
        if self.model:
            self.model.close()
