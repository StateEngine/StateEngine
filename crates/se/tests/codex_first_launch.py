"""Public first-launch consumer, using stock Codex and an owned loopback model.
Run with --se BINARY --codex NATIVE_CODEX --alias INSTALLED_CODEX_ALIAS --output NEW_DIR.
--expect-red records the two pre-fix refusals without claiming a working launch.
"""
import argparse
import ctypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import socket
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).with_name('judges')))
from mail_cli import Fixture


class Model:
    def __init__(self, root, repo):
        self.root, self.repo, self.sent, self.readback = root, repo, False, False
        self.requests = []
        model = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                body = b'{"object":"list","data":[]}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get('Content-Length', 0))
                if not 0 < length <= 8 * 1024 * 1024:
                    self.send_error(413)
                    return
                raw = self.rfile.read(length)
                if self.headers.get('Content-Encoding') == 'zstd':
                    z = ctypes.CDLL('libzstd.so.1')
                    z.ZSTD_decompress.restype = ctypes.c_size_t
                    z.ZSTD_isError.argtypes = [ctypes.c_size_t]
                    out = ctypes.create_string_buffer(8 * 1024 * 1024)
                    size = z.ZSTD_decompress(out, len(out), raw, len(raw))
                    assert not z.ZSTD_isError(size)
                    raw = out.raw[:size]
                model.respond(self, json.loads(raw))

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        assert not self.thread.is_alive()

    def respond(self, handler, request):
        self.requests.append(request)
        (self.root / 'model-requests.json').write_text(json.dumps(self.requests, indent=2))
        rid = 'resp_' + uuid.uuid4().hex
        if not self.sent:
            self.sent = True
            script = "from pathlib import Path;p=Path('sum.txt');p.write_text('5\\n');print('SUM_READBACK:'+p.read_text())"
            command = 'python3 -c ' + shlex.quote(script)
            code = 'text(await tools.exec_command(' + json.dumps({'cmd': command, 'workdir': str(self.repo), 'max_output_tokens': 1000}) + '));'
            item = {'id': 'ctc_' + uuid.uuid4().hex, 'type': 'custom_tool_call', 'call_id': 'call_' + uuid.uuid4().hex,
                    'namespace': 'functions', 'name': 'exec', 'input': code, 'status': 'completed'}
        else:
            self.readback = any(item.get('type', '').endswith('tool_call_output') and 'SUM_READBACK:5' in json.dumps(item.get('output', '')) for item in request.get('input', []) if isinstance(item, dict))
            item = {'id': 'msg_' + uuid.uuid4().hex, 'type': 'message', 'role': 'assistant', 'status': 'completed',
                    'phase': 'final_answer', 'content': [{'type': 'output_text', 'text': 'SUM_DONE', 'annotations': [], 'logprobs': []}]}
        response = {'id': rid, 'object': 'response', 'created_at': int(time.time()), 'model': request.get('model', 'offline'),
                    'status': 'in_progress', 'output': []}
        events = [{'type': 'response.created', 'response': response},
                  {'type': 'response.output_item.added', 'output_index': 0, 'item': {**item, 'status': 'in_progress'}},
                  {'type': 'response.output_item.done', 'output_index': 0, 'item': item},
                  {'type': 'response.completed', 'response': {**response, 'status': 'completed', 'output': [item],
                   'usage': {'input_tokens': 64, 'output_tokens': 20, 'total_tokens': 84, 'output_tokens_details': {'reasoning_tokens': 0}}}}]
        body = ''.join('event: ' + e['type'] + '\ndata: ' + json.dumps({**e, 'sequence_number': i}) + '\n\n'
                       for i, e in enumerate(events)).encode()
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/event-stream')
        handler.send_header('Content-Length', str(len(body)))
        handler.end_headers()
        try:
            handler.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def run(options):
    os.umask(0o077)
    options.output.mkdir(parents=True, exist_ok=False)
    checks = []
    def check(text):
        checks.append(text)
        print(f'ok {len(checks)} - {text}', flush=True)
    cases = options.case or (['alias', 'socket'] if options.expect_red else ['alias', 'plain-symlink', 'socket'])
    for case_index, case in enumerate(cases):
        directory = options.output / case
        f = Fixture(options.se, directory)
        model = Model(directory, f.repo)
        short = Path(tempfile.mkdtemp(prefix='se5b-first-', dir='/tmp'))
        print("fixture root (retained on failed or interrupted closure):", short, flush=True)
        try:
            for name, suffix in [('XDG_CONFIG_HOME', 'config'), ('XDG_CACHE_HOME', 'cache'), ('XDG_DATA_HOME', 'data'), ('XDG_STATE_HOME', 'state')]:
                location = directory / ('xdg-' + suffix)
                location.mkdir(mode=0o700)
                f.env[name] = str(location)
            f.env.pop('XDG_RUNTIME_DIR', None)
            f.env['TMPDIR'] = '/tmp'
            if case == 'alias':
                f.env['XDG_RUNTIME_DIR'] = str(short)
                command = options.alias
            elif case == 'plain-symlink':
                f.env['XDG_RUNTIME_DIR'] = str(short)
                command = directory / 'codex'
                command.symlink_to(options.codex.resolve(strict=True))
            else:
                command = options.codex
            f.env['PATH'] = str(command.parent) + os.pathsep + os.environ['PATH']
            code_home = directory / 'owned-codex-home'
            code_home.mkdir(mode=0o700)
            f.env.update(CODEX_HOME=str(code_home), OPENAI_API_KEY='sk-owned-loopback-no-account')
            (code_home / 'config.toml').write_text('model_provider = "offline-fixture"\n[model_providers.offline-fixture]\nname = "Owned loopback"\nbase_url = ' + json.dumps('http://127.0.0.1:' + str(model.server.server_port) + '/v1') + '\nwire_api = "responses"\nrequires_openai_auth = false\n')
            login = subprocess.run([str(options.codex), 'login', '--with-api-key'], input=f.env['OPENAI_API_KEY'],
                                   env=f.env, text=True, capture_output=True, timeout=20)
            assert login.returncode == 0, login.stderr
            version = subprocess.run([str(command), '--version'], env=f.env, capture_output=True, timeout=30)
            (directory / 'invoked-version.stdout').write_bytes(version.stdout)
            (directory / 'invoked-version.stderr').write_bytes(version.stderr)
            assert version.returncode == 0 and version.stdout.startswith(b'codex-cli '), (version.stdout, version.stderr)
            check(case + ': invoked configured command identifies stock Codex')
            config = f.home / 'config.toml'
            text = config.read_text()
            if options.port:
                port = options.port + case_index
                with socket.socket() as available:
                    available.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    available.bind(('127.0.0.1', port))
                text, replaced = re.subn(r'(?m)^listen_port = [0-9]+$', 'listen_port = ' + str(port), text, count=1)
                assert replaced == 1, 'configured listener port anchor missing'
            text = text.replace('[providers.codex]', '[providers.codex]\ncommand = ' + json.dumps(str(command)), 1)
            config.write_text(text)
            f.agent = f.ok('--project', f.project, 'agent', 'add', 'First Codex', '--provider', 'codex', '--model', 'gpt-6.1-sol')['agent']['id']
            for as_json in [False, True]:
                # Cover both PATH lookup and an explicit native alias path.
                configured = command.name if case == 'alias' and not as_json else str(command)
                config.write_text(text.replace(json.dumps(str(command)), json.dumps(configured), 1))
                model.sent, model.readback = False, False
                task_file = f.repo / 'sum.txt'
                task_file.unlink(missing_ok=True)
                args = [str(f.se), '--home', str(f.home), '--project', f.project,
                        *(['--json'] if as_json else []), 'launch', f.agent, '--new', '--detach', '--task',
                        'Write sum.txt containing exactly 5 followed by a newline, read it back and reply SUM_DONE.']
                result = subprocess.run(args, env=f.env, stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
                prefix = directory / ('json' if as_json else 'plain')
                prefix.with_suffix('.stdout').write_bytes(result.stdout)
                prefix.with_suffix('.stderr').write_bytes(result.stderr)
                status = f.ok('--project', f.project, 'status')
                pins = [status['runtime']['process']] + [a['session']['process'] for a in status['agents']['items'] if a['session'].get('process')]
                for pin in pins:
                    proc = Path('/proc') / str(pin['pid'])
                    fields = (proc / 'stat').read_text().rsplit(') ', 1)[1].split()
                    assert str((proc / 'exe').resolve()) == pin['exe'], pin
                    f.processes.append((pin['pid'], fields[19]))
                # Retain actual provider descendants too: the stable alias
                # parent alone is not an outside proof that Codex has exited.
                roots = {pin['pid'] for pin in pins[1:]}
                processes = {}
                for proc in Path('/proc').iterdir():
                    if not proc.name.isdigit():
                        continue
                    try:
                        fields = (proc / 'stat').read_text().rsplit(') ', 1)[1].split()
                        processes[int(proc.name)] = (int(fields[1]), fields[19])
                    except (FileNotFoundError, ProcessLookupError):
                        pass
                while True:
                    more = {pid for pid, (parent, _) in processes.items() if parent in roots}
                    if more <= roots:
                        break
                    roots.update(more)
                for pid in roots:
                    f.processes.append((pid, processes[pid][1]))
                if options.expect_red:
                    assert result.returncode != 0, (case, result.stdout)
                    expected = 'version output does not identify codex-cli' if case == 'alias' else 'no protected Unix socket path fits the provider limit'
                    assert expected in result.stderr.decode(), result.stderr
                    check(case + ': baseline reproduces ' + ('JSON' if as_json else 'plain') + ' refusal')
                else:
                    assert result.returncode == 0, (args, result.stdout, result.stderr)
                    if not as_json:
                        assert not result.stdout.lstrip().startswith(b'{'), result.stdout
                    end = time.monotonic() + 60
                    while time.monotonic() < end and not (task_file.exists() and model.readback):
                        time.sleep(0.2)
                    assert task_file.read_text() == '5\n' and model.readback, (case, 'native work/readback incomplete')
                    check(case + ': ' + ('JSON' if as_json else 'plain') + ' launch performs and reads back the real task')
                    stopped = f.ok('--project', f.project, 'stop', f.agent)
                    assert stopped['complete'] and stopped['witness']['state'] == 'witnessed' and stopped['method'] == 'graceful', stopped
                    if case == 'plain-symlink':
                        assert stopped['target']['process']['exe'] == str(options.codex.resolve(strict=True)), stopped
                    elif case == 'alias':
                        assert stopped['target']['process']['exe'] == str(Path('/bin/sh').resolve(strict=True)), stopped
                    check(case + ': public stop is graceful with no force fallback')
                    f.close()
            if not options.expect_red:
                f.close()
                config.write_text(text.replace(json.dumps(str(command)), json.dumps('/bin/echo'), 1))
                rejected = f.call('--project', f.project, 'launch', f.agent, '--detach')
                assert rejected.returncode != 0 and b'version output does not identify codex-cli' in rejected.stderr
                check(case + ': genuinely non-Codex binary remains refused')
        finally:
            f.close()
            model.close()
            (short / 'stateengine').rmdir() if (short / 'stateengine').exists() else None
            short.rmdir()
        (directory / 'closure.json').write_text(json.dumps({'observed_births': f.processes, 'endpoint_absent': not (f.home / 'endpoint.json').exists(), 'exact_births_rechecked_by_consumer': True}, indent=2))
        check(case + ': public down and outside exact-birth closure complete')
    (options.output / 'result.json').write_text(json.dumps({'passed': len(checks), 'checks': checks}, indent=2))

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--se', type=Path, required=True)
    p.add_argument('--codex', type=Path, required=True)
    p.add_argument('--alias', type=Path, required=True)
    p.add_argument('--case', action='append', choices=['alias', 'plain-symlink', 'socket'], help='Limit this run to named public consumers')
    p.add_argument('--port', type=int, help='Explicit distinct native listener port for this runtime lane')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--expect-red', action='store_true')
    o = p.parse_args()
    o.se, o.codex, o.alias, o.output = [x.absolute() for x in [o.se, o.codex, o.alias, o.output]]
    run(o)
