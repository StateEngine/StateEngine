"""One plain stock app-server per login on its control socket; two agents through stock proxies.

Self-contained and cross-platform (Linux and Windows): synthetic loopback login and model
server, no real account. Checks: each agent's turn completes, each agent's tool shell sees
only its own per-thread SE_SESSION, and one proxy exiting leaves the server and the other
agent working. Usage: xprobe.py <codex-binary> <new-output-dir> [default|explicit]
`default` listens on `unix://` (the login's default control socket); `explicit` names that path.
"""
import base64, datetime, http.server, json, os, queue, struct, subprocess, sys, threading, time, traceback
from pathlib import Path

B = sys.argv[1]; OUT = Path(sys.argv[2]).resolve(); OUT.mkdir(parents=True, exist_ok=False)
MODE = sys.argv[3] if len(sys.argv) > 3 else 'default'
WIN = os.name == 'nt'


def jwt(exp):
    enc = lambda v: base64.urlsafe_b64encode(json.dumps(v).encode()).decode().rstrip('=')
    return enc({'alg': 'none'}) + '.' + enc({'exp': exp, 'sub': 'SYNTHETIC_USER', 'https://api.openai.com/auth': {
        'chatgpt_account_id': 'SYNTHETIC_ACCOUNT', 'chatgpt_user_id': 'SYNTHETIC_USER', 'chatgpt_plan_type': 'plus'}}) + '.SYNTHETIC_SIGNATURE'


ACCESS = jwt(time.time() + 3600)
AUTH = {'auth_mode': 'chatgpt', 'OPENAI_API_KEY': None, 'tokens': {'access_token': ACCESS, 'id_token': ACCESS,
        'refresh_token': '', 'account_id': 'SYNTHETIC_ACCOUNT'}, 'last_refresh': datetime.datetime.now(datetime.timezone.utc).isoformat()}
SHELL_ECHO = 'echo "SEEN=$env:SE_SESSION"' if WIN else 'echo SEEN=$SE_SESSION'
seen = []


class Model(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def reply(self, code, body, kind='application/json'):
        self.send_response(code); self.send_header('content-type', kind); self.send_header('content-length', str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self): self.reply(200, b'{"models":[]}')

    def do_CONNECT(self): self.reply(502, b'{}')

    def do_POST(self):
        raw = json.loads(self.rfile.read(int(self.headers.get('content-length', '0'))) or b'{}')
        if not self.path.endswith('/responses'):
            self.reply(404, b'{}'); return
        items = raw.get('input', [])
        markers = [c.get('text') for i in items if i.get('type') == 'message' for c in (i.get('content') or [])
                   if 'XPROBE' in str(c.get('text', ''))]
        marker = markers[-1] if markers else None
        # Only outputs after the latest user marker belong to this turn.
        last = max((n for n, i in enumerate(items) if i.get('type') == 'message' and any(
            'XPROBE' in str(c.get('text', '')) for c in (i.get('content') or []))), default=-1)
        outputs = [i for i in items[last + 1:] if i.get('type', '').endswith('call_output')]
        seen.append({'marker': marker, 'outputs': outputs, 'tools': [t.get('name') or t.get('type') for t in raw.get('tools', [])]})
        rid = f'r{len(seen)}'
        if marker and 'shell' in marker and not outputs:
            item = {'type': 'function_call', 'id': rid + '_fc', 'call_id': rid + '_call', 'name': 'exec_command', 'arguments': json.dumps({'cmd': SHELL_ECHO})}
        else:
            item = {'type': 'message', 'role': 'assistant', 'id': rid + '_m', 'content': [{'type': 'output_text', 'text': 'done'}]}
        events = [{'type': 'response.created', 'response': {'id': rid}}, {'type': 'response.output_item.done', 'item': item},
                  {'type': 'response.completed', 'response': {'id': rid, 'usage': {'input_tokens': 1, 'input_tokens_details': None,
                   'output_tokens': 1, 'output_tokens_details': None, 'total_tokens': 2}}}]
        self.reply(200, ''.join('data: ' + json.dumps(x) + '\n\n' for x in events).encode(), 'text/event-stream')


class Client:
    """JSON-RPC over WebSocket over the stock proxy's stdio."""

    def __init__(self, env, cwd):
        self.p = subprocess.Popen([B, 'app-server', 'proxy'], env=env, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=open(cwd / 'proxy.err', 'wb'))
        self.chunks = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        key = base64.b64encode(os.urandom(16)).decode()
        self.p.stdin.write(f'GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                           f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n'.encode()); self.p.stdin.flush()
        self.buf = b''
        while b'\r\n\r\n' not in self.buf:
            self.buf += self._raw(15)
        head, self.buf = self.buf.split(b'\r\n\r\n', 1)
        if b' 101 ' not in head.split(b'\r\n')[0]:
            raise RuntimeError('proxy upgrade refused: ' + head.decode(errors='replace'))
        self.id = 0; self.backlog = []
        self.request('initialize', {'clientInfo': {'name': 'xprobe', 'version': '1'}, 'capabilities': {'experimentalApi': True}})
        self.send({'method': 'initialized'})

    def _pump(self):
        while True:
            data = self.p.stdout.read1(1 << 20)
            self.chunks.put(data)
            if not data:
                return

    def _raw(self, t):
        try:
            data = self.chunks.get(timeout=t)
        except queue.Empty:
            raise TimeoutError('proxy silent')
        if not data:
            raise EOFError('proxy closed')
        return data

    def send(self, value):
        data = json.dumps(value).encode(); mask = os.urandom(4); n = len(data)
        head = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else bytes([0xFE]) + struct.pack('>H', n) if n < 65536 else bytes([0xFF]) + struct.pack('>Q', n))
        self.p.stdin.write(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))); self.p.stdin.flush()

    def frame(self, t):
        while True:
            if len(self.buf) >= 2:
                op, n, off = self.buf[0] & 15, self.buf[1] & 127, 2
                if n == 126:
                    n, off = struct.unpack('>H', self.buf[2:4])[0], 4
                elif n == 127:
                    n, off = struct.unpack('>Q', self.buf[2:10])[0], 10
                if len(self.buf) >= off + n:
                    body, self.buf = self.buf[off:off + n], self.buf[off + n:]
                    if op == 1:
                        return json.loads(body)
                    if op == 8:
                        raise EOFError('websocket closed')
                    continue
            self.buf += self._raw(t)

    def next(self, pred, t=60):
        for i, v in enumerate(self.backlog):
            if pred(v):
                return self.backlog.pop(i)
        end = time.monotonic() + t
        while time.monotonic() < end:
            v = self.frame(max(.1, end - time.monotonic()))
            if 'id' in v and 'method' in v:
                self.send({'id': v['id'], 'error': {'code': -32601, 'message': 'xprobe'}})
            if pred(v):
                return v
            self.backlog.append(v)
        raise TimeoutError('deadline')

    def request(self, method, params):
        self.id += 1; n = self.id; self.send({'id': n, 'method': method, 'params': params})
        r = self.next(lambda x: x.get('id') == n)
        if 'error' in r:
            raise RuntimeError(json.dumps(r))
        return r['result']


def turn(c, t, text):
    c.request('turn/start', {'threadId': t, 'input': [{'type': 'text', 'text': text}], 'effort': 'low'})
    return c.next(lambda x: x.get('method') == 'turn/completed' and x['params'].get('threadId') == t)['params']['turn']['status']


rec = {'platform': sys.platform, 'mode': MODE, 'complete': False}
model = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Model); model.daemon_threads = True
threading.Thread(target=model.serve_forever, daemon=True).start(); url = f'http://127.0.0.1:{model.server_port}'
server = None; clients = []
try:
    home = OUT / 'home'; home.mkdir()
    (home / 'auth.json').write_text(json.dumps(AUTH))
    (home / 'config.toml').write_text(f'''model = "gpt-5.5"
model_provider = "synthetic"
cli_auth_credentials_store = "file"
chatgpt_base_url = "{url}"
approval_policy = "never"
sandbox_mode = "workspace-write"
[features]
apps = false
[model_providers.synthetic]
name = "Synthetic"
base_url = "{url}/v1"
wire_api = "responses"
requires_openai_auth = true
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0
''')
    keep = ('PATH', 'LANG', 'USER', 'LOGNAME', 'SystemRoot', 'windir', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP', 'SystemDrive', 'ProgramData', 'ProgramFiles', 'PSModulePath')
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.update(HOME=str(home), USERPROFILE=str(home), CODEX_HOME=str(home), HTTP_PROXY=url, HTTPS_PROXY=url, ALL_PROXY=url,
               NO_PROXY='127.0.0.1,localhost', NO_COLOR='1')
    sock = home / 'app-server-control' / 'app-server-control.sock'; sock.parent.mkdir()
    listen = 'unix://' if MODE == 'default' else f'unix://{sock}'
    rec['listen'] = listen
    print(f'listen argument: {listen}', flush=True)
    started = time.monotonic()
    server = subprocess.Popen([B, 'app-server', '--listen', listen], env=env, cwd=OUT, stdin=subprocess.DEVNULL,
                              stdout=open(OUT / 'server.out', 'wb'), stderr=open(OUT / 'server.err', 'wb'))
    while not sock.exists() and time.monotonic() - started < 30 and server.poll() is None:
        time.sleep(.1)
    rec['socket'] = {'exists': sock.exists(), 'seconds': round(time.monotonic() - started, 2), 'server_exit': server.poll()}
    names = ['ses_AGENT_A', 'ses_AGENT_B']; threads = []
    for i, name in enumerate(names):
        d = OUT / f'agent-{i}'; d.mkdir(); clients.append(Client(env, d))
        cwd = d / 'project'; cwd.mkdir()
        threads.append(clients[i].request('thread/start', {'cwd': str(cwd), 'model': 'gpt-5.5', 'modelProvider': 'synthetic',
                       'sandbox': 'workspace-write', 'approvalPolicy': 'never', 'ephemeral': False,
                       'config': {'shell_environment_policy': {'set': {'SE_SESSION': name}}}})['thread']['id'])
    rec['first_turns'] = [turn(c, t, f'XPROBE[plain:{i}]') for i, (c, t) in enumerate(zip(clients, threads))]
    rec['shell_turns'] = [turn(c, t, f'XPROBE[shell:{i}]') for i, (c, t) in enumerate(zip(clients, threads))]
    outputs = {}
    for s in seen:
        for o in s['outputs']:
            text = o.get('output') if isinstance(o.get('output'), str) else json.dumps(o.get('output'))
            outputs.setdefault(s['marker'], []).append(text[-200:])
    rec['shell_outputs'] = outputs
    rec['own_session_only'] = all(any(f'SEEN={names[i]}' in x for x in outputs.get(f'XPROBE[shell:{i}]', []))
                                  and not any(f'SEEN={names[1 - i]}' in x for x in outputs.get(f'XPROBE[shell:{i}]', []))
                                  for i in range(2))
    clients[0].p.kill(); clients[0].p.wait()
    rec['after_peer_exit'] = turn(clients[1], threads[1], 'XPROBE[plain:after]')
    rec['server_alive'] = server.poll() is None
    rec['complete'] = True
except BaseException:
    rec['failure'] = traceback.format_exc()
finally:
    for c in clients:
        if c.p.poll() is None:
            c.p.kill(); c.p.wait()
    if server and server.poll() is None:
        server.terminate(); server.wait(timeout=15)
    rec['server_exit_after_stop'] = server.poll() if server else None
    model.shutdown()
    try:
        err = (OUT / 'server.err').read_bytes().decode(errors='replace')
    except OSError as e:
        err = f'<unreadable: {e}>'
    print('server stderr begin', flush=True); print(err[-4000:], flush=True); print('server stderr end', flush=True)
    (OUT / 'result.json').write_text(json.dumps(rec, indent=2) + '\n')
    print(json.dumps(rec)[:3000])
    sys.exit(0 if rec['complete'] and rec.get('own_session_only') and rec.get('server_alive') else 1)
