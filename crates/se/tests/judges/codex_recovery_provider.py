"""Persistent app-server protocol double; no model, account or provider network.

The first transport supports the actual readiness, policy echo and MCP discovery.
A disconnected transport leaves its native process alive, as the persistent
app-server does. A later connection resumes its saved thread and policy.
The slow control pauses both native processes before reconnect, so silence is
independent of an actual successful reconnect. Neither authorizes reaping.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import traceback
import urllib.request
import uuid


def witness(name, value):
    target = Path(name)
    staged = target.with_name(target.name + '.' + str(threading.get_ident()) + '.tmp')
    staged.write_text(json.dumps(value))
    staged.replace(target)


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise EOFError
        data.extend(part)
    return bytes(data)


def receive(stream):
    first, second = exact(stream, 2)
    opcode, size = first & 15, second & 127
    if size == 126:
        size = struct.unpack('!H', exact(stream, 2))[0]
    elif size == 127:
        size = struct.unpack('!Q', exact(stream, 8))[0]
    if not first & 128 or not second & 128 or size > 4 * 1024 * 1024:
        raise ValueError('expected one bounded, masked client frame')
    mask = exact(stream, 4)
    body = bytes(value ^ mask[index % 4] for index, value in enumerate(exact(stream, size)))
    return opcode, body


def send(stream, body, opcode=1):
    size = len(body)
    header = bytes([128 | opcode])
    if size < 126:
        header += bytes([size])
    elif size < 65536:
        header += bytes([126]) + struct.pack('!H', size)
    else:
        header += bytes([127]) + struct.pack('!Q', size)
    stream.sendall(header + body)


def discover(params):
    server = params['config']['mcp_servers.stateengine']
    request = urllib.request.Request(server['url'],
        data=json.dumps({'jsonrpc':'2.0', 'id':1, 'method':'tools/list'}).encode(),
        headers={**server['http_headers'], 'Content-Type':'application/json'})
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.load(response)
        if response.status != 200 or not ('result' in result or
                result.get('error', {}).get('message', '').startswith('session-not-active:')):
            raise ValueError('actual prepared MCP discovery was not verified')


def connection(stream, number, thread, rollout, saved):
    try:
        request = bytearray()
        while not request.endswith(b'\r\n\r\n'):
            request.extend(exact(stream, 1))
            if len(request) > 16384:
                raise ValueError('upgrade header exceeded bound')
        headers = dict(line.split(':', 1) for line in request.decode().split('\r\n')[1:] if ':' in line)
        key = next(value.strip() for name, value in headers.items() if name.lower() == 'sec-websocket-key')
        digest = hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()
        stream.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                       + b'Sec-WebSocket-Accept: ' + base64.b64encode(digest) + b'\r\n\r\n')
        while True:
            opcode, body = receive(stream)
            if opcode == 8:
                return
            if opcode == 9:
                send(stream, body, 10)
                continue
            if opcode != 1:
                raise ValueError('unexpected provider frame')
            value = json.loads(body)
            if 'id' not in value:
                continue
            method, params = value['method'], value.get('params', {})
            if method == 'initialize':
                result = {'userAgent':'independent-recovery-double'}
            elif method == 'thread/resume' and 'config' not in params:
                with saved['lock']:
                    original = saved.get('policy')
                    if original is None or params['threadId'] != original['thread']['id']:
                        raise ValueError('reconnect did not select the original conversation')
                    result = original | {'thread': original['thread'] |
                                         {'turns': [], 'status': {'type': 'idle'}}}
                witness('provider-reconnect.json', {
                    'connection': number, 'helper_pid': os.getpid(), 'native_pid': os.getppid(),
                    'thread_id': result['thread']['id'],
                    'policy': {k: result[k] for k in ('approvalPolicy', 'sandbox', 'cwd')}})
            elif method in ('thread/start', 'thread/resume'):
                discover(params)
                if method == 'thread/resume':
                    thread = params['threadId']
                    rollout = Path(os.environ['CODEX_HOME']) / 'sessions' / ('rollout-' + thread + '.jsonl')
                    if not rollout.is_file():
                        raise ValueError('resume did not select the existing native conversation')
                rollout.parent.mkdir(parents=True, exist_ok=True)
                if method == 'thread/start':
                    rollout.write_text(json.dumps({'type':'session_meta',
                        'payload':{'id':thread, 'cwd':params['cwd']}}) + '\n')
                config = params['config']
                mode = params['sandbox']
                if mode == 'workspace-write':
                    policy = config['sandbox_workspace_write']
                    sandbox = {'type':'workspaceWrite', 'networkAccess':policy['network_access'],
                        'writableRoots':[p for p in policy['writable_roots'] if p != params['cwd']],
                        'excludeTmpdirEnvVar':True, 'excludeSlashTmp':True}
                elif mode == 'read-only':
                    sandbox = {'type':'readOnly', 'networkAccess':config['sandbox_read_only']['network_access']}
                else:
                    sandbox = {'type':'dangerFullAccess'}
                result = {'thread':{'id':thread, 'path':str(rollout)},
                          'approvalPolicy':params['approvalPolicy'], 'sandbox':sandbox, 'cwd':params['cwd']}
                with saved['lock']:
                    saved['policy'] = result
                witness('provider-ready.json', {'helper_pid':os.getpid(),
                    'native_pid':os.getppid(), 'discovery':True, 'thread_id': thread,
                    'policy': {k: result[k] for k in ('approvalPolicy', 'sandbox', 'cwd')}})
            elif method == 'thread/read':
                result = {'thread':{'id':thread, 'path':str(rollout), 'turns':[], 'status':{'type':'idle'}}}
            elif method == 'turn/start':
                result = {'turn':{'id':'fixture-turn', 'status':'inProgress'}}
            else:
                send(stream, json.dumps({'id':value['id'], 'error':{'code':-32601,
                     'message':'method is outside this process-recovery control'}}).encode())
                continue
            send(stream, json.dumps({'id':value['id'], 'result':result}).encode())
    except (EOFError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception:
        Path('provider-error.txt').write_text(traceback.format_exc())
    finally:
        stream.close()


def main():
    listen = sys.argv[sys.argv.index('--listen') + 1]
    if not listen.startswith('unix://'):
        raise ValueError('native fixture requires the production Unix transport')
    path = Path(listen.removeprefix('unix://'))
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    path.chmod(0o600)
    server.listen()
    thread = str(uuid.uuid4())
    rollout = Path(os.environ['CODEX_HOME']) / 'sessions' / ('rollout-' + thread + '.jsonl')
    number = 0
    saved = {'lock': threading.Lock()}
    while True:
        stream, _ = server.accept()
        number += 1
        threading.Thread(target=connection, args=(stream, number, thread, rollout, saved), daemon=True).start()


if __name__ == '__main__':
    main()
