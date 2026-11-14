"""Owned startup double: incomplete readiness never becomes an active session."""
import json
import os
from pathlib import Path
import sys
import subprocess
import threading
import time
import urllib.request

from judge_records import write_json
from mail_provider import main as ready_provider

repo = Path.cwd()
write_json(repo / 'startup-pids.json', [os.getppid(), os.getpid()])
# An unready provider must not inherit owner authority through publication.
probe_env = dict(os.environ)
probe_env.pop('SE_SESSION', None)
time.sleep(.3)
probe = subprocess.run([sys.argv[1], '--home', sys.argv[2], '--json', 'status'],
                       env=probe_env, capture_output=True, timeout=10)
write_json(repo / 'startup-owner-probe.json', {
    'exit': probe.returncode, 'stdout': probe.stdout.decode(), 'stderr': probe.stderr.decode()})
assert probe.returncode != 0, 'unready provider acquired owner CLI authority'
mode = (repo / 'startup-mode').read_text()
with (repo / 'startup-count').open('a') as output:
    output.write('started\n')
if mode == 'idle':
    def input_closed():
        sys.stdin.buffer.read()
        (repo / 'startup-saw-eof').write_text('stdin closed')
        os._exit(0)
    threading.Thread(target=input_closed, daemon=True).start()
if mode == 'ready':
    ready_provider()
elif mode == 'http-only':
    _, _, *arguments = sys.argv[1:]
    conversation = arguments[arguments.index('--session-id') + 1]
    slug = ''.join(c if c.isascii() and c.isalnum() else '-' for c in str(repo))
    transcript = Path(os.environ['HOME']) / '.claude/projects' / slug / (conversation + '.jsonl')
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(json.dumps({'type': 'user', 'sessionId': conversation,
                                    'uuid': 'startup-task', 'message': {'role': 'user', 'content': 'Startup'}}) + '\n')
    assert sys.stdin.readline()
    print(json.dumps({'type': 'system', 'subtype': 'init', 'session_id': conversation}), flush=True)
    config = json.loads(Path(arguments[arguments.index('--mcp-config') + 1]).read_text())
    server = config['mcpServers']['stateengine']
    request = urllib.request.Request(server['url'], data=json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}).encode(),
        headers={**server['headers'], 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=15) as response:
        assert response.status == 200
        write_json(repo / 'startup-http-reply.json', json.load(response))
while True:
    time.sleep(1)
