"""Finite Claude protocol fixture with authenticated discovery and real native capture."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

se, home, *arguments = sys.argv[1:]
repo = Path.cwd()
flag = '--resume' if '--resume' in arguments else '--session-id'
conversation = arguments[arguments.index(flag) + 1]
request = json.loads(sys.stdin.readline())
units = [int.from_bytes(str(repo).encode('utf-16-le')[i:i+2], 'little')
         for i in range(0, len(str(repo).encode('utf-16-le')), 2)]
slug = ''.join(chr(u) if 48 <= u <= 57 or 65 <= u <= 90 or 97 <= u <= 122 else '-' for u in units)
if len(slug) > 200:
    value = 0
    for unit in units:
        value = (31 * value + unit) & 0xffffffff
    value = abs(value if value < 0x80000000 else value - 0x100000000)
    suffix = ''
    while True:
        suffix = '0123456789abcdefghijklmnopqrstuvwxyz'[value % 36] + suffix
        value //= 36
        if not value:
            break
    slug = slug[:200] + '-' + suffix
transcript = Path(os.environ['HOME']) / '.claude/projects' / slug / (conversation + '.jsonl')
transcript.parent.mkdir(parents=True, exist_ok=True)
transcript.write_text(json.dumps({'type': 'user', 'sessionId': conversation,
    'uuid': 'review-initial', 'message': request['message']}) + '\n')
print(json.dumps({'type': 'system', 'subtype': 'init', 'session_id': conversation}), flush=True)
# A direct authenticated read avoids substituting catalogue size for turn observation.
wire = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                  'params': {'name': 'stateengine_status', 'arguments': {}}}).encode()
ipc = subprocess.run([se, '--home', home, 'mcp'], input=wire+b'\n', capture_output=True, timeout=20)
def prepared_or_active(reply):
    return 'result' in reply or reply.get('error', {}).get('message', '').startswith('session-not-active:')
assert ipc.returncode == 0 and prepared_or_active(json.loads(ipc.stdout)), 'authenticated IPC read refused'
config = json.loads(Path(arguments[arguments.index('--mcp-config') + 1]).read_text())
server = config['mcpServers']['stateengine']
query = urllib.request.Request(server['url'], data=wire,
    headers={**server['headers'], 'Content-Type': 'application/json'})
with urllib.request.urlopen(query, timeout=20) as response:
    assert response.status == 200 and prepared_or_active(json.load(response))
(repo/'review-provider-ready').touch()
failed = (repo/'review-failure').exists()
end = time.monotonic()+100
while not (repo/'review-release').exists():
    assert time.monotonic()<end, 'owned review release timed out'
    time.sleep(.02)
if not failed:
    with transcript.open('a') as out:
        out.write(json.dumps({'type': 'assistant', 'sessionId': conversation,
            'uuid': 'review-answer', 'message': {'role': 'assistant',
            'content': [{'type': 'text', 'text': 'REVIEW_RECOVERED_OK'}]}})+'\n')
print(json.dumps({'type': 'result', 'subtype': 'error_during_execution' if failed else 'success',
    'session_id': conversation, 'is_error': failed,
    'errors': ['PRIVATE_FIXTURE_DETAIL: 401 authentication text is not a typed HTTP status'] if failed else [],
    'result': '' if failed else 'REVIEW_RECOVERED_OK'}), flush=True)
while True:
    time.sleep(1)
