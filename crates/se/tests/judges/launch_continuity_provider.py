"""Synthetic native Claude protocol: append on resume; expose no credentials."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import uuid

MARKERS = (
    'CLAUDECODE', 'CLAUDE_CODE_ENTRYPOINT', 'CLAUDE_CODE_SESSION_ID',
    'CODEX_THREAD_ID', 'CODEX_CI', 'SECODE_SESSION_ID',
    'STATEENGINE_AGENT_ID', 'STATEENGINE_PROJECT_ID', 'STATEENGINE_SESSION_ID',
    'SE_SESSION', 'SE_AGENT_ID', 'SE_PROJECT_ID',
)


def main():
    se, home, *arguments = sys.argv[1:]
    if '--safe-mode' in arguments:
        request = json.loads(sys.stdin.readline())
        print(json.dumps({'type': 'control_response', 'response': {
            'request_id': request['request_id'], 'subtype': 'success',
            'response': {'effective': {}, 'sources': [], 'errors': []}}}), flush=True)
        return
    cwd = Path.cwd()
    flag = '--resume' if '--resume' in arguments else '--session-id'
    conversation = arguments[arguments.index(flag) + 1]
    # Match the existing fixture's provider transcript convention, including
    # the bounded long-path suffix. This is not the host's capture encoder.
    encoded = str(cwd).encode('utf-16-le')
    units = [int.from_bytes(encoded[i:i + 2], 'little') for i in range(0, len(encoded), 2)]
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
    initial = sys.stdin.readline()
    assert initial, 'host did not send the initial task'
    print(json.dumps({'type': 'system', 'subtype': 'init', 'session_id': conversation}), flush=True)
    time.sleep(.25)
    transcript.parent.mkdir(parents=True, exist_ok=True)
    with transcript.open('a' if flag == '--resume' else 'x') as stream:
        stream.write(json.dumps({'type': 'user', 'sessionId': conversation,
            'uuid': str(uuid.uuid4()), 'message': {'role': 'user',
            'content': 'Independent launch continuity turn.'}}) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    request = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}).encode()
    ipc = subprocess.run([se, '--home', home, 'mcp'], input=request + b'\n',
                         capture_output=True, timeout=15)
    assert ipc.returncode == 0, 'prepared session discovery failed'
    reply = json.loads(ipc.stdout)
    assert 'result' in reply or reply.get('error', {}).get('message', '').startswith('session-not-active:')
    config = json.loads(Path(arguments[arguments.index('--mcp-config') + 1]).read_text())
    server = config['mcpServers']['stateengine']
    call = urllib.request.Request(server['url'], data=request,
                                  headers={**server['headers'], 'Content-Type': 'application/json'})
    with urllib.request.urlopen(call, timeout=15) as response:
        reply = json.load(response)
        assert response.status == 200
        assert 'result' in reply or reply.get('error', {}).get('message', '').startswith('session-not-active:')
    # Only known synthetic markers are read back. Never dump the whole environment.
    row = {'conversation': conversation, 'flag': flag,
           'environment': {key: os.environ[key] for key in MARKERS if key in os.environ},
           'native_root_pid': os.getppid(), 'helper_pid': os.getpid()}
    with (cwd / 'launch-observed.jsonl').open('a') as stream:
        stream.write(json.dumps(row) + '\n')
        stream.flush()
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
