"""Protects: final-capture consumer has a native source that survives reopen."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request


def main():
    se, home, *args = sys.argv[1:]
    flag = '--resume' if '--resume' in args else '--session-id'
    conversation = args[args.index(flag) + 1]
    repo = Path.cwd()
    # Test paths are ASCII and shorter than Claude's 200-character slug limit.
    assert str(repo).isascii() and len(str(repo)) < 200
    slug = ''.join(c if c.isalnum() else '-' for c in str(repo))
    path = Path(os.environ['HOME']) / '.claude/projects' / slug / (conversation + '.jsonl')
    assert sys.stdin.readline(), 'missing native task'
    print(json.dumps({'type': 'system', 'subtype': 'init', 'session_id': conversation}), flush=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(json.dumps({'type': 'user', 'sessionId': conversation,
            'uuid': 'soak-task', 'message': {'role': 'user', 'content': 'Retain this conversation'}}) + '\n')
    request = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}).encode()
    ipc = subprocess.run([se, '--home', home, 'mcp'], input=request + b'\n',
                         capture_output=True, timeout=20)
    def verified(reply):
        return 'result' in reply or reply.get('error', {}).get('message', '').startswith('session-not-active:')
    assert ipc.returncode == 0 and verified(json.loads(ipc.stdout)), 'issued IPC discovery refused'
    config = json.loads(Path(args[args.index('--mcp-config') + 1]).read_text())
    server = config['mcpServers']['stateengine']
    call = urllib.request.Request(server['url'], data=request,
        headers={**server['headers'], 'Content-Type': 'application/json'})
    with urllib.request.urlopen(call, timeout=20) as response:
        assert response.status == 200 and verified(json.load(response)), 'issued HTTP discovery refused'
    (repo / 'provider-ready.json').write_text(json.dumps({'conversation': conversation,
        'native_root_pid': os.getppid(), 'helper_pid': os.getpid(), 'path': str(path)}))
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
