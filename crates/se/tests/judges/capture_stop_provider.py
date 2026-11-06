"""Protects: a real retained provider stream exposes capture and mail ordering."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request


def main():
    image, home, *args = sys.argv[1:]
    flag = '--resume' if '--resume' in args else '--session-id'
    conversation = args[args.index(flag) + 1]
    repo = Path.cwd()
    slug = ''.join(c if c.isalnum() else '-' for c in str(repo))
    transcript = Path(os.environ['HOME']) / '.claude/projects' / slug / (conversation + '.jsonl')
    assert sys.stdin.readline(), 'native task missing'
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(json.dumps({'type': 'user', 'sessionId': conversation,
        'uuid': 'initial-task', 'message': {'role': 'user', 'content': 'Retain the task'}}) + '\n')
    print(json.dumps({'type': 'system', 'subtype': 'init', 'session_id': conversation}), flush=True)
    frame = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}) + '\n'
    discovery = subprocess.run([image, '--home', home, 'mcp'], input=frame.encode(),
                               capture_output=True, timeout=20)
    assert discovery.returncode == 0, 'issued IPC discovery failed'
    reply = json.loads(discovery.stdout)
    assert 'result' in reply or reply.get('error', {}).get('message', '').startswith('session-not-active:')
    configuration = json.loads(Path(args[args.index('--mcp-config') + 1]).read_text())
    server = configuration['mcpServers']['stateengine']
    request = urllib.request.Request(server['url'], data=frame.encode(),
        headers={**server['headers'], 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=20) as response:
        reply = json.load(response)
        assert response.status == 200 and ('result' in reply or
            reply.get('error', {}).get('message', '').startswith('session-not-active:'))
    (repo / 'provider-ready.json').write_text(json.dumps({
        'path': str(transcript), 'native_root_pid': os.getppid(), 'helper_pid': os.getpid()}))
    deadline = time.monotonic() + 60
    while not (repo / 'complete-task').exists():
        assert time.monotonic() < deadline, 'capture trigger never arrived'
        time.sleep(.01)
    with transcript.open('a') as stream:
        stream.write(json.dumps({'type': 'assistant', 'sessionId': conversation,
            'uuid': 'capture-before-stop', 'message': {'role': 'assistant',
            'content': (repo / 'complete-task').read_text()}}) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'type': 'result', 'session_id': conversation}), flush=True)
    for line in sys.stdin:
        with (repo / 'subsequent-input.jsonl').open('a') as stream:
            stream.write(line)


if __name__ == '__main__':
    main()
