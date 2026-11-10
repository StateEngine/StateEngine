"""A managed protocol double calls its own authenticated MCP launch capability."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
sys.dont_write_bytecode = True
from mail_provider import main


def worker():
    repo = Path.cwd()
    session = os.environ['SE_SESSION']
    records = repo / 'self-admissions'
    records.mkdir(exist_ok=True)
    ready = repo / 'provider-ready.json'
    while not ready.exists() or json.loads(ready.read_text()).get('helper_pid') != os.getpid():
        time.sleep(.02)
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(180)', 'owned-self-force-job'],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    identity = dict(session=session, pids=[os.getppid(), os.getpid(), child.pid])
    (records / (session + '.json')).write_text(json.dumps(identity))
    original = repo / 'self-original-session'
    try:
        with original.open('x') as output:
            output.write(session)
        first = True
    except FileExistsError:
        first = original.read_text() == session
    def later_inputs():
        for value in source:
            with task_log.open('a') as output:
                output.write(json.dumps(value) + '\n')
    threading.Thread(target=later_inputs, daemon=True).start()
    gate = repo / ('self-force-go' if first else 'self-replay-go')
    while not gate.exists():
        time.sleep(.02)
    arguments = sys.argv[3:]
    config = json.loads(Path(arguments[arguments.index('--mcp-config') + 1]).read_text())
    server = config['mcpServers']['stateengine']

    def rpc(name, arguments, label):
        request = dict(jsonrpc='2.0', id=label, method='tools/call',
                       params=dict(name=name, arguments=arguments))
        # Record the offered operation without recording the credential headers.
        (repo / (label + '.request.json')).write_text(json.dumps(request))
        call = urllib.request.Request(server['url'], data=json.dumps(request).encode(),
                                      headers={**server['headers'], 'Content-Type': 'application/json'})
        with urllib.request.urlopen(call, timeout=30) as response:
            result = json.load(response)
        (repo / (label + '.response.json')).write_text(json.dumps(result))
        return result

    label = 'self-original' if first else 'self-successor'
    resume = rpc('stateengine_resume', {'byte_budget': 65536}, label + '-resume')
    assert not resume.get('result', {}).get('isError'), resume
    content = resume['result']['content']
    assert len(content) == 1 and content[0]['type'] == 'text', resume
    assert json.loads(content[0]['text'])['principal']['session_id'] == session, resume
    rpc('stateengine_agent_launch', {'force': True, 'detach': True,
        'idempotency_key': 'managed-self-force', 'task': 'Owned self-force replacement input.'}, label + '-launch')


if __name__ == '__main__':
    session = os.environ['SE_SESSION']
    source = sys.stdin
    task_log = Path.cwd() / ('self-input-' + session + '.jsonl')
    class RecordedInput:
        def readline(self):
            value = source.readline()
            if value:
                with task_log.open('a') as output:
                    output.write(json.dumps(value) + '\n')
            return value
    sys.stdin = RecordedInput()
    def observed_worker():
        try:
            worker()
        except BaseException:
            (Path.cwd() / ('self-error-' + session + '.txt')).write_text(traceback.format_exc())
    threading.Thread(target=observed_worker, daemon=True).start()
    main()
