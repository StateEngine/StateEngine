"""Linux native Codex reopen/rotation consumer; owned loopback model, no account.
Run with --se ABSOLUTE_SE --codex ABSOLUTE_CODEX --output NEW_DIRECTORY.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid

sys.dont_write_bytecode = True
from codex_first_launch import Model as BaseModel
from judges.mail_cli import Fixture


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def wait(predicate):
    until = time.monotonic() + 90
    while not predicate():
        assert time.monotonic() < until, 'bounded native readback did not complete'
        time.sleep(.05)


class Model(BaseModel):
    def reset(self, phase, held=False):
        self.phase, self.step, self.finished, self.held = phase, 0, False, held
        self.waiting, self.release = threading.Event(), threading.Event()

    def respond(self, handler, request):
        self.requests.append(request)
        write(self.root / 'model-requests.json', self.requests)
        if self.held and self.step == 0:
            self.waiting.set()
            assert self.release.wait(60), 'native request was never released'
        if self.step == 0:
            script = "from pathlib import Path;p=Path(" + repr(self.phase + '.txt') + ");p.write_text(" + repr(self.phase) + ");print('REPAIR_READBACK:' + p.read_text())"
            args = {'cmd': shlex.join([sys.executable, '-c', script]), 'workdir': str(self.repo),
                    'yield_time_ms': 30000, 'max_output_tokens': 1000}
            if any(tool.get('name') == 'exec_command' for tool in request.get('tools', [])):
                item = {'type': 'function_call', 'id': 'fc_' + uuid.uuid4().hex,
                        'call_id': 'call_' + uuid.uuid4().hex, 'name': 'exec_command',
                        'arguments': json.dumps(args), 'status': 'completed'}
            else:
                item = {'type': 'custom_tool_call', 'id': 'ctc_' + uuid.uuid4().hex,
                        'call_id': 'call_' + uuid.uuid4().hex, 'namespace': 'functions', 'name': 'exec',
                        'input': 'text(await tools.exec_command(' + json.dumps(args) + '));', 'status': 'completed'}
        else:
            outputs = [item.get('output') for item in request.get('input', [])
                       if item.get('type', '').endswith('call_output')]
            assert 'REPAIR_READBACK:' + self.phase in json.dumps(outputs), 'actual command readback missing'
            item = {'type': 'message', 'id': 'msg_' + uuid.uuid4().hex, 'role': 'assistant',
                    'phase': 'final_answer', 'status': 'completed', 'content': [{'type': 'output_text',
                    'text': 'REPAIR_FINISHED:' + self.phase, 'annotations': [], 'logprobs': []}]}
            self.finished = True
        self.step += 1
        response = {'id': 'resp_' + uuid.uuid4().hex, 'object': 'response', 'created_at': int(time.time()),
                    'model': request.get('model', 'offline'), 'status': 'in_progress', 'output': []}
        events = [{'type': 'response.created', 'response': response},
                  {'type': 'response.output_item.added', 'output_index': 0, 'item': item | {'status': 'in_progress'}},
                  {'type': 'response.output_item.done', 'output_index': 0, 'item': item},
                  {'type': 'response.completed', 'response': response | {'status': 'completed', 'output': [item],
                   'usage': {'input_tokens': 64, 'output_tokens': 20, 'total_tokens': 84,
                             'output_tokens_details': {'reasoning_tokens': 0}}}}]
        body = ''.join('event: ' + event['type'] + '\ndata: ' + json.dumps(event | {'sequence_number': n}) + '\n\n'
                       for n, event in enumerate(events)).encode()
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/event-stream')
        handler.send_header('Content-Length', str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)


def native_reply(path, phase):
    raw = path.read_bytes()
    for line in raw[:raw.rfind(b'\n') + 1].splitlines():
        record = json.loads(line)
        payload = record.get('payload', {})
        if record.get('type') == 'event_msg' and payload.get('type') == 'item_completed':
            item = payload.get('item', {})
            if item.get('type') == 'AgentMessage' and any(
                    part.get('text') == 'REPAIR_FINISHED:' + phase for part in item.get('content', [])):
                return True
    return False


def history(f):
    value = f.ok('--project', f.project, 'history', '--agent', f.agent)
    assert value['window']['complete'], value['window']
    return value['items']


def launch(f, model, phase, conversation=None, held=False):
    model.reset(phase, held)
    key = str(uuid.uuid4())
    args = ['--project', f.project, '--key', key, 'launch', f.agent, '--detach', '--task', 'Perform phase ' + phase]
    for _ in range(5):
        result = f.call(*args)
        value = json.loads(result.stdout)
        if result.returncode == 0:
            break
        assert value['code'] == 'commit-outcome-unknown' and value['detail']['key'] == key, value
    else:
        raise AssertionError('same-key launch remained indeterminate')
    if conversation:
        assert value['conversation_id'] == conversation, value
    f.session = value['session_id']
    pid = value['process']['pid']
    birth = Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()[19]
    f.processes.append((pid, birth))
    return value['conversation_id']


def completed(f, model, phase):
    wait(lambda: model.finished)
    assert (f.repo / (phase + '.txt')).read_text() == phase
    wait(lambda: any('REPAIR_FINISHED:' + phase in json.dumps(item['payload']) for item in history(f)))


def refused_stop(f):
    result = f.call('--project', f.project, 'stop', f.agent)
    value = json.loads(result.stdout)
    assert result.returncode != 0 and not value['complete'] and not value['capture']['flushed'], value
    assert value['resume']['state'] != 'new-required', value
    return value


def run_case(options, cold):
    name = 'cold' if cold else 'warm'
    f = Fixture(options.se, options.output / name, log_directory='calls')
    model = Model(f.root, f.repo)
    short = Path(tempfile.mkdtemp(prefix='se-capture-repair-'))
    print("fixture root (retained on failed or interrupted closure):", short, flush=True)
    try:
        code = f.root / 'codex-home'
        code.mkdir(mode=0o700)
        f.env.update(CODEX_HOME=str(code), OPENAI_API_KEY='sk-owned-loopback-no-account',
                     XDG_RUNTIME_DIR=str(short), PYTHONDONTWRITEBYTECODE='1')
        (code / 'config.toml').write_text('model_provider="owned-loopback"\n[model_providers.owned-loopback]\nname="Owned capture repair"\nbase_url=' +
            json.dumps(f'http://127.0.0.1:{model.server.server_port}/v1') + '\nwire_api="responses"\nrequires_openai_auth=false\n')
        subprocess.run([str(options.codex), 'login', '--with-api-key'], input=f.env['OPENAI_API_KEY'],
                       env=f.env, text=True, capture_output=True, check=True, timeout=20)
        config = f.home / 'config.toml'
        config.write_text(config.read_text().replace('[providers.codex]', '[providers.codex]\ncommand = ' + json.dumps(str(options.codex)), 1))
        f.agent = f.ok('--project', f.project, 'agent', 'add', 'Capture repair', '--provider', 'codex', '--model', 'gpt-6.1-sol')['agent']['id']
        conversation = launch(f, model, 'first')
        completed(f, model, 'first')
        f.ok('--project', f.project, 'stop', f.agent)
        launch(f, model, 'second', conversation)
        completed(f, model, 'second')
        f.ok('--project', f.project, 'stop', f.agent)
        files = list(code.glob('sessions/**/*.jsonl'))
        assert len(files) == 1, files
        path = files[0]
        prefix, inode = path.read_bytes(), path.stat().st_ino
        launch(f, model, 'rotated', conversation, held=True)
        assert model.waiting.wait(30), 'real provider did not reach the held request'
        backup = path.with_suffix('.jsonl.rotated')
        path.rename(backup)
        model.release.set()
        wait(lambda: native_reply(backup, 'rotated'))
        assert (f.repo / 'rotated.txt').read_text() == 'rotated'
        assert backup.stat().st_ino == inode and backup.read_bytes().startswith(prefix)
        write(f.root / 'missing-stop.json', refused_stop(f))
        if cold:
            f.ok('down')
            f.ok('up')
            write(f.root / 'cold-missing-stop.json', refused_stop(f))
        path.write_bytes(backup.read_bytes())
        assert path.stat().st_ino != inode
        write(f.root / 'replacement-stop.json', refused_stop(f))
        assert not any('REPAIR_FINISHED:rotated' in json.dumps(item['payload']) for item in history(f))
        path.unlink()
        backup.rename(path)
        repaired = f.ok('--project', f.project, 'stop', f.agent)
        assert repaired['complete'] and repaired['capture']['flushed'] and repaired['resume']['state'] == 'ready', repaired
        assert '--new' not in repaired['resume']['argv']
        write(f.root / 'repaired-stop.json', repaired)
        with sqlite3.connect('file:' + str(f.home / 'state.db') + '?mode=ro', uri=True) as db:
            credentials = db.execute('SELECT purpose,state FROM credentials').fetchall()
        assert credentials and all(state == 'revoked' for _, state in credentials), credentials
        launch(f, model, 'after_repair', conversation)
        completed(f, model, 'after_repair')
        f.ok('--project', f.project, 'stop', f.agent)
        before = history(f)
        tools = [item['payload']['metadata']['captured_tool'] for item in before
                 if item['payload'].get('metadata', {}).get('captured_tool')]
        identities = [json.dumps(tool['native'], sort_keys=True) for tool in tools]
        assert len(identities) == 4 and len(set(identities)) == 4, tools
        for phase in ['first', 'second', 'rotated', 'after_repair']:
            assert sum('REPAIR_FINISHED:' + phase in json.dumps(item['payload']) for item in before) == 1, phase
        f.ok('down')
        f.ok('up')
        after = history(f)
        stable = lambda rows: [(row['event_id'], row['recorded_at'], row['payload']) for row in rows]
        assert stable(after) == stable(before), 'reopen changed execution or reply provenance'
        write(f.root / 'public-history.json', after)
        write(f.root / 'result.json', {'complete': True, 'unique_native_executions': 4, 'replies_once': 4,
              'same_conversation_resumed_after_repair': True, 'credentials_stayed_revoked': True})
    finally:
        if hasattr(model, 'release'):
            model.release.set()
        try:
            f.close()
        finally:
            model.close()
            child = short / 'stateengine'
            if child.exists():
                child.rmdir()
            short.rmdir()
    print('PASS', name, ': original-file repair, four executions/replies once, normal resume, revoked credentials and cold readback', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', required=True, type=Path)
    parser.add_argument('--codex', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    options = parser.parse_args()
    if not sys.platform.startswith('linux'):
        parser.error('this native consumer currently qualifies Linux')
    os.umask(0o077)
    options.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    for cold in [False, True]:
        run_case(options, cold)


if __name__ == '__main__':
    main()
