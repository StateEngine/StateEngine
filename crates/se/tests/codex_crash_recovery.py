"""Public Linux crash consumer: stock Codex, owned loopback model, no account.
Run with --se ABSOLUTE_SE --codex ABSOLUTE_CODEX --output NEW_DIRECTORY.
Only the engine PID read back from this fixture is killed; its provider survives.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import uuid

from codex_first_launch import Model as BaseModel
from judges.mail_cli import Fixture as BaseFixture


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def birth(pid):
    path = Path('/proc') / str(pid)
    try:
        fields = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
        return {'pid': pid, 'birth': fields[19], 'parent': int(fields[1]),
                'state': fields[0], 'command': (path / 'cmdline').read_bytes().replace(b'\0', b' ').decode(),
                'exe': str((path / 'exe').resolve())}
    except (FileNotFoundError, ProcessLookupError):
        return None


class Fixture(BaseFixture):
    def call(self, *args, recipient=False):
        self.calls += 1
        env = self.env | ({'SE_SESSION': self.session} if recipient else {})
        argv = [str(self.se), '--json', '--home', str(self.home), *map(str, args)]
        unit = 'se5b-crash-call-' + uuid.uuid4().hex[:12]
        result = subprocess.run(['systemd-run', '--user', '--quiet', '--wait', '--collect', '--pipe',
                                 '--unit', unit, '--property=Type=exec', '--working-directory', str(self.repo),
                                 '--', '/usr/bin/env', '-i', *[k+'='+v for k, v in env.items()],
                                 '/usr/bin/script', '-q', '-e', '-c', shlex.join(argv), '/dev/null'],
                                input=b'', capture_output=True, timeout=100)
        base = self.log_root / f'call-{self.calls:03}'
        base.with_suffix('.stdout').write_bytes(result.stdout)
        base.with_suffix('.stderr').write_bytes(result.stderr)
        write(base.with_suffix('.json'), {'argv': argv, 'exit': result.returncode})
        return result

    def up(self, previous=0):
        unit = 'se5b-crash-up-' + uuid.uuid4().hex[:12]
        command = shlex.join([str(self.se), '--home', str(self.home), '--json', 'up']) + ' && sleep 3600'
        subprocess.run(['systemd-run', '--user', '--quiet', '--collect', '--unit', unit,
                        '--property=Type=exec', '--working-directory', str(self.repo), '--',
                        '/usr/bin/env', '-i', *[k+'='+v for k, v in self.env.items()],
                        '/usr/bin/script', '-q', '-e', '-c', command, str(self.root/(unit+'.log'))],
                       check=True, capture_output=True)
        self.units.append(unit)
        write(self.root/'units.json', self.units)
        until = time.monotonic() + 45
        # A status probe can contend with old-release startup's direct lease.
        while time.monotonic() < until:
            path = self.home/'endpoint.json'
            if path.exists():
                endpoint = json.loads(path.read_text())
                if endpoint['generation'] > previous:
                    status = self.ok('--project', self.project, 'status')
                    if status['runtime']['state'] == 'running':
                        return status
            time.sleep(.1)
        raise AssertionError('fresh engine generation did not publish readiness')

    def pins(self, status):
        records = [status['runtime'].get('process')]
        records += [a['session'].get('process') for a in status['agents']['items']]
        roots = set()
        for record in filter(None, records):
            observed = birth(record['pid'])
            assert observed and observed['exe'] == record['exe'], (record, observed)
            roots.add(record['pid'])
        census = {}
        for path in Path('/proc').iterdir():
            if path.name.isdigit():
                row = birth(int(path.name))
                if row:
                    census[row['pid']] = row
        while True:
            children = {pid for pid, row in census.items() if row['parent'] in roots}
            if children <= roots:
                break
            roots |= children
        for pid in roots:
            row = census[pid]
            self.processes.append((pid, row['birth']))
            self.births[(pid, row['birth'])] = row
        write(self.root/'births.json', list(self.births.values()))

    def close(self):
        result = self.ok('down')
        assert result['complete'] and result['witness']['state'] == 'witnessed', result
        until = time.monotonic()+10
        while True:
            live = []
            for pid, started in self.processes:
                row = birth(pid)
                if row and row['birth'] == started and row['state'] != 'Z':
                    live.append(row)
            if not live or time.monotonic() >= until:
                break
            time.sleep(.1)
        assert not live, [(row['pid'], row['exe']) for row in live]
        assert not (self.home/'endpoint.json').exists()
        with (self.home/'runtime.lock').open('r+b') as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lease, fcntl.LOCK_UN)
        write(self.root/'outside-final.json', {'recorded_births_closed': len(self.births), 'endpoint_absent': True, 'lease_free': True})


class Model(BaseModel):
    def respond(self, handler, request):
        self.requests.append(request)
        write(self.root/'model-requests.json', self.requests)
        rid = 'resp_' + uuid.uuid4().hex
        outputs = [item.get('output', '') for item in request.get('input', [])
                   if isinstance(item, dict) and item.get('type', '').endswith('call_output')]
        self.readback = self.readback or any('CRASH-WORK-READBACK' in json.dumps(output) for output in outputs)
        pending = re.search(r'Script running with cell ID (\S+)', str(outputs[-1])) if outputs else None
        if not self.sent:
            self.sent = True
            script = "from pathlib import Path;import time;Path('crash-start').write_text('started');time.sleep(20);Path('crash-finish').write_text('finished');print('CRASH-WORK-READBACK')"
            code = 'text(await tools.exec_command(' + json.dumps({'cmd': shlex.join([sys.executable, '-c', script]), 'workdir': str(self.repo), 'yield_time_ms': 30000, 'max_output_tokens': 1000}) + '));'
            item = {'id': 'ctc_'+uuid.uuid4().hex, 'type': 'custom_tool_call', 'call_id': 'call_'+uuid.uuid4().hex,
                    'namespace': 'functions', 'name': 'exec', 'input': code, 'status': 'completed'}
        elif pending and not self.readback:
            item = {'id': 'fc_'+uuid.uuid4().hex, 'type': 'function_call', 'call_id': 'call_'+uuid.uuid4().hex,
                    'namespace': 'functions', 'name': 'wait', 'arguments': json.dumps({'cell_id': pending[1], 'yield_time_ms': 1000, 'max_tokens': 1000}), 'status': 'completed'}
        else:
            item = {'id': 'msg_'+uuid.uuid4().hex, 'type': 'message', 'role': 'assistant', 'status': 'completed',
                    'phase': 'final_answer', 'content': [{'type': 'output_text', 'text': 'CRASH-TURN-DONE', 'annotations': [], 'logprobs': []}]}
        response = {'id': rid, 'object': 'response', 'created_at': int(time.time()), 'model': request.get('model', 'offline'), 'status': 'in_progress', 'output': []}
        events = [{'type': 'response.created', 'response': response},
                  {'type': 'response.output_item.added', 'output_index': 0, 'item': item | {'status': 'in_progress'}},
                  {'type': 'response.output_item.done', 'output_index': 0, 'item': item},
                  {'type': 'response.completed', 'response': response | {'status': 'completed', 'output': [item], 'usage': {'input_tokens': 64, 'output_tokens': 20, 'total_tokens': 84, 'output_tokens_details': {'reasoning_tokens': 0}}}}]
        body = ''.join('event: '+e['type']+'\ndata: '+json.dumps(e | {'sequence_number': i})+'\n\n' for i, e in enumerate(events)).encode()
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/event-stream')
        handler.send_header('Content-Length', str(len(body)))
        handler.end_headers()
        try:
            handler.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def prefix(f):
    with sqlite3.connect('file:'+str(f.home/'state.db')+'?mode=ro', uri=True) as db:
        rows = db.execute('select * from events order by rowid').fetchall()
        return [tuple(v.hex() if isinstance(v, bytes) else v for v in row) for row in rows]


def turns(history):
    return [item['payload'] for item in history['items'] if item['kind'] == 'session.turn']


def run(options):
    os.umask(0o077)
    f = Fixture(options.se, options.output)
    f.units, f.births = [], {}
    model = Model(f.root, f.repo)
    checks = []
    def check(text):
        checks.append(text)
        write(f.root/'result.json', {'passed': len(checks), 'checks': checks, 'complete': False})
        print('ok', len(checks), '-', text, flush=True)
    try:
        f.env['CODEX_HOME'] = str(f.root/'owner/.codex')
        f.env['OPENAI_API_KEY'] = 'sk-owned-loopback-no-account'
        code = Path(f.env['CODEX_HOME'])
        code.mkdir()
        (code/'config.toml').write_text('model_provider="owned-loopback"\n[model_providers.owned-loopback]\nname="Owned crash model"\nbase_url='+json.dumps('http://127.0.0.1:'+str(model.server.server_port)+'/v1')+'\nwire_api="responses"\nrequires_openai_auth=false\n')
        subprocess.run([str(options.codex), 'login', '--with-api-key'], input=f.env['OPENAI_API_KEY'].encode(), env=f.env, capture_output=True, check=True)
        config = f.home/'config.toml'
        config.write_text(config.read_text().replace('[providers.codex]', '[providers.codex]\ncommand = '+json.dumps(str(options.codex)), 1))
        f.agent = f.ok('--project', f.project, 'agent', 'add', 'Crash worker', '--provider', 'codex', '--model', 'gpt-6.1-sol')['agent']['id']
        status = f.up()
        first_generation = status['runtime']['generation']
        launched = f.ok('--project', f.project, '--key', 'crash-owned-launch', 'launch', f.agent, '--detach', '--task', 'Perform the owned crash-recovery work and reply CRASH-TURN-DONE.')
        f.session = launched['session_id']
        until = time.monotonic()+45
        while not (f.repo/'crash-start').exists() and time.monotonic() < until:
            time.sleep(.1)
        assert (f.repo/'crash-start').exists() and not (f.repo/'crash-finish').exists()
        queued = f.ok('--project', f.project, '--key', 'crash-before-mail', 'msg', 'send', f.agent, 'CRASH-QUEUED-BEFORE-ENGINE-EXIT')
        status = f.ok('--project', f.project, 'status')
        f.pins(status)
        assert not (f.repo/'crash-finish').exists(), 'owned work completed before the crash point'
        saved = prefix(f)
        write(f.root/'before-prefix.json', saved)
        engine = birth(status['runtime']['process']['pid'])
        assert engine and '--stateengine-private-runtime-bootstrap' in engine['command'] and engine['exe'] == str(f.se)
        # Re-read the exact birth immediately before signalling this owned engine.
        observed = birth(engine['pid'])
        assert observed and all(observed[key] == engine[key] for key in ['pid', 'birth', 'exe', 'command'])
        os.kill(engine['pid'], signal.SIGKILL)
        write(f.root/'kill.json', engine)
        check('exact owned engine killed mid real Codex work; provider was not signalled')
        journal = next((f.home/'launch').glob('*/codex-endpoint.json'))
        original_journal = journal.read_bytes()
        held = journal.with_name('codex-endpoint.held-by-consumer')
        if options.unproved_rendezvous:
            journal.rename(held)
        if options.restart_after_completion:
            until = time.monotonic()+30
            while not (f.repo/'crash-finish').exists() and time.monotonic() < until:
                time.sleep(.1)
            assert (f.repo/'crash-finish').exists()
            time.sleep(1)
        status = f.up(first_generation)
        f.pins(status)
        assert prefix(f)[:len(saved)] == saved
        check('se up starts a successor generation and preserves the committed event prefix')
        sent = f.ok('--project', f.project, '--key', 'crash-after-mail', 'msg', 'send', f.agent, 'CRASH-PENDING-MAIL')
        if options.unproved_rendezvous:
            until = time.monotonic()+25
            while time.monotonic() < until:
                status = f.ok('--project', f.project, 'status')
                worker = next(a for a in status['agents']['items'] if a['id'] == f.agent)
                if worker['session']['state'] == 'recovery-pending':
                    break
                time.sleep(.1)
            write(f.root/'unproved-status.json', status)
            assert worker['session']['state'] == 'recovery-pending', worker
            assert worker['session']['process']['pid'] == launched['process']['pid']
            assert worker['name'] in worker['resume']['reason'] and 'stop '+f.agent in worker['resume']['reason']
            assert 'endpoint identity journal is absent' in worker['resume']['reason']
            assert not journal.exists() and held.read_bytes() == original_journal
            assert birth(launched['process']['pid'])['state'] != 'Z'
            check('missing original endpoint journal names the affected agent and legal stop without inferring custody or signalling the provider')
            held.rename(journal)
            return
        until = time.monotonic()+(20 if options.expect_red else 55)
        while time.monotonic() < until:
            history = f.ok('--project', f.project, 'history', '--limit', '100')
            logical = turns(history)
            bodies = [row['body']['text'] for row in logical]
            if 'CRASH-TURN-DONE' in bodies and all(any(mid in body for body in bodies) for mid in [queued['message_id'], sent['message_id']]):
                break
            time.sleep(.25)
        write(f.root/'after-history.json', history)
        if options.expect_red:
            assert 'CRASH-TURN-DONE' not in bodies and not any(sent['message_id'] in body for body in bodies), bodies
            check('baseline reproduces stale capture and pending mail after a surviving-provider restart')
            return
        assert 'CRASH-TURN-DONE' in bodies
        for mid in [queued['message_id'], sent['message_id']]:
            assert sum(mid in body for body in bodies) == 1, (mid, bodies)
        assert (f.repo/'crash-finish').read_text() == 'finished' and model.readback
        check('successor captures the original completed turn and pending-mail notice without manual stop')
        status = f.ok('--project', f.project, 'status')
        worker = next(a for a in status['agents']['items'] if a['id'] == f.agent)
        assert worker['session']['session_id'] == f.session and worker['session']['process']['pid'] == launched['process']['pid']
        assert worker['conversation']['id'] == launched['conversation_id']
        assert not [p for p in status['pending'] if f.agent in p['detail'] and 'recovery failed' in p['detail']]
        check('status keeps the same provider birth, native session and conversation')
        again = f.ok('up')
        assert again['state'] in ['running', 'already-running']
        second = f.ok('--project', f.project, 'history', '--limit', '100')
        logical2 = turns(second)
        assert [r['turn_id'] for r in logical2][:len(logical)] == [r['turn_id'] for r in logical]
        assert len({r['turn_id'] for r in logical2}) == len(logical2)
        assert prefix(f)[:len(saved)] == saved
        check('repeated up and capture retain unique logical turns and original committed bytes')
        refused = f.call('--project', f.project, '--key', 'duplicate-after-crash', 'launch', f.agent, '--detach')
        assert refused.returncode != 0 and b'existing' in refused.stdout+refused.stderr
        check('launch refuses a second provider while the original live session remains controlled')
        read = f.rpc('stateengine_resume', {})
        assert not read.get('isError'), read
        bound = f.ok('--project', f.project, 'resume', recipient=True)
        assert bound['principal']['session_id'] == f.session and not bound['principal']['preview'], bound
        check('authenticated MCP and bound CLI resume remain usable on the recovered session')
    finally:
        completed = sys.exc_info()[0] is None
        try:
            if 'held' in locals() and held.exists():
                assert held.read_bytes() == original_journal and not journal.exists()
                held.rename(journal)
            f.close()
        finally:
            for unit in f.units:
                subprocess.run(['systemctl', '--user', 'stop', unit+'.service'], check=True, capture_output=True)
            model.close()
        if completed:
            check('public down and exact recorded-birth checks close the owned runtime and provider')
            write(f.root/'result.json', {'passed': len(checks), 'checks': checks, 'complete': True})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--codex', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expect-red', action='store_true')
    parser.add_argument('--unproved-rendezvous', action='store_true')
    parser.add_argument('--restart-after-completion', action='store_true')
    run(parser.parse_args())
