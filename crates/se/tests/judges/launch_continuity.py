"""Independent public launch judges: nested identity isolation and visible resume age.

Run --se IMAGE --output NEW_DIRECTORY --case nested|resume. Uses a native
provider protocol double and private homes; no account, model or store edits.
The resume case must stay red until launch actually reports saved-conversation
selection and age. A future Resume command is not proof of this launch's choice.
"""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
from fixture_paths import private_runtime_directory
from agent_create_cli import owner_grant
from launch_continuity_provider import MARKERS
from mail_cli import Fixture


def run(options):
    os.umask(0o077)
    options.output.mkdir(parents=True, exist_ok=False)
    runtime = private_runtime_directory()
    fixture = None
    result = {'case': options.case, 'checks': [], 'failures': []}
    try:
        fixture = Fixture(options.se, options.output / 'fixture',
                          provider_helper=Path(__file__).with_name('launch_continuity_provider.py'))
        wrapper = fixture.root / 'provider.rs'
        wrapper.write_text(wrapper.read_text().replace('2.1.287', '2.1.318'))
        subprocess.run(['rustc', '--edition=2024', str(wrapper), '-o', str(fixture.root / 'provider')],
                       capture_output=True, check=True, timeout=60)
        fixture.env = {'PATH': os.environ['PATH'], 'HOME': str(fixture.root / 'owner'),
                       'USERPROFILE': str(fixture.root / 'owner'), 'LANG': 'C.UTF-8',
                       'XDG_RUNTIME_DIR': str(runtime)}
        for key in ['XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME']:
            path = fixture.root / key.lower()
            path.mkdir()
            fixture.env[key] = str(path)
        fixture.ok('up')

        def observe(receipt):
            deadline = time.monotonic() + 20
            row = None
            while row is None:
                try:
                    text = (fixture.repo / 'launch-observed.jsonl').read_text()
                except FileNotFoundError:
                    text = ''
                # Discovery publication can precede the provider's response and
                # file write. Ignore only an unfinished final line, never a
                # malformed complete record or an unrelated session's identity.
                complete = text[:text.rfind('\n') + 1]
                for line in complete.splitlines():
                    observed = json.loads(line)
                    if (observed['conversation'] == receipt['conversation_id'] and
                            observed['environment'].get('SE_SESSION') == receipt['session_id']):
                        row = observed
                if row is None:
                    assert time.monotonic() < deadline, 'no complete observation for the exact launched conversation and session'
                    time.sleep(.02)
            assert row['native_root_pid'] == receipt['process']['pid'], (row, receipt)
            for pid in [row['native_root_pid'], row['helper_pid']]:
                fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
                fixture.processes.append((pid, fields[19]))
            return row

        def launch(agent, fresh=False, plain=False, door="cli"):
            key = str(uuid.uuid4())
            args = ['--key', key, '--project', fixture.project, 'launch', agent,
                    '--detach', '--task', 'Independent continuity check.']
            if fresh:
                args.append('--new')
            if door == 'mcp':
                response = fixture.rpc('stateengine_agent_launch', {
                    'target_agent_id': agent, 'task': 'Independent continuity check.',
                    'detach': True, 'new': fresh, 'idempotency_key': key})
                assert not response.get('isError', False), response
                receipt, reply = response['structuredContent'], None
            elif plain:
                reply = subprocess.run([str(fixture.se), '--home', str(fixture.home), *args],
                    env=fixture.env, capture_output=True, text=True, timeout=90)
                (options.output / ('new.txt' if fresh else 'resume.txt')).write_text(reply.stdout + reply.stderr)
                assert reply.returncode == 0, reply.stderr
                # Exact request replay obtains the same real launch's machine receipt.
                receipt = fixture.ok(*args)
            else:
                receipt, reply = fixture.ok(*args), None
            assert receipt['state'] == 'running', receipt
            return receipt, observe(receipt), reply.stdout if reply else None

        # Use the existing isolated owner-terminal fixture for grant setup.
        owner_grant(fixture, True)
        first, _, _ = launch(fixture.agent)
        fixture.session = first['session_id']
        if options.case == 'nested':
            parent = {key: 'synthetic-parent-' + key.lower() for key in MARKERS}
            parent['SE_SESSION'] = first['session_id']
            fixture.env.update(parent)
            try:
                for door in ['cli', 'mcp']:
                    if door == 'cli':
                        created = fixture.ok('--project', fixture.project, 'agent', 'add',
                            'Nested CLI Worker', '--provider', 'claude',
                            '--model', 'claude-sonnet-5-5', recipient=True)
                    else:
                        response = fixture.rpc('stateengine_agent_create', {
                            'name': 'Nested MCP Worker', 'provider': 'claude',
                            'model': 'claude-sonnet-5-5', 'idempotency_key': str(uuid.uuid4())})
                        assert not response.get('isError', False), response
                        created = response['structuredContent']
                    child = created['agent']['id']
                    receipt, row, _ = launch(child, door=door)
                    assert receipt['agent']['id'] == child and receipt['session_id'] != first['session_id']
                    assert row['environment'] == {'SE_SESSION': receipt['session_id']}, row
                    result['checks'].append(door + ': authenticated parent creates and launches child; no parent provider or identity marker reaches native child')
            finally:
                for key in parent:
                    fixture.env.pop(key, None)
        else:
            target = fixture.ok('--project', fixture.project, 'agent', 'add',
                'Continuity Worker', '--provider', 'claude',
                '--model', 'claude-sonnet-5-5', recipient=True)['agent']['id']
            receipts = {}
            def facts(receipt, resumed, label, before, after, planned_between=None):
                if receipt.get('resumed') is not resumed:
                    result['failures'].append(label + ': machine receipt does not report the actual resumed/fresh choice')
                age = receipt.get('saved_conversation_age', {})
                if not resumed:
                    if age.get('state') != 'absent':
                        result['failures'].append(label + ': fresh conversation carries an invented saved age')
                    return
                try:
                    assert age['state'] == 'present', age
                    value = age['value']
                    saved = datetime.fromisoformat(value['session_started_at'].replace('Z', '+00:00')).timestamp()
                    seconds = value['age_seconds']
                    assert seconds['state'] == 'present', seconds
                    assert type(seconds['value']) is int and seconds['value'] >= 1, seconds
                    # The saved timestamp belongs to the launch we actually made,
                    # and its age must agree with that clock, not a constant zero.
                    assert before - 2 <= saved <= after, (saved, before, after)
                    assert planned_between[0] - 1 <= saved + seconds['value'] <= planned_between[1] + 1, value
                except (AssertionError, KeyError, TypeError, ValueError) as error:
                    result['failures'].append(label + ': saved age is missing or inconsistent with the observed prior launch: ' + str(error))

            for door in ['cli', 'mcp']:
                before = time.time()
                saved, _, _ = launch(target, fresh=True, door=door)
                after = time.time()
                receipts[door + '-first'] = saved
                facts(saved, False, door + '-first', before, after)
                stop = fixture.ok('--project', fixture.project, 'stop', target)
                assert stop['complete'] and stop['capture']['flushed'], stop
                time.sleep(1.1)
                resuming_at = time.time()
                plain = None
                if door == 'cli':
                    resumed, row, plain = launch(target, plain=True)
                    assert resumed['conversation_id'] == saved['conversation_id'] and row['flag'] == '--resume', (saved, resumed, row)
                    facts(resumed, True, 'cli-resume', before, after, (resuming_at, time.time()))
                    result['checks'].append('cli: ordinary owner launch really resumes the saved provider conversation')
                    fixture.ok('--project', fixture.project, 'stop', target)
                    receipts['cli-resumed'] = resumed
                else:
                    # A creator can start fresh work but cannot read the child's
                    # saved capture. Test that refusal, not a privacy bypass.
                    observations = (fixture.repo / 'launch-observed.jsonl').read_bytes()
                    refused = fixture.rpc('stateengine_agent_launch', {
                        'target_agent_id': target, 'task': 'Independent continuity check.',
                        'detach': True, 'new': False, 'idempotency_key': str(uuid.uuid4())})
                    assert refused.get('isError') is True, refused
                    assert 'ScopeMismatch' in json.dumps(refused), refused
                    assert (fixture.repo / 'launch-observed.jsonl').read_bytes() == observations
                    result['checks'].append('mcp: creator cannot resume another principal capture or start a provider on refusal')
                fresh, row, fresh_plain = launch(target, fresh=True, plain=door == 'cli', door=door)
                assert fresh['conversation_id'] != saved['conversation_id'] and row['flag'] == '--session-id', (fresh, row)
                facts(fresh, False, door + '-new', before, after)
                result['checks'].append(door + ': explicit new really selects a different provider conversation')
                fixture.ok('--project', fixture.project, 'stop', target)
                if plain is not None:
                    # This is achieved behavior, not an instruction for a later resume.
                    if not re.search(r'\bresumed\b', plain, re.I):
                        result['failures'].append('launch never plainly says that it resumed the saved conversation')
                    age_pattern = re.compile(r'\b(?:\d+\s*(?:ms|seconds?|minutes?|hours?|days?|weeks?)\s*(?:old|ago)|just now|less than (?:a|one) (?:second|minute) (?:old|ago))\b', re.I)
                    if not age_pattern.search(plain):
                        result['failures'].append('resumed launch does not state how old the saved conversation is')
                    if re.search(r'\bresumed\b', fresh_plain, re.I):
                        result['failures'].append('--new is misleadingly printed as a resumed conversation')
                receipts[door + '-fresh'] = fresh
            (options.output / 'receipts.json').write_text(json.dumps(receipts, indent=2))
    except Exception as error:
        result['failures'].append(f'{type(error).__name__}: {error}')
    finally:
        if fixture is not None:
            # Parent markers must never turn owner cleanup into another seat's call.
            for key in MARKERS:
                fixture.env.pop(key, None)
            try:
                fixture.close()
                result['checks'].append('public down witnesses cleanup; observed native provider births exited')
            except Exception as error:
                result['failures'].append(f'cleanup: {error}')
        if runtime.exists():
            try:
                for directory in runtime.iterdir():
                    directory.rmdir()
                runtime.rmdir()
            except OSError as error:
                result['failures'].append(f'runtime directory cleanup: {error}')
        (options.output / 'result.json').write_text(json.dumps(result, indent=2))
    for check in result['checks']:
        print('ok - ' + check, flush=True)
    for error in result['failures']:
        print('FAIL - ' + error, flush=True)
    return 1 if result['failures'] else 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=['nested', 'resume'], required=True)
    sys.exit(run(parser.parse_args()))
