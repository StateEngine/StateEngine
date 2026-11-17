"""Public saved settings through actual owned native protocol doubles; no inference."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import sys
import termios
import time
import uuid

from agent_create_cli import owner_grant
from fixture_paths import private_runtime_directory
from mail_cli import Fixture, provider_bootstrap


def owner_set(fixture, key, value):
    master, slave = pty.openpty()

    def terminal():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    argv = [str(fixture.se), '--json', '--home', str(fixture.home), '--project',
            fixture.project, 'config', 'set', key, value]
    child = subprocess.Popen(argv, env=fixture.env, cwd=fixture.repo,
        stdin=slave, stdout=slave, stderr=slave, preexec_fn=terminal)
    os.close(slave)
    captured = bytearray()
    try:
        until = time.monotonic() + 40
        while time.monotonic() < until:
            if select.select([master], [], [], .1)[0]:
                try:
                    block = os.read(master, 65536)
                except OSError:
                    break
                if not block:
                    break
                captured.extend(block)
            elif child.poll() is not None:
                break
        if child.poll() is None:
            actual = Path(f'/proc/{child.pid}/cmdline').read_bytes().split(b'\0')
            assert [v.decode() for v in actual if v] == argv
            child.terminate()
        child.wait(timeout=5)
        assert child.returncode == 0, captured.decode()
    finally:
        os.close(master)


def run(args):
    args.output.mkdir(parents=True, exist_ok=False)
    runtime = private_runtime_directory()
    result = {'checks': [], 'failures': [], 'model_turns': 0}
    fixture = None
    try:
        helper = Path(__file__).with_name('provider_settings_review_provider.py')
        fixture = Fixture(args.se, args.output / 'fixture', provider_helper=helper)
        fixture.env = {'PATH': os.environ['PATH'], 'HOME': str(fixture.root / 'owner'),
            'USERPROFILE': str(fixture.root / 'owner'), 'LANG': 'C.UTF-8',
            'XDG_RUNTIME_DIR': str(runtime), 'CODEX_HOME': str(fixture.root / 'codex')}
        Path(fixture.env['CODEX_HOME']).mkdir()
        for name in ['XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME']:
            path = fixture.root / name.lower()
            path.mkdir()
            fixture.env[name] = str(path)
        source = fixture.root / 'provider.rs'
        source.write_text(source.read_text().replace('2.1.287', '2.1.318'))
        subprocess.run(['rustc', '--edition=2024', str(source), '-o', str(fixture.root / 'provider')],
                       capture_output=True, check=True, timeout=60)
        codex_source = fixture.root / 'codex.rs'
        codex_source.write_text('fn main(){let a:Vec<String>=std::env::args().collect();'
            'if a.iter().any(|v|v=="--version"){println!("codex-cli 0.167.2");return;}'
            'let s=std::process::Command::new(PYTHON).args(["-c",BOOTSTRAP,HELPER])'
            '.args(&a[1..]).status().unwrap();std::process::exit(s.code().unwrap_or(1));}'
            .replace('PYTHON', json.dumps(sys.executable))
            .replace('BOOTSTRAP', json.dumps(provider_bootstrap()))
            .replace('HELPER', json.dumps(str(helper.resolve()))))
        codex_image = fixture.root / 'codex-provider'
        subprocess.run(['rustc', '--edition=2024', str(codex_source), '-o', str(codex_image)],
                       capture_output=True, check=True, timeout=60)
        config = fixture.home / 'config.toml'
        config.write_text(config.read_text().replace('[providers.codex]',
            '[providers.codex]\ncommand = ' + json.dumps(str(codex_image)), 1))
        for command in [('agent', 'add', '--help'), ('launch', '--help'), ('stop', '--help'),
                        ('config', 'set', '--help')]:
            assert fixture.call(*command).returncode == 0
        fixture.ok('up')
        owner_grant(fixture, True)

        def launch(agent, provider, door='cli', resume=False):
            key = str(uuid.uuid4())
            if door == 'mcp':
                response = fixture.rpc('stateengine_agent_launch', {
                    'target_agent_id': agent, 'detach': True, 'resume': resume,
                    'task': 'Read the local fixture.', 'idempotency_key': key})
                assert not response.get('isError', False), response
                receipt = response['structuredContent']
            else:
                tail = ['--resume'] if resume else []
                receipt = fixture.ok('--project', fixture.project, '--key', key, 'launch',
                    agent, '--detach', '--task', 'Read the local fixture.', *tail)
            assert receipt['state'] == 'running' and receipt['resumed'] is resume, receipt
            until = time.monotonic() + 20
            while True:
                path = fixture.repo / 'settings-observed.jsonl'
                rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
                matching = [row for row in rows if row['session'] == receipt['session_id']
                    and row['native_root_pid'] == receipt['process']['pid'] and row['provider'] == provider]
                starts = [row for row in matching if row['method'] != 'turn/start']
                turns = [row for row in matching if row['method'] == 'turn/start']
                if starts and (provider != 'codex' or turns):
                    break
                assert time.monotonic() < until, ('no exact owned provider selection', receipt, matching)
                time.sleep(.02)
            for pid in [starts[0]['native_root_pid'], starts[0]['helper_pid']]:
                fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
                fixture.processes.append((pid, fields[19]))
            return receipt, starts[0], turns

        parent, row, _ = launch(fixture.agent, 'claude')
        fixture.session = parent['session_id']
        assert row['effort'] is None
        for door in ['cli', 'mcp']:
            for provider in ['claude', 'codex']:
                label = door + '-' + provider
                try:
                    effort = ('high' if door == 'cli' else 'max') if provider == 'claude' else ('max' if door == 'cli' else 'ultra')
                    settings = {'reasoning_effort': effort}
                    if provider == 'codex':
                        settings.update(model_provider='local_' + door, base_url='http://127.0.0.1:9/v1',
                            wire_api='responses', context_window=123456 if door == 'cli' else 234567)
                    if door == 'cli':
                        words = []
                        for field, value in settings.items():
                            words += ['--' + field.replace('_', '-'), str(value)]
                        created = fixture.ok('--project', fixture.project, 'agent', 'add', label,
                            '--provider', provider, *words)
                    else:
                        response = fixture.rpc('stateengine_agent_create', {'name': label,
                            'provider': provider, 'provider_settings': settings,
                            'idempotency_key': str(uuid.uuid4())})
                        assert not response.get('isError', False), response
                        created = response['structuredContent']
                    agent = created['agent']['id']
                    # Exercise the owner update consumer as well as both creation doors.
                    owner_set(fixture, 'agent.' + agent + '.reasoning_effort', effort)
                    saved = fixture.ok('--project', fixture.project, 'config', 'get',
                        'agent.' + agent + '.reasoning_effort')
                    assert saved['value'] == {'state': 'present', 'value': effort}, saved
                    previous = None
                    for resume in [False, True]:
                        receipt, observed, turns = launch(agent, provider, door, resume)
                        if provider == 'claude':
                            assert observed['effort'] == effort, observed
                            assert observed['method'] == ('--resume' if resume else '--session-id')
                        else:
                            selected = observed['config']
                            assert observed['modelProvider'] == settings['model_provider'], observed
                            assert selected['model_provider'] == settings['model_provider'], observed
                            assert selected['model_reasoning_effort'] == effort, observed
                            assert selected['model_context_window'] == settings['context_window'], observed
                            route = selected['route']
                            assert route['base_url'] == settings['base_url'] and route['wire_api'] == 'responses', route
                            assert all(turn['effort'] == effort for turn in turns), turns
                            assert observed['method'] == ('thread/resume' if resume else 'thread/start')
                        if previous:
                            assert receipt['conversation_id'] == previous['conversation_id'], receipt
                        result['checks'].append({'case': label, 'resume': resume,
                            'observed': observed, 'turns': turns})
                        stopped = fixture.ok('--project', fixture.project, 'stop', agent)
                        assert stopped['complete'], stopped
                        previous = receipt
                except Exception as error:
                    result['failures'].append(label + ': ' + str(error))
        result['passed'] = not result['failures'] and len(result['checks']) == 8
    except Exception as error:
        result['passed'] = False
        result['failures'].append(str(error))
    finally:
        if fixture:
            try:
                fixture.close()
                result['witnessed_shutdown'] = True
            except Exception as error:
                result['passed'] = False
                result['failures'].append('shutdown: ' + str(error))
        if result.get('witnessed_shutdown'):
            shutil.rmtree(runtime)
        (args.output / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result.get('passed') else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    raise SystemExit(run(parser.parse_args()))
