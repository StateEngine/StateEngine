"""Real Codex/owned loopback model: recover a completed reply after both host and provider exit."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from codex_crash_recovery import Model
from recovery_capture import Fixture, gone, native, replies, status, wait


def completed(path):
    if not path:
        return False
    for line in path.read_text().splitlines():
        row = json.loads(line)
        if row.get('type') == 'event_msg' and row.get('payload', {}).get('type') == 'task_complete':
            if row['payload'].get('last_agent_message') == 'CRASH-TURN-DONE':
                return True
    return False


def run_case(options, case):
    f = Fixture(options.se, options.output / case, log_directory='calls')
    model = Model(f.root, f.repo)
    runtime = Path(tempfile.mkdtemp(prefix='se-recovery-codex-'))
    home = f.root / 'owner/.codex'
    home.mkdir()
    f.env.update(CODEX_HOME=str(home), OPENAI_API_KEY='sk-owned-loopback-no-account',
                 XDG_RUNTIME_DIR=str(runtime), TMPDIR='/tmp')
    (home / 'config.toml').write_text('model_provider="owned-loopback"\n[model_providers.owned-loopback]\nname="Owned recovery model"\nbase_url=' +
        json.dumps('http://127.0.0.1:' + str(model.server.server_port) + '/v1') +
        '\nwire_api="responses"\nrequires_openai_auth=false\n')
    subprocess.run([str(options.codex), 'login', '--with-api-key'], input=f.env['OPENAI_API_KEY'],
                   text=True, env=f.env, capture_output=True, check=True, timeout=20)
    config = f.home / 'config.toml'
    config.write_text(config.read_text().replace('[providers.codex]', '[providers.codex]\ncommand = ' +
                                               json.dumps(str(options.codex.resolve())), 1))
    f.agent = f.ok('--project', f.project, 'agent', 'add', 'Recovery Codex', '--provider', 'codex', '--model', 'gpt-6.1-sol')['agent']['id']
    rows = []
    try:
        launch = f.ok('--project', f.project, 'launch', f.agent, '--detach', '--task',
                      'Perform the owned crash-recovery work and reply CRASH-TURN-DONE.')
        f.session = launch['session_id']
        wait(lambda: (f.repo / 'crash-start').exists(), 'real Codex did not start its tool', 45)
        assert not (f.repo / 'crash-finish').exists()
        host = native(status(f)['runtime']['process']['pid'])
        provider = native(launch['process']['pid'])
        assert host and str(f.se) in host['command']
        assert provider and str(runtime) in provider['command'] and 'app-server' in provider['command']
        f.processes.extend((row['pid'], row['birth']) for row in [host, provider])
        os.kill(host['pid'], signal.SIGKILL)
        wait(lambda: gone(host), 'exact original host did not exit')
        transcript = wait(lambda: next(home.glob('sessions/**/*.jsonl'), None), 'native rollout absent')
        wait(lambda: completed(transcript), 'real Codex did not complete its native reply after host exit', 60)
        assert model.readback and (f.repo / 'crash-finish').exists()
        current = native(provider['pid'])
        assert current and current['birth'] == provider['birth'] and current['command'] == provider['command']
        os.kill(provider['pid'], signal.SIGTERM)
        wait(lambda: gone(provider), 'exact completed Codex provider did not exit')
        rows.append('real Codex completed original tool and native reply after the exact host exited')
        retained = transcript.with_suffix('.retained')
        if case == 'missing':
            transcript.rename(retained)
        f.ok('up')
        if case == 'missing':
            pending = wait(lambda: (row if row['session']['state'] == 'recovery-pending' else None)
                           if (row := next(row for row in status(f)['agents']['items'] if row['id'] == f.agent))
                           else None, 'Codex capture failure was not retained')
            assert ' stop ' in pending['resume']['reason']
            assert pending['session']['recorded_state'] == 'activated'
            retained.rename(transcript)
            stopped = f.ok('--project', f.project, 'stop', f.agent)
            assert stopped['complete'] and stopped['capture']['flushed'], stopped
            rows.append('missing native rollout stays pending and repairing its exact incarnation makes stop succeed')
        else:
            wait(lambda: 'CRASH-TURN-DONE' in replies(f), 'automatic recovery omitted the completed Codex reply')
            rows.append('up captures the completed native reply without another launch or stop')
        captured = replies(f)
        assert captured.count('CRASH-TURN-DONE') == 1
        f.ok('up')
        assert replies(f) == captured
        rows.append('history and repeated up keep the original Codex reply exactly once')
    finally:
        if 'retained' in locals() and retained.exists():
            retained.rename(transcript)
        f.close()
        model.close()
        directory = runtime / 'stateengine'
        if directory.exists():
            directory.rmdir()
        runtime.rmdir()
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--codex', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=['complete', 'missing'], action='append')
    options = parser.parse_args()
    os.umask(0o077)
    options.output.mkdir(parents=True, exist_ok=False)
    checks = []
    for case in options.case or ['complete', 'missing']:
        for check in run_case(options, case):
            checks.append(case + ': ' + check)
            print('ok', len(checks), '-', checks[-1], flush=True)
    (options.output / 'results.json').write_text(json.dumps({'pass': len(checks), 'checks': checks}, indent=2))
    print('passed', len(checks), 'failed 0', flush=True)


if __name__ == '__main__':
    main()
