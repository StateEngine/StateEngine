"""Independent public CLI controls for saved-agent renaming; no provider calls."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import uuid


def check(se, root, hosted):
    root.mkdir(parents=True)
    owner, repo, home = root / 'owner', root / 'repo', root / 'state'
    owner.mkdir()
    repo.mkdir()
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(('SE_', 'STATEENGINE_', 'CLAUDE', 'CODEX_'))}
    environment.update(HOME=str(owner), USERPROFILE=str(owner))
    calls = 0

    def call(*args, success=True):
        nonlocal calls
        calls += 1
        result = subprocess.run([str(se), '--home', str(home), '--json', *args],
                                cwd=repo, env=environment, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=60)
        (root / f'{calls:02}.stdout').write_bytes(result.stdout)
        (root / f'{calls:02}.stderr').write_bytes(result.stderr)
        if success:
            assert result.returncode == 0, (args, result.stdout, result.stderr)
            return json.loads(result.stdout)
        assert result.returncode != 0, (args, result.stdout, result.stderr)
        return result

    init = call('init', '--repo', str(repo), '--name', 'Rename Controls',
                '--agent', 'Original', '--provider', 'codex')
    project, agent = init['project']['id'], init['agent']['id']
    config = home / 'config.toml'
    config.write_text('\n'.join(line for line in config.read_text().splitlines()
                                if not line.startswith('listen_port = ')) + '\n')
    prefix = ('--project', project)
    peer = call(*prefix, 'agent', 'add', 'Occupied', '--provider', 'claude')['agent']
    repo2 = root / 'other'
    repo2.mkdir()
    other = call('init', '--repo', str(repo2), '--name', 'Other Project',
                 '--agent', 'Other', '--provider', 'codex')
    if hosted:
        call('up')
    try:
        key = str(uuid.uuid4())
        renamed = call(*prefix, '--key', key, 'agent', 'rename', 'Original', 'New Name')
        assert renamed['schema'] == 'se.agent-receipt/v1'
        assert renamed['action'] == 'rename' and renamed['outcome'] == 'renamed'
        assert renamed['previous_name'] == 'Original' and renamed['agent']['name'] == 'New Name'
        assert renamed['agent']['id'] == agent and renamed['process_started'] is False
        assert renamed['state'] == 'committed'
        assert renamed['writer']['mode'] == ('host' if hosted else 'direct')
        print('ok - rename receipt, stable identity and actual writer route', flush=True)
        shown = call(*prefix, 'agent', 'show', 'New Name')
        listed = call(*prefix, 'agent', 'list')
        assert any(row['id'] == agent and row['name'] == 'New Name' for row in listed['items'])
        assert agent in json.dumps(shown) and 'New Name' in json.dumps(shown)
        call(*prefix, 'agent', 'show', 'Original', success=False)
        print('ok - new selector resolves and the prior selector retires', flush=True)
        replay = call(*prefix, '--key', key, 'agent', 'rename', 'Original', 'New Name')
        assert replay['state'] == 'replayed' and replay['event_id'] == renamed['event_id']
        assert replay['agent']['id'] == agent and replay['process_started'] is False
        call(*prefix, '--key', key, 'agent', 'rename', agent, 'Different', success=False)
        print('ok - old-selector retry resolves the committed identity; changed intent refuses', flush=True)
        noop = call(*prefix, 'agent', 'rename', agent, 'New Name')
        assert noop['outcome'] == 'unchanged' and noop['agent']['id'] == agent
        print('ok - same-name rename reports unchanged', flush=True)
        for selector, name in [(agent, 'Occupied'), (agent, 'Owner'),
                               ('not-a-saved-agent', 'Valid'), (agent, ''),
                               (agent, 'x' * 65), (agent, 'Invalid\nName'), (agent, 'Non-ASCII-\u2603')]:
            call(*prefix, 'agent', 'rename', selector, name, success=False)
        stable = call(*prefix, 'agent', 'list')
        assert any(row['id'] == agent and row['name'] == 'New Name' for row in stable['items'])
        assert any(row['id'] == peer['id'] and row['name'] == 'Occupied' for row in stable['items'])
        print('ok - conflicts and invalid/unknown inputs preserve both saved identities', flush=True)
        evidence = call(*prefix, 'history', '--event', renamed['event_id'])
        assert agent in json.dumps(evidence) and 'New Name' in json.dumps(evidence)
        print('ok - the committed event remains readable by stable identity', flush=True)
        call('--project', other['project']['id'], 'agent', 'rename', agent, 'Foreign', success=False)
        assert any(row['id'] == agent and row['name'] == 'New Name'
                   for row in call(*prefix, 'agent', 'list')['items'])
        print('ok - a foreign project cannot rename the stable identity', flush=True)
    finally:
        stopped = call('down')
        assert stopped['complete'] and stopped['witness']['state'] == 'witnessed'
        assert not (home / 'endpoint.json').exists()
        print('ok - normal shutdown is witnessed and endpoint absent', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    for hosted in (False, True):
        check(args.se.resolve(), args.output / ('hosted' if hosted else 'direct'), hosted)


if __name__ == '__main__':
    main()
