"""Public headless launch preparation judges, with no service or model execution.

Run with an already-built se and a captured native --external-host-capabilities
JSON document. The existing finite native probe answers the vendor's separate
sandbox-policy CLI contract and refuses serve-service with exit 81. Reaching
that refusal proves preparation only, never a successful launch or containment.
"""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import uuid

from secode_external import capabilities, document
from secode_host_guards import Fixture, native_probe

SCHEMA = 'secode.sandbox-policy.v1'
CAPABILITY = 'git_metadata_read_only/v1'


def git(repo, env, *args):
    result = subprocess.run(['git', '-C', str(repo), *args], env=env,
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout.decode().strip()


def repository(repo, env, linked=False):
    if linked:
        primary = repo.parent / 'primary'
        primary.mkdir()
        git(primary, env, 'init')
        git(primary, env, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            '-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-m', 'Fixture')
        repo.rmdir()  # Only the empty directory just made by Fixture.
        git(primary, env, 'worktree', 'add', '--detach', str(repo), 'HEAD')
    else:
        git(repo, env, 'init')


def metadata_paths(f):
    """Resolve the real fixture's Git coordinates, not a hand-written gitfile."""
    directory = Path(git(f.repo, f.env, 'rev-parse', '--absolute-git-dir')).resolve()
    common = Path(git(f.repo, f.env, 'rev-parse', '--git-common-dir'))
    if not common.is_absolute():
        common = f.repo / common
    paths = {f.repo / '.git', directory, common.resolve()}
    if (directory / 'commondir').exists():
        paths.add(directory / 'commondir')
    return sorted(str(path) for path in paths)


def policy_report(f):
    # Exact native CLI report fields from the vendor's sandbox-policy reader.
    return {'schema': SCHEMA, 'capabilities': [CAPABILITY],
            'policy': {'git_metadata_read_only': True,
                       'readable_roots': [str(f.repo.anchor)],
                       'writable_roots': [str(f.repo), '$PRIVATE_SCRATCH'],
                       'protected_paths': metadata_paths(f), 'network': False},
            'realization': 'not_started'}


def probe_calls(directory):
    path = directory / 'calls'
    return path.read_text().splitlines() if path.exists() else []


def launch(f):
    return f.call('--key', str(uuid.uuid4()), '--project', f.project,
                  'launch', f.agent, '--task', 'Never execute this fixture input.', '--detach')


def no_input(f, directory):
    assert not any(line.startswith('run ') for line in probe_calls(directory)), \
        'a launch preparation judge must not start a resident client'
    for path in (f.home / 'secode').glob('*.json'):
        journal = document(path)
        assert journal['initial_offered'] is False, journal
        assert journal['session_create_attempted'] is False, journal


def translated(f, directory, phase, sandbox):
    snapshot = directory / (phase + '-host-policy.json')
    assert snapshot.exists(), f'{phase} did not receive a readable SECODE_CONFIG'
    policy = document(snapshot)
    config_path = Path((directory / (phase + '-config-path')).read_text())
    assert config_path.name == 'host-policy.json', config_path
    assert document(config_path) == policy, 'observed policy differs from published configuration'
    settings = policy['sandbox']
    assert settings['enabled'] is True and settings['network'] is False, settings
    permission = policy['permission']
    if sandbox == 'workspace-write':
        assert settings.get('git_metadata_read_only') is True, settings
        roots = {Path(root).resolve() for root in settings['writable_roots']}
        assert f.repo.resolve() in roots, settings
        assert not roots.intersection(Path(path).resolve() for path in metadata_paths(f)), \
            'read-only metadata was granted as a writable root'
        assert all(permission.get(tool) != 'deny' for tool in ('edit', 'shell', 'execute')), \
            'workspace writes were silently downgraded to read-only'
    else:
        assert settings['writable_roots'] == [], settings
        for tool in ('edit', 'shell', 'execute', 'external_directory'):
            assert permission[tool] == 'deny', permission
    for tool in ('webfetch', 'websearch'):
        assert permission[tool] == 'deny', permission
    return policy, config_path


def case(se, root, external, name):
    directory = root / (name + '-probe')
    native = {'capabilities': {'schema': SCHEMA, 'capabilities': [CAPABILITY]},
              'readback': '{}'}
    if name in ('missing-capability', 'read-only'):
        native['capabilities']['capabilities'] = []
    if name == 'wrong-capability-schema':
        native['capabilities']['schema'] = 'unsupported-fixture'
    provider = native_probe(directory, copy.deepcopy(external), policy=native)
    sandbox = 'read-only' if name == 'read-only' else 'workspace-write'
    f = Fixture(se, root / name, provider, sandbox, 'never',
                setup_repo=lambda repo, env: repository(repo, env, name == 'linked-worktree'))
    original_reservation = None
    try:
        if name in ('missing-capability', 'wrong-capability-schema'):
            # This is preflight: neither public history nor any lifecycle may change.
            f.refuse(CAPABILITY)
            calls = probe_calls(directory)
            assert 'sandbox-policy --capabilities' in calls, calls
            assert not any(line.startswith(('init-profile ', 'serve-service ', 'run '))
                           for line in calls), calls
            return
        report = policy_report(f)
        if name == 'mismatched-readback':
            report['policy']['git_metadata_read_only'] = False
        elif name == 'absent-readback':
            del report['policy']['git_metadata_read_only']
        elif name == 'null-readback':
            report['policy'] = None
        elif name == 'widened-readback':
            report['policy']['writable_roots'].append(str(f.root))
        elif name == 'duplicate-readback':
            report['policy']['writable_roots'].append(str(f.repo))
        elif name == 'network-readback':
            report['policy']['network'] = True
        elif name == 'started-readback':
            report['realization'] = 'started'
        elif name == 'wrong-readback-schema':
            report['schema'] = 'unsupported-fixture'
        elif name == 'refused-auxiliary-preparation':
            # A real directory disappearing between preflight and native
            # preparation leaves the original reservation without a child.
            (directory / 'hide-cwd').write_text(str(f.repo))
        raw = '{unreadable' if name == 'unreadable-readback' else json.dumps(report)
        (directory / 'sandbox-readback.json').write_text(raw)
        if name == 'failed-readback':
            (directory / 'sandbox-exit').write_text('82')
        f.snapshot()
        result = launch(f)
        if name == 'refused-auxiliary-preparation':
            held = f.repo.with_suffix('.held')
            assert held.is_dir() and not f.repo.exists(), (result.stdout, result.stderr)
            held.rename(f.repo)
            assert result.returncode != 0, (result.stdout, result.stderr)
            no_input(f, directory)
            journals = list((f.home / 'secode').glob('*.json'))
            assert len(journals) == 1, journals
            journal = document(journals[0])
            checkpoint = journal['bootstrap']['checkpoint']
            assert checkpoint['kind'] == 'reservation', checkpoint
            original_reservation = journal['bootstrap']
            assert not any(row.startswith(('init-profile ', 'serve-service ', 'run '))
                           for row in probe_calls(directory)), probe_calls(directory)
            return  # finally still requires public witnessed down.
        # The stub always refuses service execution. Never call this launch success.
        assert result.returncode != 0, (result.stdout, result.stderr)
        calls = probe_calls(directory)
        no_input(f, directory)
        reached_service = (directory / 'service-attempted').exists()
        if name in ('workspace-write', 'linked-worktree', 'read-only'):
            assert reached_service, (calls, result.stdout, result.stderr)
            service_policy, config_path = translated(f, directory, 'service', sandbox)
            assert sum(line.startswith('serve-service ') for line in calls) == 1, calls
            if sandbox == 'workspace-write':
                readback_policy, readback_path = translated(f, directory, 'readback', sandbox)
                assert readback_policy == service_policy and readback_path == config_path
                assert Path((directory / 'readback-profile').read_text()) == config_path.parent
                assert Path((directory / 'readback-workspace').read_text()).resolve() == f.repo.resolve()
                capability_at = calls.index('sandbox-policy --capabilities')
                bootstrap_at = next(i for i, row in enumerate(calls) if row.startswith('init-profile '))
                readback_at = next(i for i, row in enumerate(calls)
                                   if row.startswith('sandbox-policy --service '))
                service_at = next(i for i, row in enumerate(calls) if row.startswith('serve-service '))
                assert capability_at < bootstrap_at < readback_at < service_at, calls
        else:
            assert any(row.startswith('sandbox-policy --service ') for row in calls), \
                (calls, result.stdout, result.stderr)
            translated(f, directory, 'readback', sandbox)
            assert not reached_service, 'bad policy readback reached service execution'
            assert not any(row.startswith('serve-service ') for row in calls), calls
            reason = (result.stdout + result.stderr).lower()
            assert any(code in reason for code in (b'provider-incompatible', b'source-unreadable')), reason
    finally:
        held = f.repo.with_suffix('.held')
        if held.is_dir() and not f.repo.exists():
            held.rename(f.repo)
        f.close()
        if original_reservation is not None:
            journal = document(journals[0])
            terminal = journal['bootstrap']
            assert journal['retired'] is True, journal
            assert terminal['lifecycle'] == original_reservation['lifecycle'], terminal
            assert terminal['checkpoint']['kind'] == 'exit', terminal
            exit_value = terminal['checkpoint']['value']
            assert exit_value['source'] == original_reservation['checkpoint'], exit_value
            witness = exit_value['witness']
            assert witness['root'] == 'NoChildCreated', witness
            remaining = witness['scope_exit']['remaining']
            assert remaining['population'] == 'Empty' and remaining['extent'] == 'Complete', witness
            assert remaining['known_live'] == [] and witness['scope_exit']['exit_basis'], witness


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--capabilities', type=Path, required=True,
                        help='captured native --external-host-capabilities JSON')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=CASES, action='append')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('this launch-preparation fixture is Linux-only; Windows remains unqualified')
    external = document(args.capabilities)
    capabilities(external)
    root = args.output.resolve()
    root.mkdir(mode=0o700)
    selected = args.case or CASES
    print(f'1..{len(selected)}', flush=True)
    failed = []
    for number, name in enumerate(selected, 1):
        try:
            case(args.se.resolve(), root, external, name)
        except Exception as error:
            failed.append(name)
            print(f'not ok {number} - {name}: {error}', flush=True)
        else:
            print(f'ok {number} - {name} launch preparation only', flush=True)
    if failed:
        raise SystemExit('failed: ' + ', '.join(failed))


CASES = ['workspace-write', 'missing-capability', 'wrong-capability-schema',
         'mismatched-readback', 'absent-readback', 'null-readback',
         'unreadable-readback', 'failed-readback', 'read-only', 'linked-worktree',
         'widened-readback', 'duplicate-readback', 'network-readback',
         'started-readback', 'wrong-readback-schema', 'refused-auxiliary-preparation']

if __name__ == '__main__':
    main()
