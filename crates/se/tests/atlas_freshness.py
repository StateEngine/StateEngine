"""Public CLI/MCP regression for cached pointers after an unparsed source edit.

Run with --se EXACT_RELEASE_BINARY --output NEW_PRIVATE_DIRECTORY on Linux.
Uses a native Claude protocol fixture, not a paid provider. An external holder
of the derived cache's native writer lease keeps maintenance pending; no cache
rows, parser profiles, credentials or production source are substituted.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).with_name('judges')))
from mail_cli import Fixture


def present(answer):
    if 'data' not in answer and isinstance(answer.get('value'), dict):
        answer = answer['value']
    assert answer['data']['state'] == 'present', answer
    return answer, answer['data']['value']


def pointer(answer, kind, name):
    answer, value = present(answer)
    if kind == 'outline':
        assert any(symbol['name'] == name for symbol in value['symbols']), value
        return answer, value['file'], value['coverage']
    hits = [hit['target']['Code'] for hit in value['page']['items']
            if hit.get('target', {}).get('Code', {}).get('name') == name]
    assert len(hits) == 1, value
    return answer, hits[0]['pointer'], None


def run(args):
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    private = {}
    for name in ['XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME']:
        directory = args.output / name.lower()
        directory.mkdir(mode=0o700)
        private[name] = str(directory)
    runtime = Path(tempfile.mkdtemp(prefix='se-af-', dir='/tmp'))
    private['XDG_RUNTIME_DIR'] = str(runtime)

    class IsolatedFixture(Fixture):
        def call(self, *arguments, **options):
            self.env.update(private)
            return super().call(*arguments, **options)

    f = IsolatedFixture(args.se, args.output / 'fixture')
    files = [('changed.js', 'atlas_changed_value'), ('control.js', 'atlas_control_value')]
    originals = {}
    for path, name in files:
        data = ('export function ' + name + '(){return 1;}\n' + '// padding\n' * 1200).encode()
        assert 1024 < len(data) < 524288
        (f.repo / path).write_bytes(data)
        originals[path] = data

    observations, failures, lease = {}, [], None
    baseline = {}

    def query(door, kind, path, name, preparing=False):
        if door == 'CLI':
            arguments = ['--project', f.project, 'atlas', kind,
                         name if kind == 'find' else path, '--budget', '8192']
            if kind == 'find':
                arguments += ['--kind', 'symbol', '--mode', 'exact', '--in', path]
            result = f.call(*arguments)
            if preparing and result.returncode == 1:
                error = json.loads(result.stdout)
                if error.get('code') == 'deadline-exceeded' and error.get('detail', {}).get('op') == 'Atlas SQL':
                    return error
            assert result.returncode in [0, 2], (result.stdout, result.stderr)
            return json.loads(result.stdout)
        arguments = {'format': 'json', 'byte_budget': 8192}
        arguments.update({'query': name, 'kind': 'symbol', 'mode': 'exact', 'paths': [path]}
                         if kind == 'find' else {'path': path})
        result = f.rpc('stateengine_atlas_' + kind, arguments)
        assert not result.get('isError'), result
        texts = [item['text'] for item in result.get('content', [])
                 if item.get('type') == 'text']
        assert len(texts) == 1, result
        return json.loads(texts[0])

    try:
        started = f.ok('up')
        pid = started['process']['pid']
        birth = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
        f.processes.append((pid, birth))
        # Observe real cold publication, then retain its native writer lease
        # before launching the provider or running the read assertions. Merely
        # waiting for readiness would race the first incremental reconciliation.
        until = time.monotonic() + 60
        while True:
            if list((f.home / 'atlas').glob('*/*/current.json')):
                candidate = (f.home / 'atlas' / 'writer.lock').open('rb')
                try:
                    fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    lease = candidate
                    break
                except BlockingIOError:
                    candidate.close()
            assert time.monotonic() < until, 'cold epoch was not published and released'
            time.sleep(.001)
        f.launch()
        # Establish actual cold-parsed symbols and hashes, not merely readiness.
        until = time.monotonic() + 60
        observations['preparation'] = []
        while True:
            status = f.ok('--project', f.project, 'status')['atlas']
            observations['preparation'].append(status)
            summary = status.get('summary') or {}
            if not summary.get('epoch') or summary.get('coverage', {}).get('indexed_files', 0) < 2:
                assert time.monotonic() < until, status
                time.sleep(.1)
                continue
            ready = True
            for path, name in files:
                answer = query('CLI', 'find', path, name, preparing=True)
                observations['preparation'].append(answer)
                try:
                    _, value, _ = pointer(answer, 'find', name)
                    ready &= value['freshness'] == 'Current' and bool(value['content_hash'])
                    baseline[path] = value
                except (AssertionError, KeyError):
                    ready = False
            if ready:
                break
            assert time.monotonic() < until, answer
            time.sleep(.1)
        observations['before_edit'] = {}
        for door in ['CLI', 'MCP']:
            for kind in ['find', 'outline']:
                for path, name in files:
                    answer = query(door, kind, path, name)
                    _, value, coverage = pointer(answer, kind, name)
                    assert value['freshness'] == 'Current', answer
                    assert value['content_hash'] == baseline[path]['content_hash'], answer
                    if kind == 'outline':
                        assert coverage == 'Indexed', answer
                    observations['before_edit'][f'{door}/{kind}/{path}'] = answer

        # Hold only the real writer lease while reading the published WAL epoch.
        # This models pending maintenance deterministically, without modifying
        # cached coverage or racing a reparse to make the regression disappear.
        changed = f.repo / 'changed.js'
        with changed.open('ab') as writer:
            writer.write(b'// saved edit outside the admitted incremental parser profile\n')
            writer.flush()
            os.fsync(writer.fileno())
        edited = changed.read_bytes()
        assert edited != originals['changed.js'] and edited.startswith(originals['changed.js'])
        assert (f.repo / 'control.js').read_bytes() == originals['control.js']
        observations['edit'] = {
            'bytes': len(edited),
            'before_sha256': hashlib.sha256(originals['changed.js']).hexdigest(),
            'after_sha256': hashlib.sha256(edited).hexdigest(),
            'native_writer_lease_held': True,
        }
        observations['after_edit'] = {}
        for door in ['CLI', 'MCP']:
            for kind in ['find', 'outline']:
                for path, name in files:
                    label = f'{door}/{kind}/{path}'
                    answer = query(door, kind, path, name)
                    observations['after_edit'][label] = answer
                    _, value, coverage = pointer(answer, kind, name)
                    if value['content_hash'] != baseline[path]['content_hash']:
                        failures.append(label + ': cached hash changed despite retained writer lease')
                    if path == 'control.js':
                        if value['freshness'] != 'Current' or (kind == 'outline' and coverage != 'Indexed'):
                            failures.append(label + ': unchanged verified source lost Current coverage')
                        continue
                    if value['freshness'] != 'Stale':
                        failures.append(label + ': edited unparsed bytes still claim ' + value['freshness'])
                    reasons = answer['index']['coverage']['reasons']
                    if kind == 'outline' and isinstance(coverage, dict):
                        reasons = [*reasons, coverage.get('Stale', {}).get('reason')]
                    if 'StaleSnapshot' not in reasons:
                        failures.append(label + ': stale source reason is absent')
                    if kind == 'outline' and coverage == 'Indexed':
                        failures.append(label + ': edited outline still claims Indexed')
        observations['failures'] = failures
    finally:
        if lease is not None:
            lease.close()
        (args.output / 'observations.json').write_text(json.dumps(observations, indent=2))
        # Always exercise ordinary shutdown before reporting an expected red.
        f.close()
        with (f.home / 'runtime.lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert not (f.home / 'endpoint.json').exists()
        (args.output / 'outside.json').write_text(json.dumps({
            'births': f.processes, 'original_births_not_executing': True,
            'endpoint_absent': True, 'runtime_lease_free': True,
        }, indent=2))
        if (runtime / 'stateengine').exists():
            (runtime / 'stateengine').rmdir()
        runtime.rmdir()
    labels = set(observations['after_edit'])
    assert len(labels) == 8
    failed = {message.split(': ', 1)[0] for message in failures}
    for path, label in [('changed.js', 'changed pointers'), ('control.js', 'unchanged controls')]:
        cases = {case for case in labels if case.endswith('/' + path)}
        print(f'{label}: {len(cases - failed)} passed; {len(cases & failed)} failed', flush=True)
    assert not failures, '\n'.join(failures)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    options.se, options.output = options.se.absolute(), options.output.absolute()
    run(options)
