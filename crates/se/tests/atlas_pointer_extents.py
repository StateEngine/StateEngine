"""Bug: pre-a3cd2faa compact pointers omitted target size; ordinary edits deferred.

Protects: public CLI/MCP symbol and file extents agree with live UTF-8 bytes,
including CRLF and exclusive final newlines, after default-profile reparsing.
Uses the native Claude protocol fixture; it does not qualify a paid provider,
parser resource budget, latency, or a quiet machine.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).with_name('judges')))
from mail_cli import Fixture


def value(answer):
    if 'data' not in answer:
        answer = answer['value']
    assert answer['data']['state'] == 'present', answer
    return answer['data']['value']


def run(args):
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    private = {}
    for key in ['XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME']:
        path = args.output / key.lower()
        path.mkdir()
        private[key] = str(path)
    runtime = Path(tempfile.mkdtemp(prefix='se-pe-', dir='/tmp'))
    print("fixture root (retained on failed or interrupted closure):", runtime, flush=True)
    private['XDG_RUNTIME_DIR'] = str(runtime)

    class IsolatedFixture(Fixture):
        def call(self, *arguments, **options):
            self.env.update(private)
            return super().call(*arguments, **options)

    f = IsolatedFixture(args.se, args.output / 'fixture')
    cases = [('crlf.rs', b'\r\n', True), ('utf8.rs', b'\n', False)]
    data, names, declarations = {}, {}, {}
    for i, (path, newline, final_newline) in enumerate(cases):
        names[path] = f'extent_before_{i}'
        declarations[path] = f'pub fn {names[path]}() -> u32 {{ 7 }}'.encode()
        # More than the former 1 KiB admission ceiling, using actual UTF-8 bytes.
        data[path] = ('// café ordinary source'.encode() + newline) * 180
        data[path] += declarations[path] + (newline if final_newline else b'')
        assert 1024 < len(data[path]) < 65536
        (f.repo / path).write_bytes(data[path])
    observations, failures = {'preparation': [], 'checks': {}, 'outcomes': {}}, []

    def query(door, kind, path, name, compact=False):
        if door == 'MCP':
            arguments = {'format': 'compact' if compact else 'json', 'byte_budget': 8192}
            arguments.update({'query': name, 'kind': 'symbol', 'mode': 'exact', 'paths': [path]}
                             if kind == 'find' else {'path': path})
            reply = f.rpc('stateengine_atlas_' + kind, arguments)
            assert not reply.get('isError'), reply
            texts = [part['text'] for part in reply['content'] if part['type'] == 'text']
            assert len(texts) == 1, reply
            return texts[0] if compact else json.loads(texts[0])
        arguments = ['--project', f.project, 'atlas', kind,
                     name if kind == 'find' else path, '--budget', '8192']
        if kind == 'find':
            arguments += ['--kind', 'symbol', '--mode', 'exact', '--in', path]
        if not compact:
            result = f.call(*arguments)
        else:
            f.calls += 1
            result = subprocess.run([str(f.se), '--home', str(f.home), *arguments],
                                    env=f.env, capture_output=True, timeout=90)
            base = f.log_root / f'call-{f.calls:02}'
            base.with_suffix('.stdout').write_bytes(result.stdout)
            base.with_suffix('.stderr').write_bytes(result.stderr)
        assert result.returncode in [0, 2, 4], (result.stdout, result.stderr)
        return result.stdout.decode() if compact else json.loads(result.stdout)

    def symbol(answer, name):
        hits = value(answer)['page']['items']
        matches = [hit['target']['Code'] for hit in hits
                   if hit.get('target', {}).get('Code', {}).get('name') == name]
        assert len(matches) == 1, answer
        return matches[0]['pointer']

    def ready(stage):
        until = time.monotonic() + 45
        while True:
            try:
                answers = {path: query('CLI', 'find', path, names[path]) for path, _, _ in cases}
                observations['preparation'].append({'stage': stage, 'answers': answers})
                pointers = {path: symbol(answer, names[path]) for path, answer in answers.items()}
                if all(p['freshness'] == 'Current' for p in pointers.values()):
                    return True
            except (AssertionError, KeyError) as error:
                observations['preparation'].append({'stage': stage, 'error': str(error)})
            if time.monotonic() >= until:
                failures.append(stage + ': default parser did not publish the new declarations')
                return False
            time.sleep(.15)

    def check(stage):
        for path, _, _ in cases:
            actual = (f.repo / path).read_bytes()
            assert actual == data[path]
            for door in ['CLI', 'MCP']:
                label = stage + '/' + door + '/' + path
                observations['outcomes'][label] = 'failed'
                try:
                    found = query(door, 'find', path, names[path])
                    outlined = query(door, 'outline', path, names[path])
                    compact = query(door, 'find', path, names[path], True)
                    compact_outline = query(door, 'outline', path, names[path], True)
                    observations['checks'][label] = [found, outlined, compact, compact_outline]
                    p, file = symbol(found, names[path]), value(outlined)['file']
                    assert p['freshness'] == file['freshness'] == 'Current'
                    assert p['content_hash'] == file['content_hash']
                    span = p['span']
                    assert actual[span['start_byte']:span['end_byte']] == declarations[path]
                    assert file['span'] == {
                        'start': {'line': 1, 'byte_column': 0},
                        'end': {'line': actual.count(b'\n') + 1,
                                'byte_column': len(actual.rsplit(b'\n', 1)[-1])},
                        'start_byte': 0, 'end_byte': len(actual)}, file
                    line = actual[:span['start_byte']].count(b'\n') + 1
                    assert f'{path}:{line} ({len(declarations[path])} B)' in compact
                    last = actual.count(b'\n') + int(not actual.endswith(b'\n'))
                    assert f'{path}:1-{last} ({len(actual)} B)' in compact_outline
                    for text in [compact, compact_outline]:
                        assert len(text.encode()) <= 8192
                        assert 'café ordinary source' not in text
                        assert declarations[path].decode() not in text
                    observations['outcomes'][label] = 'passed'
                except (AssertionError, KeyError) as error:
                    failures.append(label + ': ' + str(error))

    try:
        started = f.ok('up')
        pid = started['process']['pid']
        f.processes.append((pid, Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]))
        f.launch()
        if ready('cold'):
            check('cold')
        for i, (path, newline, final_newline) in enumerate(cases):
            old = data[path]
            names[path] = f'extent_saved_{i}'
            declarations[path] = f'pub fn {names[path]}() -> u32 {{ 9 }}'.encode()
            data[path] = old.replace(f'extent_before_{i}'.encode(), names[path].encode()).replace(b'{ 7 }', b'{ 9 }')
            with (f.repo / path).open('wb') as writer:
                writer.write(data[path])
                writer.flush()
                os.fsync(writer.fileno())
            observations.setdefault('edits', {})[path] = {
                'before_sha256': hashlib.sha256(old).hexdigest(),
                'after_sha256': hashlib.sha256(data[path]).hexdigest(), 'bytes': len(data[path])}
        if ready('saved'):
            check('saved')
    finally:
        observations['failures'] = failures
        (args.output / 'observations.json').write_text(json.dumps(observations, indent=2))
        f.close()
        for name in ['runtime.lock', 'atlas/writer.lock']:
            with (f.home / name).open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (args.output / 'outside.json').write_text(json.dumps({
            'births': f.processes, 'original_births_not_executing': True,
            'endpoint_absent': not (f.home / 'endpoint.json').exists(),
            'runtime_and_atlas_writer_leases_free': True}, indent=2))
        if (runtime / 'stateengine').exists():
            (runtime / 'stateengine').rmdir()
        runtime.rmdir()
    outcomes = list(observations['outcomes'].values())
    print(f'pointer extent and ordinary edit cases: {outcomes.count("passed")} passed; '
          f'{outcomes.count("failed")} failed; {8 - len(outcomes)} not run', flush=True)
    assert len(outcomes) == 8 and not failures, '\n'.join(failures)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    options.se, options.output = options.se.absolute(), options.output.absolute()
    run(options)
