"""Exercise the real export with synthetic secrets in each collected source.

No account credential or provider process is used. Failures keep the private
fixture for inspection; successful runs are removed by the native test caller.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


class Fixture:
    def __init__(self, root, executable):
        root.mkdir(mode=0o700)
        self.root, self.executable = root, executable
        self.user = root / 'synthetic user'
        self.home = self.user / 'state'
        self.temp = root / 'exports'
        self.repo = root / 'repository'
        for path in [self.user, self.home, self.temp, self.repo]:
            path.mkdir(mode=0o700)
        self.environment = {}
        for key in ['PATH', 'SystemRoot', 'WINDIR', 'COMSPEC', 'SYSTEMDRIVE', 'PATHEXT']:
            if key in os.environ:
                self.environment[key] = os.environ[key]
        self.environment.update(HOME=str(self.user), USERPROFILE=str(self.user),
            APPDATA=str(self.user / 'AppData/Roaming'),
            LOCALAPPDATA=str(self.user / 'AppData/Local'),
            XDG_CONFIG_HOME=str(self.user / '.config'),
            XDG_STATE_HOME=str(self.user / '.local/state'),
            TMPDIR=str(self.temp), TEMP=str(self.temp), TMP=str(self.temp), NO_COLOR='1')
        self.forbidden = []
        self.serial = 0

    def file(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(text, encoding='utf-8')
        path.chmod(0o600)

    def credentials(self):
        # Excluded files must remain excluded even when their contents are not
        # recognizable tokens and thus cannot be rescued by text substitution.
        for index, path in enumerate([self.user / '.codex/auth.json',
                self.user / '.claude/.credentials.json', self.home / 'engine.key',
                self.home / 'credentials.json', self.home / 'nested/runtime-startup-' / 'ignored.log']):
            marker = 'excluded-file-' + str(index)
            self.file(path, json.dumps({'value': marker}))
            self.forbidden.append(marker)

    def cli(self, *arguments):
        result = subprocess.run([self.executable, '--home', str(self.home), '--json', *arguments],
            cwd=self.repo, env=self.environment, text=True, capture_output=True, timeout=30)
        self.serial += 1
        self.file(self.root / ('call-' + str(self.serial) + '.json'), json.dumps(dict(
            arguments=arguments, exit=result.returncode, stdout=result.stdout, stderr=result.stderr)))
        return result

    def log(self, text):
        self.file(self.home / ('runtime-startup-' + 'a' * 32 + '.log'), text)

    def export(self):
        result = self.cli('diagnostic-bundle')
        if result.returncode not in (0, 2):
            raise AssertionError('export refused before collecting the fixture')
        receipt = json.loads(result.stdout)
        raw = Path(receipt['path']).read_bytes()
        assert receipt['bytes'] == len(raw)
        assert receipt['sha256'] == hashlib.sha256(raw).hexdigest()
        document = json.loads(raw)
        assert document['schema'] == 'se.diagnostic-bundle-file/v1'
        assert document['logs']['entries'][0]['state'] == 'observed'
        assert 'review marker retained' in document['logs']['entries'][0]['content']
        self.file(self.root / 'reopened-bundle.json', raw.decode())
        return raw.decode(), document


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from strings(item)


def check(root, executable, case):
    fixture = Fixture(root, executable)
    if case == 'structured-observations':
        project = 'sk-synthetic-project-canary'
        agent = 'ghp_syntheticAgentCanary'
        result = fixture.cli('init', '--repo', str(fixture.repo), '--name', project,
                             '--agent', agent, '--provider', 'claude')
        assert result.returncode == 0, 'fixture init failed'
        fixture.forbidden.extend([project, agent])
        config = fixture.home / 'config.toml'
        config.write_text(config.read_text(encoding='utf-8')
                          + '\n# api_key=config-comment-canary\n', encoding='utf-8')
        fixture.forbidden.append('config-comment-canary')
        fixture.log('review marker retained\n')
    elif case == 'plain-log':
        fixture.log('review marker retained\napi_key=plain-short-canary\n'
                    'Authorization: Bearer bearer-short-canary\n'
                    '-----BEGIN PRIVATE KEY-----\nprivate-key-canary\n-----END PRIVATE KEY-----\n'
                    + str(fixture.user) + '/private-path-canary\n')
        fixture.forbidden.extend(['plain-short-canary', 'bearer-short-canary',
                                  'private-key-canary', 'private-path-canary'])
    elif case == 'nested-json':
        fixture.log(json.dumps({'message': 'review marker retained',
            'nested': {'credentials': {'api_key': 'nested-object-canary'}},
            'payload': json.dumps({'account': {'api_key': 'encoded-short-canary'}})}) + '\n')
        fixture.forbidden.extend(['nested-object-canary', 'encoded-short-canary'])
    elif case == 'escaped-json-key':
        fixture.log('review marker retained\n{"api\\u005fkey":"escaped-key-canary"}\n')
        fixture.forbidden.append('escaped-key-canary')
    elif case == 'escaped-json-path':
        payload = json.dumps({'path': str(fixture.user / 'encoded-path-canary')}).replace('/', r'\/')
        fixture.log('review marker retained\n' + payload + '\n')
        fixture.forbidden.append('encoded-path-canary')
    else:
        raise AssertionError('unknown fixture')
    # Files and configuration sit alongside each source but are never authorized
    # collection inputs. Both initialized and uninitialized sources are covered.
    fixture.credentials()
    fixture.file(fixture.user / '.claude/settings.json', '{"api_key":"provider-config-canary"}')
    fixture.forbidden.append('provider-config-canary')
    source = {path: path.read_bytes() for path in fixture.home.rglob('*') if path.is_file()}
    raw, document = fixture.export()
    assert str(fixture.user) not in raw
    assert str(fixture.repo) not in raw
    if case == 'structured-observations':
        assert document['status']['state'] == 'observed'
        assert document['doctor']['state'] == 'observed'
    leaks = [marker for marker in fixture.forbidden
             if marker in raw or any(marker in text for text in strings(document))]
    for path, original in source.items():
        assert path.read_bytes() == original, 'collection changed its source'
    assert not leaks, 'synthetic secret survived: ' + ', '.join(leaks)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--se', required=True)
    parser.add_argument('--output', required=True, type=Path)
    arguments = parser.parse_args()
    arguments.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    results = []
    for case in ['structured-observations', 'plain-log', 'nested-json',
                 'escaped-json-key', 'escaped-json-path']:
        try:
            check(arguments.output / case, str(Path(arguments.se).resolve()), case)
            results.append(dict(case=case, passed=True))
        except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
            results.append(dict(case=case, passed=False, error=str(error)))
    (arguments.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results))
    passed = sum(result['passed'] for result in results)
    print('Diagnostic redaction: ' + str(passed) + ' passed, ' + str(len(results) - passed) + ' failed')
    return int(passed != len(results))


if __name__ == '__main__':
    sys.exit(main())
