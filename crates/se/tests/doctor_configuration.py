#!/usr/bin/env python3
"""Public doctor configuration checks against an existing, closed private fixture.

--binary SE --state INITIALIZED_HOME --owner OWNER_HOME --out NEW_DIRECTORY
No installation, initialization, provider launch or account changes are performed.
The caller must supply an owned disposable fixture; its config is restored.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys


def run(options):
    state = options.state.resolve(strict=True)
    owner = options.owner.resolve(strict=True)
    out = options.out.resolve()
    out.mkdir(mode=0o700)
    config = state / 'config.toml'
    assert not config.is_symlink(), 'fixture must start with a regular or absent config'
    original = config.read_bytes() if config.exists() else None
    mode = stat.S_IMODE(config.stat().st_mode) if original is not None else None
    before = hashlib.sha256((state / 'state.db').read_bytes()).hexdigest()
    assert not (state / 'endpoint.json').exists(), 'fixture must have no host endpoint'
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('SE_', 'STATEENGINE_', 'CLAUDE', 'CODEX_'))}
    env.update(HOME=str(owner), USERPROFILE=str(owner), SE_HOME=str(state), NO_COLOR='1')
    binary = options.binary.resolve(strict=True)
    checks = []

    def call(label, selected=None, plain=False, args=None, terminal=False):
        selected_env = dict(env)
        if selected is not None:
            selected_env['SE_CONFIG'] = str(selected)
        argv = [str(binary), '--home', str(state), *(args or ['doctor'])]
        if not plain:
            argv.append('--json')
        if terminal:
            argv = ['script', '-q', '-e', '-c', shlex.join(argv), '/dev/null']
        result = subprocess.run(argv, env=selected_env, cwd=owner,
                                capture_output=True, timeout=30)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        return result

    def diagnose(label, failed, path, code=None, selected=None):
        result = call(label, selected)
        value = json.loads(result.stdout)
        rows = {item['id']: item for item in value['checks']}
        assert 'configuration.file' in rows, (label, 'configuration was not diagnosed', value)
        row = rows['configuration.file']
        assert row['state'] == ('failed' if failed else 'ok'), (label, row)
        assert str(path) in row['observed'], (label, row)
        assert 'runtime.endpoint' in rows, 'config faults must not abort other checks'
        if failed:
            assert result.returncode == 1 and value['outcome'] == 'problems', (label, value)
            assert value['summary']['failed'] > 0
            assert row['code'] == code, (label, row)
            assert row['reason'] and row['fix']['text'] and not row['repairable']
            plain = call(label + '-plain', selected, plain=True)
            text = (plain.stdout + plain.stderr).decode(errors='replace')
            assert plain.returncode == 1 and str(path) in text, (label, text)
            assert row['fix']['text'] in text, (label, 'missing manual remedy', text)
        assert b'private-canary-value' not in result.stdout + result.stderr
        checks.append(label)

    def write(data):
        if config.is_symlink():
            config.unlink()
        config.write_bytes(data)
        config.chmod(0o600)

    try:
        write(b'version = 1\n')
        diagnose('valid', False, config)
        write(b'version = 1\nruntime = [not valid TOML\n')
        diagnose('invalid-toml', True, config, 'configuration-invalid')
        write(b'version = 2\n')
        diagnose('unsupported-version', True, config, 'configuration-invalid')
        write(b'version = 1\n[runtime]\nblocking_jobs = 99\n')
        diagnose('invalid-policy', True, config, 'configuration-invalid')
        write(b'version = 1\nunknown_key = "private-canary-value"\n')
        diagnose('unknown-key', True, config, 'input-unknown-field')
        if sys.platform == 'linux' and os.geteuid() != 0:
            write(b'version = 1\n')
            config.chmod(0)
            try:
                diagnose('unreadable', True, config, 'source-unreadable')
            finally:
                config.chmod(0o600)
        config.unlink()
        diagnose('absent-default', False, config)
        if sys.platform != 'win32':
            config.symlink_to(out / 'absent-target')
            diagnose('dangling-default', True, config, 'source-unreadable')
            config.unlink()
        write(b'version = 1\n')
        explicit = out / "selected config's ü.toml"
        explicit.write_bytes(b'version = 2\n')
        diagnose('explicit-invalid', True, explicit, 'configuration-invalid', explicit)
        missing = out / 'missing-explicit.toml'
        diagnose('explicit-missing', True, missing, 'source-unreadable', missing)
        relative = Path(os.path.relpath(explicit, owner))
        diagnose('relative-selection', True, owner / relative, 'configuration-invalid', relative)
        diagnose('empty-selection', True, 'SE_CONFIG', 'configuration-invalid', '')
        if sys.platform == 'linux':
            # Root recovery stays reachable without reading any config bytes.
            write(b'version = 1\nruntime = [not valid TOML\n')
            state.chmod(0o750)
            try:
                result = call('root-recovery', args=['doctor', '--fix', 'home.permissions'], terminal=True)
                if (state / 'standalone-install.json').exists():
                    assert result.returncode == 0, result.stdout + result.stderr
                else:
                    # An init-only fixture can tighten metadata, then must
                    # refuse installation admission without reading config.
                    assert result.returncode == 1, result.stdout + result.stderr
                    assert b'owned installation record is absent' in result.stdout + result.stderr
                assert b'configuration-invalid' not in result.stdout + result.stderr
                assert stat.S_IMODE(state.stat().st_mode) == 0o700
                assert config.read_bytes() == b'version = 1\nruntime = [not valid TOML\n'
                checks.append('root-recovery')
            finally:
                state.chmod(0o700)
    finally:
        if config.is_symlink():
            config.unlink()
        if config.exists():
            config.chmod(0o600)
        if original is None:
            config.unlink(missing_ok=True)
        else:
            config.write_bytes(original)
            config.chmod(mode)
        after = hashlib.sha256((state / 'state.db').read_bytes()).hexdigest()
        assert before == after, 'doctor changed the store bytes'
        assert not (state / 'endpoint.json').exists(), 'doctor started a host'
    (out / 'results.json').write_text(json.dumps({'checks': checks,
        'store_unchanged': before == after, 'endpoint_absent': True,
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}, indent=2))
    print(f'{len(checks)} passed; 0 failed; store unchanged; no host endpoint')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'state', 'owner', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
