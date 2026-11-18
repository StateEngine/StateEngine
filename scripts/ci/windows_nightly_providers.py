"""Run the five native journeys serially in a disposable hosted Windows VM."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from harness_matrix.io import ANSI

PROVIDERS = {
    'claude': ('claude', 'claude-stream-json', 'CI_ANTHROPIC_API_KEY', 'CI_CLAUDE_MODEL'),
    'codex': ('codex', 'codex-app-server', 'CI_OPENAI_API_KEY', 'CI_CODEX_MODEL'),
}
KEYS = ('CI_ANTHROPIC_API_KEY', 'CI_OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY')
FAILURE_STREAM_LIMIT = 65536


def clean_environment():
    # Let Windows PowerShell construct its own module path, even under pwsh.
    return {key: value for key, value in os.environ.items()
            if key.upper() not in KEYS and key.upper() != 'PSMODULEPATH'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def secret_variants(values):
    return {variant for value in values for variant in
            (value, json.dumps(value, ensure_ascii=True)[1:-1], quote(value, safe=''),
             base64.b64encode(value.encode('utf-8')).decode('ascii')) if variant}


def require_safe_output(outputs, values):
    secrets = [variant.encode('utf-8') for variant in secret_variants(values)]
    require(all(secret not in data for secret in secrets for data in outputs),
            'Result contains credential material and cannot be published')


def evidence_identity(info):
    # Windows Python can expose birth time for lstat().st_ctime_ns and
    # change time for fstat().st_ctime_ns on the very same file.
    created = getattr(info, 'st_birthtime_ns', info.st_ctime_ns) if os.name == 'nt' else info.st_ctime_ns
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, created)


def read_evidence(path, limit):
    def plain(info):
        return (stat.S_ISREG(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400
                and info.st_nlink == 1 and info.st_ino != 0 and info.st_size <= limit)

    info = path.lstat()
    require(plain(info), 'Failure evidence is not a bounded plain file')
    identity = evidence_identity(info)
    try:
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            require(plain(opened) and evidence_identity(opened) == identity,
                    'Failure evidence identity changed')
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            named = path.lstat()
            require(len(data) == info.st_size and plain(after) and plain(named)
                    and evidence_identity(after) == evidence_identity(named) == identity
                    and after.st_ctime_ns == opened.st_ctime_ns, 'Failure evidence changed during read')
    except FileNotFoundError as error:
        raise RuntimeError('Failure evidence disappeared during read') from error
    return data


def failure_stream(path, redact):
    try:
        raw = read_evidence(path, 8 * 1024**2)
    except FileNotFoundError:
        return 'absent', None, None, None, None
    except (OSError, RuntimeError):
        return 'unreadable', None, None, None, None
    try:
        decoded, replacement = raw.decode('utf-8'), False
    except UnicodeDecodeError:
        decoded, replacement = raw.decode('utf-8', errors='replace'), True
    # ConPTY merges the child's streams into stdout and may insert formatting
    # inside a credential. Remove terminal formatting before redaction.
    text = redact(ANSI.sub('', decoded).replace('\r', '')).encode('utf-8')
    return ('present', text[:FAILURE_STREAM_LIMIT].decode('utf-8', errors='ignore'),
            len(text) > FAILURE_STREAM_LIMIT, len(raw), replacement)


def failure_evidence(output, values):
    metadata = output / 'first-failed-command.json'
    try:
        raw_metadata = read_evidence(metadata, 1024**2)
    except FileNotFoundError:
        return None
    command = json.loads(raw_metadata)
    name = command.get('stderr_file')
    require(isinstance(name, str) and re.fullmatch(r'[0-9]{4}-[A-Za-z0-9_-]+\.stderr', name)
            and isinstance(command.get('argv'), list) and all(isinstance(arg, str) for arg in command['argv'])
            and isinstance(command.get('actual_argv'), list)
            and all(isinstance(arg, str) for arg in command['actual_argv'])
            and isinstance(command.get('label'), str)
            and (command.get('exit') is None or type(command['exit']) is int)
            and (command.get('failure') is None or isinstance(command['failure'], str)),
            'Failure command evidence is malformed')
    variants = sorted(secret_variants(values), key=len, reverse=True)

    def redact(value):
        if value is None:
            return None
        for secret in variants:
            value = value.replace(secret, '[REDACTED]')
        # A terminal line break can divide an otherwise recognizable secret.
        joined = ''.join(value.split())
        if any(secret in joined for secret in variants):
            return '[REDACTED]'
        return value

    evidence = dict(label=redact(command['label']), argv=[redact(arg) for arg in command['argv']],
                    actual_argv=[redact(arg) for arg in command['actual_argv']],
                    exit=command['exit'], failure=redact(command['failure']))
    for stream in ('stdout', 'stderr'):
        path = (output / name).with_suffix('.' + stream)
        state, text, truncated, size, replacement = failure_stream(path, redact)
        evidence.update({stream: text, stream + '_state': state,
                         stream + '_truncated': truncated, stream + '_bytes': size,
                         stream + '_decode_replacement': replacement})
    return evidence


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def windows_package_image(provider, launcher):
    packages = launcher.parent / 'node_modules'
    package = packages / {'claude': '@anthropic-ai/claude-code', 'codex': '@openai/codex'}[provider]
    name = package.relative_to(packages).as_posix()
    metadata = json.loads(read_evidence(package / 'package.json', 65536))
    require(isinstance(metadata, dict) and metadata.get('name') == name, 'Installed provider package name differs')
    if provider == 'claude':
        bins = metadata.get('bin')
        entry = bins.get('claude') if isinstance(bins, dict) else bins
        require(isinstance(entry, str) and entry, 'Installed Claude package has no command entry')
        relative = Path(entry)
        require(not relative.anchor and '..' not in relative.parts, 'Installed Claude command must be package-relative')
        resolved_package = package.resolve(strict=True)
        image = (resolved_package / relative).resolve(strict=True)
        require(image.is_relative_to(resolved_package), 'Installed Claude command escapes its package')
        return image
    layouts = {'win-amd64': ('codex-win32-x64', 'x86_64-pc-windows-msvc'),
               'win-arm64': ('codex-win32-arm64', 'aarch64-pc-windows-msvc')}
    layout = layouts.get(sysconfig.get_platform())
    require(layout is not None, 'Windows Codex package architecture is unsupported')
    optional, target = layout
    for root in (package / 'node_modules/@openai' / optional, packages / '@openai' / optional, package):
        candidate = root / 'vendor' / target / 'bin/codex.exe'
        if candidate.is_file():
            return candidate.resolve(strict=True)
    raise RuntimeError('Installed Codex package has no native image')


def windows_provider_image(provider, launcher):
    adjacent = launcher.with_name(provider + '.exe')
    if adjacent.is_file():
        image = adjacent.resolve(strict=True)
    elif launcher.suffix.lower() == '.exe':
        image = launcher
    else:
        image = windows_package_image(provider, launcher)
    require(image.suffix.lower() == '.exe' and image.is_file(),
            'Installed provider command is not a native Windows executable')
    with image.open('rb') as stream:
        require(stream.read(2) == b'MZ', 'Installed provider command has no Windows image header')
    return image


def prepared(provider, root, archive, archive_sha, commit, seed, platform='win32'):
    command, driver, key_name, model_name = PROVIDERS[provider]
    model = os.environ.get(model_name)
    require(isinstance(model, str) and re.fullmatch(r'[A-Za-z0-9._:/+-]{1,128}', model),
            'Provider model variable is absent or invalid')
    require(bool(os.environ.get(key_name)), 'Dedicated provider key is absent')
    require(not any(value and value in model for value in
                    (os.environ.get('CI_ANTHROPIC_API_KEY'), os.environ.get('CI_OPENAI_API_KEY'))),
            'Provider model variable contains credential material')
    executable = shutil.which(command)
    require(executable is not None, 'Native provider executable is absent')
    launcher = Path(executable).resolve()
    image = windows_provider_image(provider, launcher) if platform == 'win32' else launcher
    version = subprocess.run([str(image), '--version'], env=clean_environment(), stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=60, check=True).stdout.strip()
    require(bool(version) and len(version) <= 1024, 'Provider version is unavailable')
    config = root / (provider + '.toml')
    config.write_text('version = 1\n\n[providers.' + provider + ']\nmodel = ' + json.dumps(model)
                      + '\nprofile = "nightly"\n'
                      + '[profiles.nightly]\nsandbox = "workspace-write"\n'
                      + 'approval = "never"\nnetwork = true\nbypass = false\n', encoding='utf-8')
    profile = dict(name='nightly', sandbox='workspace-write', approval='never', network=True, bypass=False)
    settings = {
        'credential_seed': seed, 'configuration': {'path': str(config), 'sha256': digest(config)},
        'permission_profile': profile, 'images': [
            {'path': str(path), 'sha256': digest(path)} for path in dict.fromkeys((launcher, image))],
        'version_command': [str(image), '--version'], 'version_stdout': version,
    }
    manifest = {'schema': 'se.harness-matrix-input/v1', 'harnesses': [
        {'id': provider, 'driver': driver, 'platforms': {platform: settings}}]}
    if platform == 'win32':
        settings['launch_image'] = str(image)
        manifest['windows_journeys'] = {
            'release': {'path': str(archive), 'sha256': archive_sha, 'source_commit': commit}}
    path = root / (provider + '-manifest.json')
    path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return path, key_name


def provision(provider, key_name, root):
    key = os.environ.get(key_name)
    require(isinstance(key, str) and bool(key), 'Dedicated provider key is absent')
    credential = {'api_key': key} if provider == 'claude' else {'auth_mode': 'apikey', 'OPENAI_API_KEY': key}
    source = {'credential': credential, 'native': {'hasCompletedOnboarding': True} if provider == 'claude' else {}}
    result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/windows-journeys.py'), 'provision',
                             '--provider', provider, '--out', str(root / provider)],
                            input=json.dumps(source).encode(), env=clean_environment(),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    require(result.returncode == 0, 'Private credential provisioning failed')
    receipt = json.loads(result.stdout)
    path = Path(receipt['path'])
    require(path == (root / provider / 'seed.json').resolve() and digest(path) == receipt['sha256'],
            'Private seed identity differs')
    return {'path': str(path), 'sha256': receipt['sha256']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--release-run-id', required=True)
    parser.add_argument('--provider', choices=tuple(PROVIDERS), required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == 'win32' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted',
            'A disposable hosted Windows VM is required')
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('GITHUB_EVENT_NAME') in ('schedule', 'workflow_dispatch')
            and os.environ.get('GITHUB_REF') == 'refs/heads/main', 'A main nightly workflow is required')
    commit = os.environ.get('NIGHTLY_SOURCE_SHA', '')
    scheduled_head = os.environ.get('GITHUB_SHA', '')
    require(re.fullmatch(r'[a-f0-9]{40}', commit) and re.fullmatch(r'[a-f0-9]{40}', scheduled_head)
            and re.fullmatch(r'[0-9]+', args.release_run_id)
            and re.fullmatch(r'[a-f0-9]{64}', args.archive_sha256), 'Release identities are invalid')
    archive = args.archive.resolve(strict=True)
    require(archive.is_file() and digest(archive) == args.archive_sha256, 'Release archive digest differs')
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, timeout=30,
                                     env=clean_environment()).strip()
    require(actual == commit, 'Workflow checkout does not match its scheduled source')
    ancestor = subprocess.run(['git', 'merge-base', '--is-ancestor', commit, scheduled_head],
                              cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=30, env=clean_environment())
    require(ancestor.returncode == 0, 'Release source is not in scheduled main history')
    args.out.mkdir(parents=True, exist_ok=False)
    root = args.out.resolve()
    seed_root = (Path(os.environ['RUNNER_TEMP']) / 'nightly-provider-seeds').resolve()
    seed_root.mkdir(mode=0o700, exist_ok=False)
    subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/ci/installation_account.py'), 'provision'],
                   check=True, stdin=subprocess.DEVNULL, timeout=60, env=clean_environment())
    rows = []
    provider = args.provider
    key_name = PROVIDERS[provider][2]
    seed = provision(provider, key_name, seed_root)
    manifest, _ = prepared(provider, root, archive, args.archive_sha256, commit, seed)
    output = root / (provider + '-journey')
    result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/windows-journeys.py'), 'run',
                             '--manifest', str(manifest), '--harness', provider,
                             '--cycle', os.environ['GITHUB_RUN_ID'], '--out', str(output),
                             '--foreground-runtime'],
                            env=clean_environment(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=7200)
    receipt_path = output / 'results.json'
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    phases = receipt.get('phases', {})
    rows.append({'provider': provider, 'exit': result.returncode, 'result': receipt.get('result'),
                 'receipt_sha256': digest(receipt_path),
                 'phases': {key: phases.get(key, {}).get('result', 'NOT RUN') for key in ('J1','J2','J3','J4','J5')},
                 'release': receipt.get('release'), 'credential_closure': receipt.get('credential_closure'),
                 'process_closure': receipt.get('process_closure'),
                 'detached_host_start': receipt.get('detached_host_start'),
                 'foreground_hosts': receipt.get('foreground_hosts')})
    secrets = [os.environ[name] for name in KEYS if os.environ.get(name)]
    failure_state = 'not-applicable' if receipt.get('result') == 'PASS' else 'unavailable'
    failure = None
    if receipt.get('result') != 'PASS':
        try:
            failure = failure_evidence(output, secrets)
            if failure is not None:
                failure_state = 'available'
        except (OSError, RuntimeError, ValueError, TypeError):
            failure_state = 'unreadable'
    evidence_bytes = (json.dumps(failure, indent=2) + '\n').encode('utf-8') if failure is not None else None
    rows[0]['failure_evidence'] = failure_state
    if evidence_bytes is not None:
        rows[0]['failure_evidence_sha256'] = hashlib.sha256(evidence_bytes).hexdigest()

    summary = {'schema': 'se.windows-nightly-providers/v1', 'source_commit': commit,
               'workflow_run_id': os.environ['GITHUB_RUN_ID'], 'release_run_id': args.release_run_id,
               'archive_sha256': args.archive_sha256, 'providers': rows}
    summary_bytes = (json.dumps(summary, indent=2) + '\n').encode('utf-8')
    receipts = {row['provider']: (root / (row['provider'] + '-journey') / 'results.json').read_bytes()
                for row in rows}
    require_safe_output([summary_bytes, *receipts.values(), *([evidence_bytes] if evidence_bytes else [])], secrets)
    publish = root / 'publish'
    publish.mkdir()
    (publish / 'summary.json').write_bytes(summary_bytes)
    for provider, data in receipts.items():
        destination = publish / (provider + '-journey')
        destination.mkdir()
        (destination / 'results.json').write_bytes(data)
        if evidence_bytes is not None:
            (destination / 'failure.json').write_bytes(evidence_bytes)
    return 0 if (len(rows) == 1 and all(row['exit'] == 0 and row['result'] == 'PASS'
               and isinstance(row['detached_host_start'], dict)
               and row['detached_host_start'].get('hosted') == 'NOT RUN'
               and row['process_closure'] == [] and isinstance(row['credential_closure'], dict)
               and row['credential_closure'].get('delivery') == ('environment' if row['provider'] == 'claude' else 'private-file')
               and row['credential_closure'].get('private_copy_absent') is True
               and row['credential_closure'].get('refresh_tokens_copied') is False
               and isinstance(row['release'], dict) and row['release'].get('archive_sha256') == args.archive_sha256
               and row['release'].get('source_commit') == commit
               and all(value == 'PASS' for value in row['phases'].values()) for row in rows)) else 1


if __name__ == '__main__':
    raise SystemExit(main())
