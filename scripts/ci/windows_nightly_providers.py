"""Run the five native journeys serially in a disposable hosted Windows VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PROVIDERS = {
    'claude': ('claude', 'claude-stream-json', 'CI_ANTHROPIC_API_KEY', 'CI_CLAUDE_MODEL'),
    'codex': ('codex', 'codex-app-server', 'CI_OPENAI_API_KEY', 'CI_CODEX_MODEL'),
}
KEYS = ('CI_ANTHROPIC_API_KEY', 'CI_OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY')


def clean_environment():
    # Let Windows PowerShell construct its own module path, even under pwsh.
    return {key: value for key, value in os.environ.items()
            if key.upper() not in KEYS and key.upper() != 'PSMODULEPATH'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def require_safe_output(outputs, values):
    secrets = [encoded for value in values for encoded in
               (value.encode('utf-8'), json.dumps(value, ensure_ascii=True)[1:-1].encode('utf-8'))]
    require(all(secret not in data for secret in secrets for data in outputs),
            'Result contains credential material and cannot be published')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepared(provider, root, archive, archive_sha, commit, seed):
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
    image = Path(executable).resolve()
    version = subprocess.run([str(image), '--version'], env=clean_environment(), stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=60, check=True).stdout.strip()
    require(bool(version) and len(version) <= 1024, 'Provider version is unavailable')
    config = root / (provider + '.toml')
    config.write_text('[providers.' + provider + ']\ncommand = ' + json.dumps(str(image))
                      + '\nmodel = ' + json.dumps(model) + '\nprofile = "nightly"\n'
                      + '[profiles.nightly]\nsandbox = "workspace-write"\n'
                      + 'approval = "never"\nnetwork = true\nbypass = false\n', encoding='utf-8')
    profile = dict(name='nightly', sandbox='workspace-write', approval='never', network=True, bypass=False)
    manifest = {'schema': 'se.harness-matrix-input/v1', 'harnesses': [
        {'id': provider, 'driver': driver, 'platforms': {'win32': {
            'credential_seed': seed, 'configuration': {'path': str(config), 'sha256': digest(config)},
            'permission_profile': profile, 'images': [{'path': str(image), 'sha256': digest(image)}],
            'version_command': [str(image), '--version'], 'version_stdout': version}}}],
        'windows_journeys': {'release': {'path': str(archive), 'sha256': archive_sha, 'source_commit': commit}}}
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
                             '--cycle', os.environ['GITHUB_RUN_ID'], '--out', str(output)],
                            env=clean_environment(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=7200)
    receipt_path = output / 'results.json'
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    phases = receipt.get('phases', {})
    rows.append({'provider': provider, 'exit': result.returncode, 'result': receipt.get('result'),
                 'receipt_sha256': digest(receipt_path),
                 'phases': {key: phases.get(key, {}).get('result', 'NOT RUN') for key in ('J1','J2','J3','J4','J5')},
                 'release': receipt.get('release'), 'credential_closure': receipt.get('credential_closure'),
                 'process_closure': receipt.get('process_closure')})

    summary = {'schema': 'se.windows-nightly-providers/v1', 'source_commit': commit,
               'workflow_run_id': os.environ['GITHUB_RUN_ID'], 'release_run_id': args.release_run_id,
               'archive_sha256': args.archive_sha256, 'providers': rows}
    summary_bytes = (json.dumps(summary, indent=2) + '\n').encode('utf-8')
    receipts = {row['provider']: (root / (row['provider'] + '-journey') / 'results.json').read_bytes()
                for row in rows}
    require_safe_output([summary_bytes, *receipts.values()], [os.environ[name] for name in KEYS if os.environ.get(name)])
    publish = root / 'publish'
    publish.mkdir()
    (publish / 'summary.json').write_bytes(summary_bytes)
    for provider, data in receipts.items():
        destination = publish / (provider + '-journey')
        destination.mkdir()
        (destination / 'results.json').write_bytes(data)
    return 0 if (len(rows) == 1 and all(row['exit'] == 0 and row['result'] == 'PASS'
               and row['process_closure'] == [] and isinstance(row['credential_closure'], dict)
               and row['credential_closure'].get('delivery') == ('environment' if row['provider'] == 'claude' else 'private-file')
               and row['credential_closure'].get('private_copy_absent') is True
               and row['credential_closure'].get('refresh_tokens_copied') is False
               and isinstance(row['release'], dict) and row['release'].get('archive_sha256') == args.archive_sha256
               and row['release'].get('source_commit') == commit
               and all(value == 'PASS' for value in row['phases'].values()) for row in rows)) else 1


if __name__ == '__main__':
    raise SystemExit(main())
