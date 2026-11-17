"""Import and recheck the scheduled protected Windows provider evidence."""
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import time
import zipfile

MAX_ARTIFACT = 16 * 1024**2
PHASES = ('J1', 'J2', 'J3', 'J4', 'J5')


def plan(config):
    settings = config.get('windows')
    if settings is None:
        return []
    if (not isinstance(settings, dict) or
            not re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', str(settings.get('release_repository', ''))) or
            not re.fullmatch('[a-f0-9]{64}', str(settings.get('provider_workflow_sha256', '')))):
        raise ValueError('Windows nightly requires the release repository and reviewed workflow digest')
    return [{'platform': 'win32', 'surface': surface, 'selection': 'windows-journeys',
             'output': f'windows-{surface}-journeys', 'state': 'planned', 'exit': None,
             'hosted_provider': True} for surface in ('claude', 'codex')]


def gh(*args, env=None):
    return subprocess.check_output(['gh', *args], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=20, env=env)


def verify_runner(receipt, run):
    """The retained receipt must name every script in the pinned checkout."""
    product = run.get('product') or {}
    tree, commit = product.get('worktree'), product.get('commit')
    if not isinstance(tree, str) or not Path(tree).is_absolute() or not re.fullmatch('[a-f0-9]{40}', str(commit)):
        raise ValueError('pinned provider runner checkout is unavailable')
    def git(*args):
        try:
            return subprocess.check_output(['git', '-C', tree, *args], stdin=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL, timeout=20)
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError('pinned provider runner source is unreadable') from error
    if git('rev-parse', 'HEAD').decode().strip() != commit:
        raise ValueError('provider runner checkout differs from the product pin')
    entries = git('ls-tree', '-r', '--name-only', commit, '--', 'scripts/windows_journeys').decode().splitlines()
    names = {entry.removeprefix('scripts/') for entry in entries
             if entry.endswith('.py') or entry.endswith('/terminal.ps1')}
    names.update({'windows-journeys.py', 'harness-matrix.py', 'harness-matrix-report.py',
                  'ci/installation_account.py', *['harness_matrix/' + name for name in
                  ('flow.py', 'inputs.py', 'io.py', 'report.py', 'native_processes.ps1')]})
    registry = '../crates/se-harness-registry/src/registry.json'
    names.add(registry)
    if not entries or set(receipt.get('runner_sha256', {})) != names:
        raise ValueError('provider runner source inventory differs from the product pin')
    for name in names:
        source = 'crates/se-harness-registry/src/registry.json' if name == registry else 'scripts/' + name
        expected = hashlib.sha256(git('show', commit + ':' + source)).hexdigest()
        if receipt['runner_sha256'].get(name) != expected:
            raise ValueError('provider runner source digest differs from the product pin')


def observation(inv, directory, run):
    """Re-read the original GitHub artifact and its two original receipts."""
    if (inv.get('platform') != 'win32' or inv.get('surface') not in ('claude', 'codex')
            or inv.get('selection') != 'windows-journeys'
            or inv.get('hosted_workflow_conclusion') not in ('success', 'failure')
            or inv.get('hosted_job_conclusion') not in ('success', 'failure')):
        raise ValueError('hosted provider plan or workflow outcome differs')
    path = Path(directory) / 'windows-hosted-proof.zip'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARTIFACT:
        raise ValueError('hosted provider artifact is absent or too large')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != inv.get('hosted_artifact_sha256'):
        raise ValueError('hosted provider artifact digest differs')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        names = [entry.filename for entry in infos]
        allowed = {'summary.json', 'claude-journey/results.json', 'codex-journey/results.json'}
        if len(names) != len(set(names)) or not set(names).issubset(allowed) or 'summary.json' not in names:
            raise ValueError('hosted provider artifact inventory differs')
        if any(entry.file_size > MAX_ARTIFACT for entry in infos) or sum(entry.file_size for entry in infos) > MAX_ARTIFACT:
            raise ValueError('hosted provider evidence exceeds its bound')
        summary = json.loads(archive.read('summary.json'))
        provider = inv['surface']
        provider_rows = summary.get('providers')
        if (not isinstance(provider_rows, list) or not all(isinstance(row, dict) for row in provider_rows)
                or any(row.get('provider') not in ('claude', 'codex') for row in provider_rows)
                or len({row.get('provider') for row in provider_rows}) != len(provider_rows)):
            raise ValueError('hosted provider inventory is invalid')
        matching = [row for row in provider_rows if row.get('provider') == provider]
        expected_run = str(inv.get('hosted_workflow_run_id', ''))
        release_id = (run.get('windows_release') or {}).get('run_id')
        if (summary.get('schema') != 'se.windows-nightly-providers/v1'
                or summary.get('source_commit') != (run.get('product') or {}).get('commit')
                or summary.get('workflow_run_id') != expected_run or not expected_run.isdigit()
                or summary.get('release_run_id') != release_id or not isinstance(release_id, str) or not release_id.isdigit()
                or not re.fullmatch('[0-9a-f]{64}', str(summary.get('archive_sha256', '')))
                or len(matching) != 1):
            raise ValueError('hosted provider evidence has a different source, release or scope')
        selected = matching[0]
        receipt_name = provider + '-journey/results.json'
        if receipt_name not in names:
            raise ValueError('hosted provider receipt is absent')
        receipt_raw = archive.read(receipt_name)
        if hashlib.sha256(receipt_raw).hexdigest() != selected.get('receipt_sha256'):
            raise ValueError('hosted provider receipt digest differs')
        receipt = json.loads(receipt_raw)
        verify_runner(receipt, run)
        phases = receipt.get('phases')
        if (receipt.get('harness') != provider or receipt.get('state') != 'finished'
                or receipt.get('result') != selected.get('result') or receipt.get('release') != selected.get('release')
                or receipt.get('credential_closure') != selected.get('credential_closure')
                or receipt.get('process_closure') != selected.get('process_closure') or not isinstance(phases, dict)
                or set(phases) != set(PHASES) or set(selected.get('phases', {})) != set(PHASES)
                or any(not isinstance(phases[key], dict) or phases[key].get('result') != selected['phases'][key]
                       or phases[key].get('result') not in ('PASS', 'FAIL', 'INCOMPLETE', 'NOT RUN') for key in PHASES)
                or type(selected.get('exit')) is not int or selected['exit'] not in (0, 1)):
            raise ValueError('hosted provider phase or exit evidence differs')
        release = receipt.get('release')
        passed = selected['result'] == 'PASS'
        if passed and (inv['hosted_workflow_conclusion'] != 'success' or inv['hosted_job_conclusion'] != 'success'
                       or selected['exit'] != 0 or any(phases[key]['result'] != 'PASS' for key in PHASES)
                       or any(not isinstance(phases[key].get('tokens'), dict)
                              or phases[key]['tokens'].get('state') not in ('observed', 'observed-background', 'not-used')
                              for key in PHASES)
                       or any(phases[key]['tokens']['state'] != 'observed' for key in ('J2', 'J3', 'J4'))
                       or not isinstance(release, dict) or release.get('source_commit') != summary['source_commit']
                       or release.get('archive_sha256') != summary['archive_sha256']
                       or receipt.get('process_closure') != []
                       or not isinstance(receipt.get('credential_closure'), dict)
                       or receipt['credential_closure'].get('delivery') != ('environment' if provider == 'claude' else 'private-file')
                       or receipt['credential_closure'].get('private_copy_absent') is not True
                       or receipt['credential_closure'].get('refresh_tokens_copied') is not False):
            raise ValueError('passing hosted provider evidence lacks release or closure proof')
        if not passed and (selected['exit'] != 1 or selected['result'] not in ('FAIL', 'INCOMPLETE')):
            raise ValueError('hosted provider result and exit disagree')
        return selected, phases


def acquire(config, run, directory, deadline, checkpoint):
    rows = [row for row in run['invocations'] if row.get('hosted_provider')]
    if not rows:
        return
    settings = config['windows']
    repo = settings['release_repository']
    started = datetime.fromisoformat(run['started_at']).astimezone(timezone.utc)
    try:
        from github_access import environment
        env = environment(settings)
        candidates = json.loads(gh('run', 'list', '--repo', repo, '--workflow', 'windows-nightly.yml',
                                   '--event', 'schedule', '--branch', 'main',
                                   '--limit', '100', '--json', 'databaseId,createdAt', env=env))
        candidates = [item for item in candidates if datetime.fromisoformat(item['createdAt'].replace('Z', '+00:00'))
                      >= started.replace(microsecond=0)]
        if len(candidates) != 1 or type(candidates[0].get('databaseId')) is not int:
            raise ValueError('this night has no unique scheduled provider workflow')
        workflow = candidates[0]['databaseId']
        remaining = int(deadline - time.monotonic())
        if remaining < 30:
            raise ValueError('provider workflow did not complete before the nightly deadline')
        # Watch the one identified workflow; a failed job can still upload a
        # truthful failing receipt, so its exit is inspected below.
        subprocess.run(['gh', 'run', 'watch', str(workflow), '--repo', repo, '--exit-status'],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=remaining, check=False, env=env)
        url = f'repos/{repo}/actions/runs/{workflow}'
        metadata = json.loads(gh('api', url, env=env))
        if (metadata.get('event') != 'schedule' or metadata.get('head_branch') != 'main'
                or metadata.get('status') != 'completed' or metadata.get('conclusion') not in ('success', 'failure')
                or str(metadata.get('path', '')).split('@')[0] != '.github/workflows/windows-nightly.yml'):
            raise ValueError('scheduled provider workflow has no witnessed final outcome')
        workflow_sha = settings.get('provider_workflow_sha256')
        head = metadata.get('head_sha')
        if (not isinstance(workflow_sha, str) or not re.fullmatch('[a-f0-9]{64}', workflow_sha)
                or not isinstance(head, str) or not re.fullmatch('[a-f0-9]{40}', head)):
            raise ValueError('reviewed provider workflow identity is unavailable')
        workflow_source = gh('api', f'repos/{repo}/contents/.github/workflows/windows-nightly.yml?ref={head}',
                             '-H', 'Accept: application/vnd.github.raw+json', env=env)
        if hashlib.sha256(workflow_source).hexdigest() != workflow_sha:
            raise ValueError('scheduled provider workflow differs from the reviewed workflow')
        jobs = json.loads(gh('api', url + '/jobs?per_page=100', env=env)).get('jobs', [])
        providers = [job for job in jobs if job.get('name') == 'providers']
        if (len(providers) != 1 or providers[0].get('status') != 'completed'
                or providers[0].get('conclusion') not in ('success', 'failure')):
            raise ValueError('protected provider job did not complete')
        release_rows = json.loads(gh('run', 'list', '--repo', repo, '--workflow', 'release.yml',
                                     '--event', 'workflow_dispatch', '--branch', 'main', '--limit', '100',
                                     '--json', 'databaseId,displayTitle,headSha,status,conclusion,createdAt', env=env))
        workflow_started = datetime.fromisoformat(metadata['created_at'].replace('Z', '+00:00'))
        if workflow_started.tzinfo is None:
            raise ValueError('scheduled workflow creation time has no timezone')
        label = 'nightly-' + workflow_started.astimezone(timezone.utc).date().isoformat() + '-' + str(workflow)
        releases = [row for row in release_rows if row.get('displayTitle') == label
                    and not (row.get('status') == 'completed' and row.get('conclusion') == 'cancelled')]
        if len(releases) != 1 or type(releases[0].get('databaseId')) is not int:
            raise ValueError('this night has no unique non-cancelled release')
        release = releases[0]
        source = (run.get('product') or {}).get('commit')
        if (release.get('headSha') != source or release.get('status') != 'completed'
                or release.get('conclusion') != 'success'):
            raise ValueError('nightly release is not a successful build of the pinned source')
        run['windows_release'] = {'state':'available','run_id':str(release['databaseId']),
                                  'source_commit':source,'label':label}
        artifacts = json.loads(gh('api', url + '/artifacts', env=env)).get('artifacts', [])
        matches = [item for item in artifacts if item.get('name') == 'windows-nightly-proof' and item.get('expired') is False]
        if len(matches) != 1:
            raise ValueError('provider workflow has no unique retained receipt')
        artifact = matches[0]
        if (type(artifact.get('id')) is not int or artifact['id'] <= 0 or type(artifact.get('size_in_bytes')) is not int
                or not 0 < artifact['size_in_bytes'] <= MAX_ARTIFACT
                or not re.fullmatch('sha256:[a-f0-9]{64}', str(artifact.get('digest', '')))):
            raise ValueError('hosted provider artifact identity is unavailable')
        raw = gh('api', f'repos/{repo}/actions/artifacts/{artifact["id"]}/zip', env=env)
        if len(raw) != artifact['size_in_bytes'] or hashlib.sha256(raw).hexdigest() != artifact['digest'][7:]:
            raise ValueError('downloaded provider artifact identity differs')
        destination = Path(directory) / 'windows-hosted-proof.zip'
        with destination.open('xb') as output:
            output.write(raw)
        for row in rows:
            row.update(hosted_workflow_run_id=str(workflow), hosted_artifact_sha256=artifact['digest'][7:],
                       hosted_workflow_conclusion=metadata['conclusion'],
                       hosted_job_conclusion=providers[0]['conclusion'])
            try:
                selected, _ = observation(row, directory, run)
                row.update(state='finished', exit=selected['exit'])
            except (ValueError, KeyError, OSError, TypeError, zipfile.BadZipFile) as error:
                row.update(state='unavailable', exit=None, error=str(error))
            checkpoint()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        for row in rows:
            if row['state'] != 'finished':
                row.update(state='unavailable', exit=None, error='hosted provider: ' + str(error))
        checkpoint()
