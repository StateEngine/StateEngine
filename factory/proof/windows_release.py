"""Request or reuse a hosted release for the exact nightly source."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import tomllib
from urllib.parse import quote


def gh(*args, body=None, env=None):
    result = subprocess.run(['gh', *args], input=json.dumps(body) if body is not None else None,
                            stdin=subprocess.DEVNULL if body is None else None, capture_output=True,
                            text=True, timeout=90, check=False, env=env)
    if result.returncode:
        raise RuntimeError('hosted release request failed; check workflow access')
    return result.stdout


def prepare(config, source, commit, started_at):
    settings = config.get('windows')
    if settings is None:
        return None
    repository, ref = settings.get('release_repository'), settings.get('release_ref')
    if (not isinstance(repository, str) or
            not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or
            not isinstance(ref, str) or not re.fullmatch(r'[A-Za-z0-9_./-]+', ref) or
            not re.fullmatch(r'[a-f0-9]{40}', commit)):
        raise ValueError('hosted release repository, branch, and full source commit are required')
    from github_access import environment
    env = environment(settings)
    started = datetime.fromisoformat(started_at.replace('Z', '+00:00')).replace(microsecond=0)
    if started.tzinfo is None:
        raise ValueError('nightly start must include its timezone')
    label = 'nightly-' + started.astimezone(timezone.utc).date().isoformat()
    rows = json.loads(gh('run', 'list', '--repo', repository, '--workflow', 'release.yml',
                         '--limit', '100', '--json',
                         'databaseId,headSha,status,conclusion,createdAt,displayTitle', env=env))
    named = [row for row in rows if row.get('displayTitle') == label]
    if len(named) > 1:
        raise RuntimeError('the nightly release identity is duplicated')
    for row in named:
        created = datetime.fromisoformat(row['createdAt'].replace('Z', '+00:00'))
        if created.tzinfo is None:
            raise ValueError('hosted release creation time has no timezone')
        complete = row.get('status') == 'completed' and row.get('conclusion') == 'success'
        building = row.get('status') in ('queued', 'in_progress', 'waiting', 'pending', 'requested')
        if (created >= started and row.get('headSha') == commit and row.get('displayTitle') == label
                and (complete or building)
                and type(row.get('databaseId')) is int and row['databaseId'] > 0):
            return {'state': 'available' if complete else 'building',
                    'run_id': str(row['databaseId']), 'source_commit': commit}
        raise RuntimeError('the named nightly release is failed, stale or pinned to another source')
    branch = json.loads(gh('api', f'repos/{repository}/commits/{quote(ref, safe="")}', env=env))
    if branch.get('sha') != commit:
        raise RuntimeError('release branch moved after the nightly source was pinned')
    version = tomllib.loads((Path(source) / 'Cargo.toml').read_text())['workspace']['package']['version']
    if not isinstance(version, str) or not re.fullmatch(r'[A-Za-z0-9.+-]+', version):
        raise ValueError('workspace release version is invalid')
    response = json.loads(gh('api', '--method', 'POST', '-H', 'X-GitHub-Api-Version: 2026-03-10',
                             f'repos/{repository}/actions/workflows/release.yml/dispatches', '--input', '-',
                             body={'ref': ref, 'inputs': {'version': version, 'nightly': label},
                                   'return_run_details': True}, env=env))
    run_id = response.get('workflow_run_id')
    if type(run_id) is not int or run_id <= 0:
        raise RuntimeError('hosted release dispatch returned no run identity')
    return {'state': 'requested', 'source_commit': commit, 'run_id': str(run_id), 'label': label}
