"""Bind a scheduled provider job to the night's hosted release artifact."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

from nightly_release_validation import extract_artifact, validate


def gh(*args):
    return subprocess.check_output(['gh', *args], stdin=subprocess.DEVNULL, timeout=90)


def main():
    repository = os.environ['GITHUB_REPOSITORY']
    workflow_id = os.environ['GITHUB_RUN_ID']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not workflow_id.isdigit():
        raise RuntimeError('Scheduled workflow identity is invalid')
    schedule = json.loads(gh('api', f'repos/{repository}/actions/runs/{workflow_id}'))
    if (schedule.get('event') not in ('schedule', 'workflow_dispatch') or schedule.get('head_branch') != 'main'
            or schedule.get('head_sha') != os.environ.get('GITHUB_SHA')):
        raise RuntimeError('Scheduled main workflow identity differs')
    started = datetime.fromisoformat(schedule['created_at'].replace('Z', '+00:00')).astimezone(timezone.utc)
    label = 'nightly-' + started.date().isoformat() + '-' + workflow_id
    runs = json.loads(gh('run', 'list', '--repo', repository, '--workflow', 'release.yml',
                         '--event', 'workflow_dispatch', '--branch', 'main', '--limit', '100',
                         '--json', 'databaseId,displayTitle,headSha,createdAt,status,conclusion'))
    candidates = [run for run in runs if run.get('displayTitle') == label
                  and datetime.fromisoformat(run['createdAt'].replace('Z', '+00:00')).date() == started.date()
                  and not (run.get('status') == 'completed' and run.get('conclusion') == 'cancelled')]
    if not candidates:
        scheduled_head = os.environ.get('GITHUB_SHA')
        branch = json.loads(gh('api', f'repos/{repository}/commits/main'))
        if branch.get('sha') != scheduled_head:
            raise RuntimeError('Main moved after the nightly workflow was started')
        version = tomllib.loads(Path('Cargo.toml').read_text(encoding='utf-8'))['workspace']['package']['version']
        if not isinstance(version, str) or not re.fullmatch(r'[A-Za-z0-9.+-]+', version):
            raise RuntimeError('Workspace release version is invalid')
        body = json.dumps({'ref':'main','inputs':{'version':version,'nightly':label},'return_run_details':True})
        dispatched = subprocess.run(['gh','api','--method','POST','-H','X-GitHub-Api-Version: 2026-03-10',
                                     f'repos/{repository}/actions/workflows/release.yml/dispatches','--input','-'],
                                    input=body.encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=90, check=True)
        run_id = json.loads(dispatched.stdout).get('workflow_run_id')
        if type(run_id) is not int or run_id <= 0:
            raise RuntimeError('Nightly release dispatch returned no run identity')
        candidates = [{'databaseId':run_id, 'headSha':scheduled_head}]
    if len(candidates) != 1:
        raise RuntimeError('The scheduled night does not have exactly one named release run')
    release = candidates[0]
    run_id, commit = release.get('databaseId'), release.get('headSha')
    if (type(run_id) is not int or run_id <= 0 or not isinstance(commit, str)
            or not re.fullmatch('[a-f0-9]{40}', commit) or commit != os.environ.get('GITHUB_SHA')):
        raise RuntimeError('The release run has invalid identities')
    subprocess.run(['gh', 'run', 'watch', str(run_id), '--repo', repository, '--exit-status'],
                   stdin=subprocess.DEVNULL, timeout=10800, check=True)
    url = f'repos/{repository}/actions/runs/{run_id}'
    observed = json.loads(gh('api', url))
    if (observed.get('head_sha') != commit or observed.get('head_branch') != 'main'
            or observed.get('event') != 'workflow_dispatch' or observed.get('display_title') != label
            or observed.get('status') != 'completed'
            or observed.get('conclusion') != 'success'
            or str(observed.get('path', '')).split('@')[0] != '.github/workflows/release.yml'):
        raise RuntimeError('Hosted release did not finish successfully on the selected source')
    artifacts = json.loads(gh('api', url + '/artifacts')).get('artifacts', [])
    matches = [row for row in artifacts if row.get('name') == 'release-assets' and row.get('expired') is False]
    if len(matches) != 1:
        raise RuntimeError('The release has no unique retained artifact')
    item = matches[0]
    if (type(item.get('id')) is not int or item['id'] <= 0 or type(item.get('size_in_bytes')) is not int
            or not 0 < item['size_in_bytes'] <= 512 * 1024**2):
        raise RuntimeError('The hosted release artifact identity or size is invalid')
    root = Path(os.environ['RUNNER_TEMP']) / 'nightly-release'
    root.mkdir(mode=0o700, exist_ok=False)
    outer = root / 'outer.zip'
    with outer.open('xb') as output:
        subprocess.run(['gh', 'api', f'repos/{repository}/actions/artifacts/{item["id"]}/zip'],
                       stdin=subprocess.DEVNULL, stdout=output, timeout=600, check=True)
    if outer.stat().st_size != item['size_in_bytes']:
        raise RuntimeError('Downloaded release artifact size differs')
    archive = extract_artifact(outer, item.get('digest'), root / 'archive')
    validate(archive, commit)
    with archive.open('rb') as source:
        archive_sha = hashlib.file_digest(source, 'sha256').hexdigest()
    # These are non-secret immutable identifiers used by the next job.
    with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output:
        output.write(f'source_sha={commit}\nrelease_run_id={run_id}\narchive_sha256={archive_sha}\n')
        output.write(f'archive_path={archive}\n')


if __name__ == '__main__':
    main()
