"""Record a nightly release request that the hosted workflow will fulfill."""
from datetime import datetime, timezone
import re


def prepare(config, source, commit, started_at):
    settings = config.get('windows')
    if settings is None:
        return None
    repository, ref = settings.get('release_repository'), settings.get('release_ref')
    if (not isinstance(repository, str) or
            not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or
            ref != 'main' or not isinstance(commit, str) or not re.fullmatch(r'[a-f0-9]{40}', commit)):
        raise ValueError('hosted release repository, main branch and full source commit are required')
    started = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
    if started.tzinfo is None:
        raise ValueError('nightly start must include its timezone')
    return {'state':'pending', 'source_commit':commit,
            'night':started.astimezone(timezone.utc).date().isoformat()}
