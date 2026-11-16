"""Bounded, account-free hosted journey receipts and nightly source binding."""
import datetime
import hashlib
import json
from pathlib import Path
import re

NAMES = ('Install', 'Adopt', 'Come-back', 'Two-agents', 'Remove')


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.partial')
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
    temporary.replace(path)


def binding(value):
    require(isinstance(value, dict) and set(value) == {
        'schema', 'started_at', 'product_commit', 'judge_commit', 'linux_archive_sha256'}, 'Unexpected nightly binding fields')
    require(value['schema'] == 'se.nightly-binding/v1', 'Unknown nightly binding schema')
    for key in ('product_commit', 'judge_commit'):
        require(isinstance(value[key], str) and re.fullmatch('[0-9a-f]{40}', value[key]), 'An exact commit is required: ' + key)
    require(isinstance(value['linux_archive_sha256'], str) and re.fullmatch('[0-9a-f]{64}', value['linux_archive_sha256']),
            'The Linux nightly archive digest is required; never substitute another main build')
    started = datetime.datetime.fromisoformat(value['started_at'])
    require(started.utcoffset() == datetime.timedelta(0), 'Nightly time must include UTC')
    return value


def unread_provider(surface, reason):
    require(surface in ('claude', 'codex'), 'Unknown provider')
    return dict(schema='se.hosted-five-journeys/v1', surface=surface, result='NOT RUN',
                qualification='Real provider coverage is unmeasured; account-free probes do not replace it',
                rows=[dict(journey=i + 1, name=name, result='NOT RUN', behavior='NOT RUN', reason=reason)
                      for i, name in enumerate(NAMES)])
