"""Native per-journey token observations; absent usage is never reported as zero."""
import json
from pathlib import Path
import stat
import time

from harness_matrix.io import require


def snapshot(home, provider):
    root = Path(home) / ('.claude/projects' if provider == 'claude' else '.codex/sessions')
    rows, found = {}, False
    if not root.exists():
        return dict(files={}, observed=False, observed_at=time.time())
    total = 0
    for path in sorted(root.rglob('*.jsonl')):
        for ancestor in [path, *path.relative_to(root).parents]:
            candidate = ancestor if ancestor.is_absolute() else root / ancestor
            info = candidate.lstat()
            require(not stat.S_ISLNK(info.st_mode)
                    and not getattr(info, 'st_file_attributes', 0) & 0x400,
                    'Native usage input contains a link or reparse point')
        require(path.is_file(), 'Native usage input is not a plain file')
        total += path.stat().st_size
        require(total <= 256 * 1024**2 and path.stat().st_size <= 32 * 1024**2,
                'Native usage observation exceeds its finite bound')
        usage, events = {}, {}
        with path.open(encoding='utf-8') as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                except ValueError:
                    require(not line.endswith('\n'), 'Complete native usage record is malformed')
                    continue
                if provider == 'claude':
                    message = row.get('message', {})
                    if not isinstance(message, dict):
                        continue
                    value = message.get('usage')
                    identity = message.get('id') or row.get('uuid')
                    if not isinstance(value, dict) or not isinstance(identity, str):
                        continue
                    events[identity] = {name: count for name, count in value.items()
                                        if name.endswith('_tokens') and type(count) is int and count >= 0}
                else:
                    payload = row.get('payload', {})
                    if not isinstance(payload, dict) or payload.get('type') != 'token_count':
                        continue
                    value = (payload.get('info') or {}).get('total_token_usage')
                    if isinstance(value, dict):
                        usage = {name: count for name, count in value.items()
                                 if name.endswith('_tokens') and type(count) is int and count >= 0}
        if provider == 'claude':
            for value in events.values():
                for name, count in value.items():
                    usage[name] = usage.get(name, 0) + count
        if usage:
            rows[str(path.relative_to(root))] = usage
            found = True
    return dict(files=rows, observed=found, observed_at=time.time())


def difference(before, after, provider_used):
    counts = {}
    for name, initial in before['files'].items():
        require(name in after['files'], 'Native usage evidence disappeared')
        for key, value in initial.items():
            require(after['files'][name].get(key, -1) >= value,
                    'Native cumulative usage decreased or became unreadable')
    for name, final in after['files'].items():
        initial = before['files'].get(name, {})
        for key, value in final.items():
            counts[key] = counts.get(key, 0) + value - initial.get(key, 0)
    if provider_used and (not after['observed'] or not any(counts.values())):
        return dict(state='unavailable', reason='No new native provider usage record was observed',
                    partial_counters=counts)
    return dict(state='observed' if provider_used else 'observed-background' if any(counts.values())
                else 'not-used', counters=counts,
                interval=[before['observed_at'], after['observed_at']],
                boundary='Native transcript counters; cached/reasoning subsets are not added twice')
