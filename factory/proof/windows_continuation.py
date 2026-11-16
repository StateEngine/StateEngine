"""A separate scheduled service continues the same pinned nightly on Windows."""
import fcntl
from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
import re
import time

from windows_adapter import run as run_windows


def identity():
    value = os.environ.get('INVOCATION_ID', '')
    if not re.fullmatch('[a-f0-9]{32}', value):
        raise RuntimeError('Windows continuation requires a service invocation identity')
    return value


# One standing custody window a day, matching the timer. A second window would let a
# night publish Windows rows the Linux attempt never pinned.
CUSTODY_WINDOWS = ((13, 15),)
def first_standing_night(config):
    """The earliest night this continuation may serve, when the config names one.

    Deployment scheduling belongs to the deployment's configuration, not to public
    source: a hard-coded date here would be an operator default baked into the
    product. An absent key permits any date, which is the standing behaviour.
    """
    raw = (config.get("windows") or {}).get("first_night")
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError("windows.first_night must be an ISO date")
    return date.fromisoformat(raw)


def slot_deadline(now=None, config=None):
    """Reserve five minutes for joining the guest and restoring shared custody."""
    now = now or datetime.now(timezone.utc)
    now = now.astimezone(timezone.utc)
    first = first_standing_night(config) if config is not None else None
    if first is not None and now.date() < first:
        raise RuntimeError(
            f"the configured first Windows nightly is {first.isoformat()}; "
            f"this slot ({now.date().isoformat()}) is not its own")
    for start, end in CUSTODY_WINDOWS:
        if start <= now.hour < end:
            seconds = (now.replace(hour=end, minute=0, second=0, microsecond=0) - now).total_seconds()
            if seconds > 300:
                return time.monotonic() + seconds - 300
    hours = " or ".join(f"{start:02d}–{end:02d}" for start, end in CUSTODY_WINDOWS)
    raise RuntimeError(f'Windows continuation requires the {hours} UTC custody window')


def attempt(config, pointer):
    state = Path(config['state']).resolve()
    directory = Path(pointer['directory'])
    if directory.is_symlink() or not directory.resolve().is_relative_to(state):
        raise RuntimeError('Windows attempt is outside the configured nightly spool')
    record = json.loads((directory / 'run.json').read_text())
    if record.get('service_invocation_id') != pointer.get('service_invocation_id'):
        raise RuntimeError('Windows continuation names a different Linux attempt')
    return state, directory, record


def queue(config, directory, record):
    from lifecycle import save
    if not any(row.get('windows_probe') and row['state'] == 'planned'
               for row in record['invocations']):
        return
    if not all(record.get(name, {}).get('commit') for name in ('product', 'judge')):
        return  # Planned rows remain unavailable; no unpinned work may boot a VM.
    state = Path(config['state'])
    pointer = {'directory': str(directory), 'service_invocation_id': record['service_invocation_id']}
    pending = state / 'windows-pending.json'
    if pending.exists() and json.loads(pending.read_text()) != pointer:
        raise RuntimeError('A previous Windows continuation remains pending; its evidence is retained')
    save(pending, pointer)
    # The separately installed UTC timer consumes this pointer in a permitted
    # custody window. Finishing Linux never grants immediate VM admission.


def execute(config, finalize_only=False):
    from lifecycle import checkpoint, save
    from report import exit_status
    from windows_adapter import finalize
    service = identity()
    state = Path(config['state'])
    services = state / 'windows-services'
    services.mkdir(exist_ok=True, mode=0o700)
    mapping = services / (service + '.json')
    if not finalize_only:
        pending = state / 'windows-pending.json'
        if not pending.exists():
            save(mapping, {'empty': True})
            return 0
        # Give ExecStopPost an explicit no-admission mapping even if the clock
        # rejects this invocation before a nightly attempt is acquired.
        save(mapping, {'empty': True})
        deadline = slot_deadline()
        pointer = json.loads(pending.read_text())
        save(mapping, pointer)
    pointer = json.loads(mapping.read_text())
    if pointer == {'empty': True}:
        return 0
    state, directory, record = attempt(config, pointer)
    with (state / 'nightly.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Re-read after taking custody of the report; a queued service cannot
        # overwrite a result another finalizer published while it was starting.
        state, directory, record = attempt(config, pointer)
        if record.get('windows_service_invocation_id') not in (None, service):
            raise RuntimeError('Windows continuation already belongs to another service attempt')
        record['windows_service_invocation_id'] = service
        publish = lambda: checkpoint(state, directory, record, config)
        publish()
        try:
            if finalize_only:
                result = os.environ.get('SERVICE_RESULT')
                code = os.environ.get('EXIT_CODE')
                status = os.environ.get('EXIT_STATUS')
                record['windows_service_exit'] = {'result': result, 'code': code, 'status': status}
                from report import summarize
                expected = exit_status(summarize(record, directory))
                finished = all(row['state'] not in ('planned', 'running')
                               for row in record['invocations'] if row.get('windows_probe'))
                if (not finished or code != 'exited' or status != str(expected)
                        or result != ('success' if expected == 0 else 'exit-code')):
                    record['errors'].append(f'Windows service={result} exit={code}:{status}')
                for row in record['invocations']:
                    if row.get('windows_probe') and row['state'] == 'running':
                        finalize(config, record, directory, row)
            else:
                run_windows(config, record, directory, deadline, publish)
        except Exception as error:
            record['errors'].append('Windows continuation: ' + str(error))
        finally:
            for row in record['invocations']:
                if row.get('windows_probe') and row['state'] in ('planned', 'running'):
                    row.update(state='unavailable', exit=None,
                               error='Windows service ended before a complete native receipt')
            report = publish()
        pending = state / 'windows-pending.json'
        if pending.exists() and json.loads(pending.read_text()) == pointer:
            pending.unlink()
        return exit_status(report)
