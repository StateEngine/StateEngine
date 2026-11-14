"""Schedule native Windows scopes through the configured custody producer."""
import hashlib
import json
from pathlib import Path
import subprocess
import time
import uuid

from native import import_receipt

# These are the scopes the current native observer supports on Windows.
SCOPES = {('claude', 'wave-2'), ('claude', '4'), ('codex', '4')}


def plan(config):
    settings = config.get('windows')
    if settings is None:
        return []
    if not isinstance(settings, dict):
        raise ValueError('windows must name its custody producer and probe scopes')
    command = settings.get('producer_command')
    if (not isinstance(command, list) or not command
            or any(not isinstance(arg, str) or not arg for arg in command)
            or not Path(command[0]).is_absolute()):
        raise ValueError('Windows custody producer requires an absolute executable argv')
    probes = settings.get('probes', [['claude', 'wave-2'], ['claude', '4'], ['codex', '4']])
    if not isinstance(probes, list) or not 1 <= len(probes) <= len(SCOPES):
        raise ValueError('Windows requires one to three supported native probe scopes')
    rows = []
    seen = {(row.get('surface'), row.get('selection'))
            for row in config.get('native_receipts', []) if row.get('platform') == 'win32'}
    for probe in probes:
        if (not isinstance(probe, (list, tuple)) or len(probe) != 2
                or not all(isinstance(value, str) for value in probe)
                or tuple(probe) not in SCOPES):
            raise ValueError('Windows probes require Claude wave-2 or Claude/Codex journey 4')
        surface, selection = probe
        if (surface, selection) in seen:
            raise ValueError('Windows probe scope is duplicated')
        seen.add((surface, selection))
        rows.append({'platform': 'win32', 'surface': surface, 'selection': selection,
                     'output': f'windows-{surface}-{selection}', 'state': 'planned',
                     'exit': None, 'native_receipt': True, 'windows_probe': True})
    return rows


def invoke(argv, request, phase, log, timeout):
    with log.open('ab') as stream:
        # The producer owns VM admission and shutdown. Neither shell expansion
        # nor a timed-out SSH process grants this controller guest custody.
        child = subprocess.Popen([*argv, '--request', str(request), '--phase', phase],
                                 stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                                 close_fds=True)
        try:
            return child.wait(timeout=timeout)
        except BaseException:
            # An unreaped child retains this exact PID through exec and exit.
            if child.poll() is None:
                command = Path('/proc', str(child.pid), 'cmdline').read_bytes()
                if not command:
                    raise RuntimeError('Producer command identity is unreadable; custody retained')
                child.kill()
            child.wait(timeout=10)
            raise


def run(config, record, directory, deadline, checkpoint):
    rows = [row for row in record['invocations'] if row.get('windows_probe')]
    if not rows:
        return
    settings = config['windows']
    timeout = settings.get('timeout_seconds', 7200)
    if type(timeout) is not int or not 60 <= timeout <= 14400:
        raise ValueError('Windows producer timeout must be 60..14400 seconds')
    for row in rows:
        if deadline - time.monotonic() <= 300:
            row.update(state='unavailable', error='whole-run deadline before Windows custody admission')
            checkpoint()
            continue
        stage = directory / (row['output'] + '-producer')
        stage.mkdir(mode=0o700)
        request = {'schema': 'se.windows-nightly-request/v1', 'attempt': str(uuid.uuid4()),
                   'run_started_at': record['started_at'],
                   'service_invocation_id': record.get('service_invocation_id'),
                   'platform': 'win32', 'surface': row['surface'], 'selection': row['selection'],
                   'product': record['product'], 'judge': record['judge'],
                   'reporter_directory': str(Path(__file__).resolve().parent),
                   'producer_config': {'node': config['node'], 'auth_home': config['auth_home'],
                       'credential_sources': config.get('credential_sources', {}),
                       'window_grant': settings.get('window_grant')},
                   'run_timeout_seconds': min(timeout, deadline - time.monotonic() - 300),
                   'output': str(stage / 'receipts'), 'custody_receipt': str(stage / 'custody.json')}
        request_path = stage / 'request.json'
        from lifecycle import save
        save(request_path, request)
        digest = hashlib.sha256(request_path.read_bytes()).hexdigest()
        row.update(state='running', request_sha256=digest)
        checkpoint()
        errors = []
        try:
            code = invoke(settings['producer_command'], request_path, 'run', stage / 'run.log',
                          min(timeout, deadline - time.monotonic() - 300))
            if code not in (0, 1):
                errors.append(f'Windows custody producer exited {code}')
        except Exception as error:
            errors.append(str(error))
        finally:
            finalize(config, record, directory, row, errors)
            checkpoint()


def finalize(config, record, directory, row, errors=()):
    """Retire the original producer request after normal exit or service death."""
    stage = directory / (row['output'] + '-producer')
    request_path = stage / 'request.json'
    try:
        raw = request_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != row.get('request_sha256'):
            raise RuntimeError('Windows finalizer request differs from its retained plan')
        request = json.loads(raw)
        if (request.get('product') != record.get('product')
                or request.get('judge') != record.get('judge')
                or request.get('surface') != row['surface']
                or request.get('selection') != row['selection']):
            raise RuntimeError('Windows finalizer source or scope differs from its retained plan')
        code = invoke(config['windows']['producer_command'], request_path, 'finalize',
                      stage / 'finalize.log', 240)
        if code:
            raise RuntimeError(f'Windows custody finalizer exited {code}')
        custody = json.loads((stage / 'custody.json').read_text())
        if (custody.get('schema') != 'se.windows-nightly-custody/v1'
                or custody.get('request_sha256') != row['request_sha256']
                or custody.get('attempt') != request['attempt']
                or custody.get('reservation_closed') is not True
                or custody.get('guest_processes_joined') is not True
                or custody.get('shared_guest_restored') is not True):
            raise RuntimeError('Windows custody closure is absent or differs from this request')
        if errors:
            raise RuntimeError('; '.join(errors))
        import_receipt(row, stage / 'receipts', directory, record, Path(config['state']))
    except Exception as error:
        row.update(state='unavailable', exit=None, error=str(error))
