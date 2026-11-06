"""Bug: 532e5c28 — stop receipts must distinguish a clean provider exit from force.

Public CLI consumer with native Claude protocol fixtures; no paid provider.
The companion native dispatch test covers a stop dispatched after exact exit.
"""
import argparse
import fcntl
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).with_name('judges')))
from mail_cli import Fixture


def run(args):
    args.output.mkdir(parents=True, exist_ok=False)
    results, failures = [], []
    for mode, helper in [('clean', 'live_mail_provider.py'), ('force', 'mail_provider.py')]:
        f = Fixture(args.se, args.output / mode,
                    Path(__file__).with_name('judges') / helper, log_directory='calls')
        result = {'case': mode}
        try:
            runtime = f.ok('up')['process']['pid']
            birth = Path(f'/proc/{runtime}/stat').read_text().rsplit(')', 1)[1].split()[19]
            f.processes.append((runtime, birth))
            f.launch()
            stopped = f.ok('--project', f.project, 'stop', f.agent)
            result['stop'] = stopped
            expected = 'graceful' if mode == 'clean' else 'forced'
            assert stopped['complete'] and stopped['population'] == 'empty', stopped
            assert stopped['target']['provider'] == 'claude', stopped
            assert stopped['method'] == expected, stopped
            assert stopped['capture']['flushed'], stopped
            if mode == 'force':
                detail = stopped['witness']['detail']
                assert 'Signal' in detail and 'number: 9' in detail, detail
            repeated = f.ok('--project', f.project, 'stop', f.agent)
            result['repeated_stop'] = repeated
            assert repeated['result'] == 'already-stopped' and repeated['method'] is None, repeated
        except Exception as error:
            result['failure'] = repr(error)
            failures.append(mode + ': ' + repr(error))
        finally:
            results.append(result)
            (args.output / 'results.json').write_text(json.dumps(results, indent=2))
            try:
                f.close()
            except Exception as error:
                result['cleanup_failure'] = repr(error)
                (args.output / 'results.json').write_text(json.dumps(results, indent=2))
                raise
            assert not (f.home / 'endpoint.json').exists()
            with (f.home / 'runtime.lock').open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            outside = []
            for pid, birth in f.processes:
                path = Path(f'/proc/{pid}/stat')
                fields = path.read_text().rsplit(')', 1)[1].split() if path.exists() else None
                assert fields is None or fields[19] != birth or fields[0] == 'Z'
                outside.append({'pid': pid, 'birth': birth,
                                'now_birth': fields[19] if fields else None,
                                'now_state': fields[0] if fields else None})
            result['outside'] = outside
            result['endpoint_absent'] = result['runtime_lease_free'] = True
            (args.output / 'results.json').write_text(json.dumps(results, indent=2))
    print(f'public provider stop: {2 - len(failures)} passed; {len(failures)} failed', flush=True)
    assert not failures, '\n'.join(failures)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    options.se, options.output = options.se.resolve(), options.output.resolve()
    run(options)
