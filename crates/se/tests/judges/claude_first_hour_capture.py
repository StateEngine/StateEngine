"""Replay first-turn native metadata through the public hook and capture consumer.

This is an isolated Linux protocol reproduction, not a real-provider first-hour
run. The default delays one accepted metadata write across the hook budget;
--no-delay-commit runs the same source and reader without that fault.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from mail_cli import Fixture


ANSWER = 'FIRST_TURN_CAPTURE_COMPLETE'


def hook(fixture, transcript, conversation, label):
    payload = {'session_id': conversation, 'transcript_path': str(transcript)}
    result = subprocess.run([str(fixture.se), '--home', str(fixture.home),
                             'hook', 'claude', 'stop'],
                            env={**fixture.env, 'SE_SESSION': fixture.session},
                            cwd=fixture.repo, input=json.dumps(payload).encode(),
                            capture_output=True, timeout=20)
    (fixture.log_root / (label + '.stdout')).write_bytes(result.stdout)
    (fixture.log_root / (label + '.stderr')).write_bytes(result.stderr)
    (fixture.log_root / (label + '.exit')).write_text(str(result.returncode))
    # Hook zero is an availability contract; history is the capture witness.
    return result


def history(f):
    page = f.ok('--project', f.project, 'history', '--kind', 'session.turn', '--limit', '100')
    assert page['window']['complete'] and page['next'] is None, page
    return page['items']


def run(f, gate=None):
    value = f.ok('--project', f.project, 'launch', f.agent, '--detach', '--task', 'Capture the first reply')
    assert value['state'] == 'running', value
    f.session = value['session_id']
    ready = json.loads((f.repo / 'provider-ready.json').read_text())
    transcript = Path(ready['path'])
    conversation = json.loads(transcript.read_text().splitlines()[0])['sessionId']
    if os.name == 'posix':
        owner = json.loads((f.home / 'endpoint.json').read_text())['epoch']['owner']
        pins = []
        for pid in (owner['pid'], ready['native_root_pid'], ready['helper_pid']):
            fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
            argv = Path(f'/proc/{pid}/cmdline').read_bytes()
            assert (pid == owner['pid'] or str(f.root).encode() in argv
                    or str(f.repo).encode() in argv), (pid, argv)
            pins.append({'pid': pid, 'birth': fields[19],
                         'image': str(Path(f'/proc/{pid}/exe').resolve()),
                         'argv': [os.fsdecode(x) for x in argv.split(b'\0') if x]})
            f.processes.append((pid, fields[19]))
        (f.log_root / 'process-identities.json').write_text(json.dumps(pins, indent=2))
    records = [{'type': 'mode', 'mode': 'default'}, {'type': 'permission-mode'}]
    for kind in ('session-owner', 'file-history-snapshot', 'attachment',
                 'file-history-snapshot', *(['attachment'] * 11), 'last-prompt'):
        records.append({'type': kind, 'fixture_padding': 'p' * (4000 if kind == 'attachment' else 100)})
    records.append({'type': 'mode'})
    for kind in ('atis-latch', 'api-request-shape', 'api-request-blob', 'api-request-blob',
                 'api-request', 'last-prompt', 'session-owner'):
        row = {'type': kind}
        if kind == 'api-request-shape':
            row['fixture_padding'] = 'x' * 85000
        records.append(row)
    records.append({'type': 'permission-mode'})
    records.extend([{'type': kind} for kind in ('session-owner', 'atis-latch', 'ai-title', 'tools-used')])
    for number in (1, 2):
        records.append({'type': 'assistant', 'uuid': f'tool-call-{number}', 'message': {
            'role': 'assistant', 'content': [{'type': 'tool_use', 'id': f'tool-{number}',
                'name': 'Read', 'input': {'file_path': str(f.repo / 'README.md')}}]}})
        records.append({'type': 'user', 'uuid': f'tool-result-{number}', 'message': {
            'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': f'tool-{number}',
                                       'content': 'Synthetic file result'}]}})
        if number == 1:
            records.append({'type': 'attachment', 'fixture_padding': 'q' * 129000})
        records.extend([{'type': kind} for kind in ('api-request', 'last-prompt', 'ai-title',
                          'mode', 'permission-mode', 'session-owner', 'atis-latch', 'tools-used')])
    with transcript.open('a') as output:
        for record in records:
            record['sessionId'] = conversation
            output.write(json.dumps(record) + '\n')
        output.flush()
        os.fsync(output.fileno())
    # No streamed result wakes the coordinator here: attended providers use
    # lifecycle hooks after writing this same bound native source.
    with transcript.open('a') as output:
        output.write(json.dumps({'type': 'assistant', 'sessionId': conversation,
            'uuid': 'first-complete-reply', 'message': {'role': 'assistant',
                                                     'content': ANSWER}}) + '\n')
        output.flush()
        os.fsync(output.fileno())
    if gate:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(hook, f, transcript, conversation, 'first-hook')
            until = time.monotonic() + 15
            while not (gate / 'capture-write-accepted').exists():
                assert not pending.done(), pending.result().stderr
                assert time.monotonic() < until, 'capture write barrier was not reached'
                time.sleep(.02)
            # Cross the hook's five-second budget, then let its accepted native
            # write finish. The source and its original identities stay intact.
            time.sleep(6)
            (gate / 'release').touch()
            result = pending.result()
        assert (gate / 'capture-write-returned').exists()
        assert not (gate / 'barrier-expired').exists(), 'barrier self-expired'
    else:
        result = hook(f, transcript, conversation, 'first-hook')
    rows = history(f)
    replies = [r for r in rows if r['payload']['role'] == 'assistant']
    until = time.monotonic() + 5
    while not replies and time.monotonic() < until:
        time.sleep(.25)
        rows = history(f)
        replies = [r for r in rows if r['payload']['role'] == 'assistant']
    (f.log_root / 'captured-turns.json').write_text(json.dumps(rows, indent=2))
    observed = f.ok('--project', f.project, 'agent', 'show', f.agent)
    (f.log_root / 'before-stop-agent.json').write_text(json.dumps(observed, indent=2))
    if gate and not replies:
        assert b'commit-outcome-unknown' in result.stderr, result.stderr
        assert 'CaptureIncomplete' in json.dumps(observed), observed
    assert len(replies) == 1 and replies[0]['payload']['body']['text'] == ANSWER, result.stderr
    original = replies[0]['event_id']
    again = hook(f, transcript, conversation, 'repeat-hook')
    replies = [r for r in history(f) if r['payload']['role'] == 'assistant']
    assert len(replies) == 1 and replies[0]['event_id'] == original, again.stderr
    shown = f.ok('--project', f.project, 'agent', 'show', f.agent)
    assert 'CaptureIncomplete' not in json.dumps(shown), shown
    print('ok 1 - first native reply survives metadata and a repeated public hook', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--delay-commit', action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('this native write-boundary reproduction requires Linux')
    f = Fixture(args.se, args.workspace or args.output,
                Path(__file__).with_name('claude_first_hour_provider.py'),
                log_directory=str(args.output.resolve()) if args.workspace else None)
    foreground = None
    gate = None
    if args.delay_commit:
        gate = f.log_root / 'gate'
        gate.mkdir()
        library = f.log_root / 'barrier.so'
        source = Path(__file__).with_name('capture_stop_barrier.c')
        subprocess.run(['cc', '-std=c11', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                        '-O2', str(source), '-o', str(library)], check=True,
                       capture_output=True, timeout=30)
        f.env.update(LD_PRELOAD=str(library), CAPTURE_ORDER_GATE=str(gate),
                     CAPTURE_ORDER_HOME=str(f.home), CAPTURE_ORDER_TURN='api-request-shape')
        log = (f.log_root / 'foreground.log').open('wb')
        foreground = subprocess.Popen([str(f.se), '--home', str(f.home), 'up', '--foreground', '--json'],
                                     env=f.env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        until = time.monotonic() + 30
        while not (f.home / 'endpoint.json').exists():
            assert foreground.poll() is None, 'foreground host exited before endpoint publication'
            assert time.monotonic() < until, 'foreground host did not publish'
            time.sleep(.02)
        process = Path('/proc') / str(foreground.pid)
        assert process.joinpath('exe').resolve() == f.se
        argv = process.joinpath('cmdline').read_bytes().split(b'\0')
        assert str(f.home).encode() in argv and b'--foreground' in argv, argv
        owner = json.loads((f.home / 'endpoint.json').read_text())['epoch']['owner']
        fields = process.joinpath('stat').read_text().rsplit(') ', 1)[1].split()
        assert owner['pid'] == foreground.pid and str(owner['started']['start_ticks']) == fields[19]
        assert str(library) in process.joinpath('maps').read_text(), 'barrier not mapped in owned host'
        (gate / 'host-pid').write_text(str(foreground.pid))
    print('1..1', flush=True)
    try:
        run(f, gate)
    except Exception:
        print('not ok 1 - first reply capture must finish after temporary writer delay', flush=True)
        raise
    finally:
        if gate:
            (gate / 'release').touch()
        f.close()
        (f.log_root / 'post-down-turns.json').write_text(json.dumps(history(f), indent=2))
        if foreground:
            assert foreground.wait(timeout=30) == 0, 'foreground runtime cleanup failed'
            log.close()


if __name__ == '__main__':
    main()
