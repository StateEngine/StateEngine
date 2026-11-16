"""Public MCP witness while zero or two controlled native forwards remain quiet."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
from kept_open_writes import Rpc


def process_rows(pid):
    script = ("$ErrorActionPreference='Stop'; $rows=@(Get-CimInstance Win32_Process "
              f"-Filter 'ProcessId={int(pid)}' -ErrorAction Stop | "
              "Select-Object ProcessId,ExecutablePath,CommandLine,CreationDate); "
              "ConvertTo-Json -InputObject $rows -Compress")
    done = subprocess.run(['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
                           '-Command', script], capture_output=True, timeout=20)
    if done.returncode != 0:
        raise ValueError('native process observation unreadable')
    rows = json.loads(done.stdout)
    if not isinstance(rows, list):
        raise ValueError('native process observation did not return an array')
    return rows


def helpers(count):
    directory = Path(os.environ['SE_FORWARD_WITNESS_DIR'])
    records = []
    expected = os.path.normcase(os.path.realpath(os.environ['SE_FORWARD_WITNESS_BINARY']))
    for path in sorted(directory.glob('forward-*.json')):
        raw = path.read_bytes()
        if len(raw) > 4096:
            raise ValueError('forward receipt exceeds bound')
        receipt = json.loads(raw)
        rows = process_rows(receipt['pid'])
        if len(rows) != 1:
            raise ValueError('controlled forward was absent before the public request')
        process = rows[0]
        if (process['ProcessId'] != receipt['pid'] or not process['CreationDate']
                or os.path.normcase(os.path.realpath(process['ExecutablePath'])) != expected):
            raise ValueError('forward native process identity mismatch')
        command = process['CommandLine']
        mapping = f"127.0.0.1:{receipt['port']}:127.0.0.1:9"
        if not all(value in command for value in ['-N', '-T', '-L', 'forward-witness', mapping]):
            raise ValueError('controlled forward native command line mismatch')
        records.append({'receipt': receipt, 'native_process': process})
    if len(records) != count or len({r['receipt']['pid'] for r in records}) != count:
        raise ValueError('forward count differs from independent native observation')
    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--se', required=True)
    parser.add_argument('--home', required=True)
    args = parser.parse_args()
    data = json.load(sys.stdin)
    client = data['client']
    count = data['forward_count']
    report = {'qualified': False, 'outcome': 'unknown', 'verified_events': 0,
              'replays_verified': 0, 'forward_count': count}
    rpc = None
    try:
        report['helpers'] = helpers(count)
        started = time.perf_counter_ns()
        try:
            rpc = Rpc(args.se, args.home, client['capability'])
        except Exception as error:
            message = str(error)
            report['elapsed_ms'] = (time.perf_counter_ns() - started) / 1e6
            report['error'] = message
            # Do not treat unrelated setup errors, missing output or arbitrary
            # failures as the targeted native IPC starvation counterexample.
            if count == 2 and 'ipc-unavailable' in message and 'read header: timed out' in message:
                report.update(qualified=True, outcome='ipc-stalled')
            raise
        status, _ = rpc.tool('stateengine_status', {})
        if status['runtime']['state'] != 'running' or not status['runtime']['generation']:
            raise ValueError('public status did not witness the running host')
        generation = str(status['runtime']['generation'])
        working, _ = rpc.tool('stateengine_working_state_get', {})
        value = working['value']
        if value['state'] == 'absent':
            revision = 'absent'
        elif value['state'] == 'present':
            revision = value['value']['revision']
        else:
            raise ValueError('working state unreadable or unknown')
        receipts = []
        for name in ['stateengine_msg_send', 'stateengine_working_state_set']:
            key = 'forward-' + uuid.uuid4().hex
            body = 'forward worker witness ' + key
            arguments = ({'to': client['to'], 'body': body, 'idempotency_key': key}
                         if name.endswith('msg_send') else
                         {'text': body, 'expect': revision, 'idempotency_key': key})
            receipt, elapsed = rpc.tool(name, arguments)
            if (receipt['state'] != 'committed' or receipt['idempotency_key'] != key
                    or receipt['writer']['mode'] != 'host'
                    or receipt['writer']['host_generation'] != generation):
                raise ValueError('public write receipt mismatch')
            if name.endswith('working_state_set') and receipt['revision'] != (1 if revision == 'absent' else revision + 1):
                raise ValueError('working revision did not advance once')
            receipts.append((name, arguments, receipt, elapsed))
        reader = Rpc(args.se, args.home, client['capability'])
        try:
            for name, arguments, receipt, elapsed in receipts:
                event, _ = reader.tool('stateengine_event_read', {'event_id': receipt['event_id']})
                if event['event_id'] != receipt['event_id'] or event['writer'] != receipt['writer']:
                    raise ValueError('outside immutable event identity mismatch')
                body = arguments.get('body', arguments.get('text'))
                if event['payload']['body']['sha256'] != hashlib.sha256(body.encode()).hexdigest():
                    raise ValueError('outside immutable body mismatch')
                if name.endswith('msg_send') and event['payload']['message_id'] != receipt['message_id']:
                    raise ValueError('outside message identity mismatch')
                report['verified_events'] += 1
        finally:
            reader.close()
        for name, arguments, receipt, elapsed in receipts:
            replay, _ = rpc.tool(name, arguments)
            fields = ['schema', 'idempotency_key', 'event_id', 'writer']
            fields.append('message_id' if name.endswith('msg_send') else 'revision')
            if replay['state'] != 'replayed' or any(replay[k] != receipt[k] for k in fields):
                raise ValueError('original-key retry changed committed identity')
            report['replays_verified'] += 1
        report['writes'] = [{'operation': name, 'ms': elapsed, 'receipt': receipt}
                            for name, _, receipt, elapsed in receipts]
        report['elapsed_ms'] = (time.perf_counter_ns() - started) / 1e6
        report.update(qualified=True, outcome='responded')
    except Exception as error:
        report.setdefault('error', repr(error))
    finally:
        if rpc is not None:
            try:
                rpc.close()
            except Exception as error:
                report.update(qualified=False, cleanup_error=repr(error))
        output = json.dumps(report, indent=2).replace(client['capability'], '<synthetic-capability>')
        print(output)
    return 0 if report['qualified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
