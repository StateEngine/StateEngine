"""Synthetic Claude stream/transcript producer with a same-boot monotonic clock."""
import json
import os
from pathlib import Path
import sys
import socket
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'crates/se/tests/judges'))
import mail_provider


def produce():
    repo = Path.cwd()
    ready = json.loads((repo / 'provider-ready.json').read_text())
    conversation = ready['conversation']
    matches = list((Path(os.environ['HOME']) / '.claude/projects').rglob(conversation + '.jsonl'))
    if len(matches) != 1:
        raise ValueError('Expected one native transcript')
    transcript = matches[0]
    delay_file = repo / 'result-delay-ms'
    delay_ms = int(delay_file.read_text()) if delay_file.exists() else 0
    endpoint = json.loads((repo / 'output-control.json').read_text())
    connection = socket.create_connection(('127.0.0.1', endpoint['port']), timeout=30)
    connection.settimeout(30)
    connection.sendall((endpoint['nonce'] + '\n').encode())
    with connection, connection.makefile('r') as control, (repo / 'producer.jsonl').open('a', buffering=1) as log:
        for line in control:
            marker = line.strip()
            if len(marker) != 18 or not marker.startswith('output-probe-') or not marker[-5:].isdigit():
                raise ValueError('Invalid synthetic observation ID')
            record = {'type': 'assistant', 'sessionId': conversation, 'uuid': marker,
                      'message': {'role': 'assistant', 'content': [{'type': 'text', 'text': marker}]}}
            before = time.monotonic_ns()
            with transcript.open('a') as output:
                output.write(json.dumps(record) + '\n')
                output.flush()
            written = time.monotonic_ns()
            print(json.dumps({'type': 'assistant', 'session_id': conversation,
                              'message': record['message']}), flush=True)
            assistant_streamed = time.monotonic_ns()
            if delay_ms:
                time.sleep(delay_ms / 1000)
            print(json.dumps({'type': 'result', 'session_id': conversation, 'result': marker,
                              'is_error': False}), flush=True)
            streamed = time.monotonic_ns()
            log.write(json.dumps({'id': marker, 'emit_begin_ns': before,
                                  'transcript_flushed_ns': written,
                                  'assistant_stream_flushed_ns': assistant_streamed,
                                  'stream_flushed_ns': streamed}) + '\n')
    while True:
        time.sleep(1)


if __name__ == '__main__':
    mail_provider.main(produce)
