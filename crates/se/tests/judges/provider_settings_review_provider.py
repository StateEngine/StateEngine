"""Native protocol doubles: record only non-secret launch selections."""
import json
import os
from pathlib import Path
import sys


def record(row):
    row.update(native_root_pid=os.getppid(), helper_pid=os.getpid(),
               session=os.environ.get('SE_SESSION'))
    with Path('settings-observed.jsonl').open('a') as stream:
        stream.write(json.dumps(row) + '\n')
        stream.flush()


def codex():
    import codex_recovery_provider as protocol
    receive, send = protocol.receive, protocol.send
    requests = {}

    def read(stream):
        opcode, body = receive(stream)
        if opcode == 1:
            value = json.loads(body)
            method, params = value.get('method'), value.get('params', {})
            if method in ('thread/start', 'thread/resume') and 'config' in params:
                config = params['config']
                selected = {key: config[key] for key in (
                    'model_provider', 'model_reasoning_effort', 'model_context_window')
                    if key in config}
                provider = config.get('model_provider')
                if provider:
                    selected['route'] = config.get('model_providers', {}).get(provider)
                record({'provider': 'codex', 'method': method,
                        'modelProvider': params.get('modelProvider'), 'config': selected})
                requests[value['id']] = params
            elif method == 'turn/start':
                record({'provider': 'codex', 'method': method,
                        'effort': params.get('effort')})
        return opcode, body

    def write(stream, body, opcode=1):
        if opcode == 1:
            value = json.loads(body)
            params = requests.get(value.get('id'))
            if params and 'result' in value:
                # Native app-server echoes the selected provider and effort.
                result = value['result']
                result['modelProvider'] = params.get('modelProvider')
                result['reasoningEffort'] = params['config'].get('model_reasoning_effort')
                body = json.dumps(value).encode()
        send(stream, body, opcode)

    protocol.receive, protocol.send = read, write
    protocol.main()


if __name__ == '__main__':
    if 'app-server' in sys.argv[1:]:
        codex()
    else:
        import launch_continuity_provider
        arguments = sys.argv[3:]
        flag = '--resume' if '--resume' in arguments else '--session-id'
        effort = arguments[arguments.index('--effort') + 1] if '--effort' in arguments else None
        record({'provider': 'claude', 'method': flag, 'effort': effort,
                'conversation': arguments[arguments.index(flag) + 1]})
        launch_continuity_provider.main()
