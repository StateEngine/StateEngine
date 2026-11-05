"""Exercise mail ID names over real authenticated stdio and HTTP MCP.

Run with --se EXACT_CANDIDATE --output NEW_OWNED_DIRECTORY. The existing mail
fixture owns its home and native provider double; no account or install is used.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'judges'))
from mail_cli import Fixture
from work_mail import Reader


def run(options):
    options.output.mkdir(parents=True, exist_ok=False)
    f = Fixture(options.se, options.output / 'owner', log_directory='calls')
    checks = []
    try:
        f.launch()
        argv = (f.repo / 'provider-argv.txt').read_text().splitlines()
        config = json.loads(Path(argv[argv.index('--mcp-config') + 1]).read_text())
        session = {'session_id': f.session, 'http': config['mcpServers']['stateengine']}
        reader = Reader(f, options.output)
        for action in ('read', 'ack', 'dismiss'):
            sent = f.mail('send', f.agent, 'First mail ' + action + ' marker')
            original_event = None
            for door in ('stdio', 'http'):
                for spelling in ('message_id', 'msg_id'):
                    result = reader.good(session, door, 'stateengine_msg_' + action,
                                         {spelling: sent['message_id']})
                    assert result['message_id'] == sent['message_id'], result
                    if action == 'read':
                        assert 'First mail read marker' in json.dumps(result)
                    if original_event is None:
                        original_event = result['event_id']
                    else:
                        assert result['event_id'] == original_event and result['marker'] == 'already'
                    checks.append(action + '/' + door + '/' + spelling)
            print('PASS', action, 'both spellings, both doors, stable recipient receipt', flush=True)
        for door in ('stdio', 'http'):
            for spelling in ('message_id', 'msg_id'):
                refused = reader.bad(session, door, 'stateengine_msg_read',
                                     {spelling: sent['message_id'], 'agent_id': 'another-agent'})
                assert 'another-agent' in json.dumps(refused)
                checks.append('caller-conflict/' + door + '/' + spelling)
        print('PASS conflicting caller assertions still refuse on both doors', flush=True)
    finally:
        f.close()
        (options.output / 'checks.json').write_text(json.dumps(checks, indent=2) + '\n')
    print('PASS public down and outside native PID/birth and endpoint closure;', len(checks), 'mail checks', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', required=True, type=lambda v: Path(v).resolve(strict=True))
    parser.add_argument('--output', required=True, type=Path)
    run(parser.parse_args())
