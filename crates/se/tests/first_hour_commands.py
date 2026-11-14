"""Execute first-hour reply/reopen commands and both resume cursor error doors.

Uses the existing native Claude protocol double, private state and a loopback port.
Run with --se RELEASE_SE --output NEW_DIRECTORY --port UNUSED_PORT.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).with_name('judges')))
from mail_cli import Fixture


def run(args):
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    helper = args.output / 'reply-provider.py'
    provider = Path(__file__).with_name('judges').joinpath('mail_provider.py').read_text()
    anchor = '    while True:\n        time.sleep(1)'
    assert provider.count(anchor) == 1, 'native protocol-double wait anchor missing'
    provider = provider.replace(anchor, '''    time.sleep(0.2)
    answer = {"type":"assistant", "sessionId":conversation, "uuid":"first-hour-answer",
              "message":{"role":"assistant", "content":"FIRST_HOUR_REPLY"}}
    with transcript.open("a") as output:
        output.write(json.dumps(answer) + "\\n")
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps(answer), flush=True)
    print(json.dumps({"type":"result", "session_id":conversation}), flush=True)
    for _ in sys.stdin:
        pass''')
    helper.write_text(provider)
    runtime = Path(tempfile.mkdtemp(prefix='ot-first-', dir='/tmp'))
    print("fixture root (retained on failed or interrupted closure):", runtime, flush=True)
    private_env = {'XDG_RUNTIME_DIR': str(runtime), 'TMPDIR': '/tmp'}
    for key, leaf in [('CODEX_HOME', 'codex'), ('XDG_CONFIG_HOME', 'config'),
                      ('XDG_CACHE_HOME', 'cache'), ('XDG_DATA_HOME', 'data'),
                      ('XDG_STATE_HOME', 'xdg-state')]:
        private = args.output / leaf
        private.mkdir(mode=0o700)
        private_env[key] = str(private)

    class IsolatedFixture(Fixture):
        def call(self, *arguments, **options):
            self.env.update(private_env)
            return super().call(*arguments, **options)

    f = IsolatedFixture(args.se, args.output / "home with spaces'", provider_helper=helper)
    config = f.home / 'config.toml'
    with socket.socket() as available:
        available.bind(('127.0.0.1', args.port))
    text, count = re.subn(r'(?m)^listen_port = [0-9]+$',
                         'listen_port = ' + str(args.port), config.read_text(), count=1)
    assert count == 1
    config.write_text(text)
    checks = []

    def check(label):
        checks.append(label)
        print(f'ok {len(checks)} - {label}', flush=True)

    def retain_births():
        ready = json.loads((f.repo / 'provider-ready.json').read_text())
        status = f.ok('--project', f.project, 'status')
        for pid in [ready['native_root_pid'], ready['helper_pid'], status['runtime']['process']['pid']]:
            birth = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
            if (pid, birth) not in f.processes:
                f.processes.append((pid, birth))

    def execute(command, label, machine=True):
        words = command['argv']
        assert shlex.split(command['command']) == words
        assert words[:3] == ['se', '--home', str(f.home)]
        assert words[words.index('--project') + 1] == f.project
        result = subprocess.run([str(f.se), *(['--json'] if machine else []), *words[1:]],
                                env=f.env, stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
        (args.output / (label + '.stdout')).write_bytes(result.stdout)
        (args.output / (label + '.stderr')).write_bytes(result.stderr)
        assert result.returncode == 0, (result.stdout, result.stderr)
        return result

    try:
        (f.repo / 'startup-stderr-burst').touch()
        launch = f.ok('--project', f.project, 'launch', f.agent, '--detach', '--task', 'Answer my task')
        assert (f.repo / 'startup-stderr-finished').read_text() == 'drained'
        check('pre-init stderr pressure drains before readiness without blocking the initial task')
        f.session = launch['session_id']
        retain_births()
        replies = launch['replies']
        assert replies['argv'][-4:] == ['--agent', f.agent, '--kind', 'session.turn']
        until = time.monotonic() + 15
        while True:
            history = execute(replies, 'read-replies')
            if b'FIRST_HOUR_REPLY' in history.stdout:
                break
            assert time.monotonic() < until, 'printed command did not read the captured reply'
            time.sleep(0.1)
        inbox = f.mail('list', '--to', f.agent)
        assert not inbox['items'], 'native replies were incorrectly treated as mail'
        check('JSON launch gives an executable exact-home/agent reply reader, even with an empty inbox')

        for token in ['opaque-invalid', 'bad cursor', '', 'x' * 4097]:
            cli = f.call('--project', f.project, 'resume', '--preview', f.agent, '--since', token)
            assert cli.returncode != 0
            value = json.loads(cli.stdout)
            assert value['code'] == 'cursor-invalid' and 'without --since' in value['remedy']['text']
            tool = f.rpc('stateengine_resume', {'since': token})
            assert tool['isError']
            value = tool.get('structuredContent') or json.loads(tool['content'][0]['text'])
            assert value['code'] == 'cursor-invalid' and 'without --since' in value['remedy']['text']
        check('malformed and invalid cursors have stable CLI/MCP codes and a fresh-read remedy')

        current = f.ok('--project', f.project, 'resume', '--preview', f.agent, '--budget', '65536')
        second = f.ok('--project', f.project, 'agent', 'add', 'Other', '--provider', 'claude', '--model', 'claude-sonnet-5-5')
        other = second['agent']['id']
        foreign = f.call('--project', f.project, 'resume', '--preview', other, '--since', current['cursor'])
        assert foreign.returncode != 0 and json.loads(foreign.stdout)['code'] == 'cursor-invalid'
        check('a genuine cursor for another agent refuses rather than hiding a partial read')

        stopped = f.ok('--project', f.project, 'stop', f.agent)
        assert stopped['complete']
        refused = f.call('--project', f.project, 'resume', 'Recipient')
        assert refused.returncode != 0
        remedy = json.loads(refused.stdout)['remedy']['command']['argv']
        literal = refused.stderr.decode().split('Run: ', 1)[1].strip()
        assert shlex.split(literal) == remedy
        reopened = execute({'argv': remedy, 'command': literal}, 'reopen', machine=False)
        text = reopened.stdout.decode()
        assert not text.lstrip().startswith('{') and 'Read replies: ' in text
        assert 'Conversation: ' + launch['conversation_id'] in text
        retain_births()
        command = text.split('Read replies: ', 1)[1].splitlines()[0]
        execute({'argv': shlex.split(command), 'command': command}, 'plain-read-replies')
        check('resume AGENT refuses read-only with a runnable reopen command; plain launch prints its reply reader')

        assert f.ok('--project', f.project, 'stop', f.agent)['complete']
        before = f.ok('--project', f.project, 'agent', 'show', f.agent)['agent']['value']
        transcript, = Path(f.env['HOME']).glob('.claude/projects/*/' + launch['conversation_id'] + '.jsonl')
        rotated = transcript.with_suffix('.jsonl.rotated')
        transcript.rename(rotated)
        recovery = None
        for machine in [False, True]:
            result = subprocess.run([str(f.se), '--home', str(f.home), '--project', f.project,
                                     *(['--json'] if machine else []), 'launch', f.agent, '--detach'],
                                    env=f.env, capture_output=True, timeout=45)
            (args.output / ('rotated-' + str(machine) + '.stdout')).write_bytes(result.stdout)
            (args.output / ('rotated-' + str(machine) + '.stderr')).write_bytes(result.stderr)
            assert result.returncode == 3, (result.stdout, result.stderr)
            assert str(transcript).encode() in result.stderr and b'--new' in result.stderr
            assert not transcript.exists() and rotated.exists(), 'refusal started the permissive provider'
            current = f.ok('--project', f.project, 'agent', 'show', f.agent)['agent']['value']
            assert current['session']['session_id'] == before['session']['session_id']
            if machine:
                error = json.loads(result.stdout)
                assert error['code'] == 'resume-reference-unverifiable'
                recovery = {'argv': error['remedy']['command']['argv'],
                            'command': result.stderr.decode().split('Run: ', 1)[1].strip()}
        execute(recovery, 'rotated-new-recovery')
        retain_births()
        current = f.ok('--project', f.project, 'agent', 'show', f.agent)['agent']['value']
        assert current['conversation']['id'] != launch['conversation_id']
        assert b'FIRST_HOUR_REPLY' in execute(replies, 'retained-old-reply').stdout
        check('rotated transcript refuses before preparation in both modes; exact --new recovery retains earlier replies')
    finally:
        f.close()
        with (f.home / 'runtime.lock').open('rb') as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (args.output / 'outside.json').write_text(json.dumps({
            'births': f.processes, 'observed_births_not_executing': True,
            'endpoint_absent': not (f.home / 'endpoint.json').exists(), 'lease_free': True,
        }, indent=2))
        if (runtime / 'stateengine').exists():
            (runtime / 'stateengine').rmdir()
        runtime.rmdir()
    (args.output / 'result.json').write_text(json.dumps({'passed': len(checks), 'checks': checks}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, required=True)
    run(parser.parse_args())
