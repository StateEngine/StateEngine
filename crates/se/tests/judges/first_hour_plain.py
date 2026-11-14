"""Judge the five first-hour plain CLI regressions using an isolated native provider.

Linux only. No account or paid calls: the existing Claude protocol double supplies real
conversation records and receives actual mail notices. JSON and exact-event
reads remain controls for the full diagnostic and conversation data.
Run: python3 first_hour_plain.py --se /absolute/se --output NEW_DIRECTORY
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time
import traceback

from mail_cli import Fixture


ANSWER = 'TRANSFER_COMPLETE: three tests passed; input balances unchanged.'
HUMAN = "Explain the quoted phrase 'Automated StateEngine notice' in ordinary prose."


def provider(path):
    source = Path(__file__).with_name('mail_provider.py').read_text()
    start = source.index('    transcript.write_text(')
    end = source.index('    request = ', start)
    source = source[:start] + '''    with transcript.open("a") as log:
        log.write(json.dumps({"type":"user", "sessionId":conversation,
            "uuid":"initial-" + str(os.getpid()), "message":{"role":"user",
            "content":HUMAN}}) + "\\n")
''' + source[end:]
    anchor = '    while True:\n        time.sleep(1)'
    assert source.count(anchor) == 1, 'native provider wait anchor missing'
    source = source.replace(anchor, '''    def emit(text):
        row = {"type":"assistant", "sessionId":conversation,
            "uuid":"answer-" + str(time.time_ns()),
            "message":{"role":"assistant", "content":text}}
        with transcript.open("a") as log:
            log.write(json.dumps(row) + "\\n")
            log.flush()
            os.fsync(log.fileno())
        print(json.dumps(row), flush=True)
        print(json.dumps({"type":"result", "session_id":conversation}), flush=True)
    emit(ANSWER)
    for line in sys.stdin:
        value = json.loads(line)
        content = value.get("message", {}).get("content", "")
        if not isinstance(content, str):
            content = "\\n".join(x.get("text", "") for x in content)
        with transcript.open("a") as log:
            log.write(json.dumps({"type":"user", "sessionId":conversation,
                "uuid":"notice-" + str(time.time_ns()),
                "message":{"role":"user", "content":content}}) + "\\n")
        emit(ANSWER)
''')
    source = source.replace('import json\n', 'import json\nHUMAN = ' + repr(HUMAN) + '\nANSWER = ' + repr(ANSWER) + '\n', 1)
    settings = '    if "--safe-mode" in arguments:\n        request = json.loads(sys.stdin.readline())\n        assert request["request"]["subtype"] == "get_settings"\n        print(json.dumps({"type":"control_response", "response":{\n            "request_id":"settings", "subtype":"success", "response":{\n            "effective":{}, "sources":[], "errors":[]}}}), flush=True)\n        return\n'
    marker = '    flag = "--resume"'
    assert source.count(marker) == 1, 'native provider argument anchor missing'
    source = source.replace(marker, settings + marker, 1)
    path.write_text(source)


def run(args):
    os.umask(0o077)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    helper = args.output / 'provider.py'
    provider(helper)
    runtime = Path(tempfile.mkdtemp(prefix='plain-runtime-', dir=os.environ.get('TMPDIR')))
    print("fixture root (retained on failed or interrupted closure):", runtime, flush=True)
    isolated = {'XDG_RUNTIME_DIR': str(runtime)}
    for key in ['CODEX_HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME']:
        path = args.output / key.lower()
        path.mkdir(mode=0o700)
        isolated[key] = str(path)

    class PrivateFixture(Fixture):
        def call(self, *arguments, **options):
            self.env.update(isolated)
            for name in list(self.env):
                if name.startswith(('OPENAI', 'ANTHROPIC')) or any(x in name for x in ['TOKEN', 'SECRET', 'API_KEY']):
                    del self.env[name]
            return super().call(*arguments, **options)

    f = PrivateFixture(args.se, args.output / "selected home's", provider_helper=helper)
    checks = []
    sequence = 0

    def plain(label, *arguments):
        nonlocal sequence
        sequence += 1
        selector = [] if arguments[0] == 'down' else ['--project', f.project]
        result = subprocess.run([str(f.se), '--home', str(f.home), *selector, *arguments],
                                cwd=f.repo, env=f.env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=90)
        prefix = args.output / (str(sequence) + '-' + label)
        prefix.with_suffix('.stdout').write_bytes(result.stdout)
        prefix.with_suffix('.stderr').write_bytes(result.stderr)
        return result, result.stdout.decode()

    def judge(label, test):
        try:
            test()
            checks.append({'name': label, 'passed': True})
            print('ok', len(checks), '-', label, flush=True)
        except AssertionError:
            checks.append({'name': label, 'passed': False, 'error': traceback.format_exc()})
            print('not ok', len(checks), '-', label, flush=True)

    def healthy_status(label):
        result, text = plain(label, 'status')
        assert result.returncode == 0 and 'Runtime: stopped' in text, (result.returncode, text)
        assert 'Recipient' in text and ('launch' in text or 'resume' in text), text
        for diagnostic in ['use se doctor', 'no connection file', 'Proposed decisions: not counted',
                           'Conversation recording: not checked; code index: not built']:
            assert diagnostic not in text, text

    def already_down():
        receipt = f.ok('down')
        assert receipt['already_down'] and receipt['complete'] and not receipt['stops'], receipt
        result, text = plain('already-down', 'down')
        assert result.returncode == 0 and 'Already down' in text, (result.returncode, text)
        # An empty native inventory proves absence, not a completed writer flush.
        assert 'Pending writes saved' not in text and 'Shutdown verified' not in text, text

    def remember():
        ready = json.loads((f.repo / 'provider-ready.json').read_text())
        status = f.ok('--project', f.project, 'status')
        for pid in [ready['native_root_pid'], ready['helper_pid'], status['runtime']['process']['pid']]:
            birth = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
            if (pid, birth) not in f.processes:
                f.processes.append((pid, birth))

    def history():
        return f.ok('--project', f.project, 'history', '--agent', f.agent,
                    '--kind', 'session.turn', '--limit', '100')

    def wait_for(predicate):
        until = time.monotonic() + 20
        while True:
            value = history()
            if predicate(value):
                return value
            assert time.monotonic() < until, 'native transcript fixture did not reach required state'
            time.sleep(0.1)

    def body(item):
        return item['payload']['body']['text']

    try:
        judge('healthy new status gives a launch path without repair noise', lambda: healthy_status('new-status'))
        judge('already-down absence does not claim a writer flush or a performed shutdown', already_down)
        launch = f.ok('--project', f.project, 'launch', f.agent, '--detach', '--task', HUMAN)
        f.session = launch['session_id']
        remember()
        wait_for(lambda page: any(body(item) == ANSWER for item in page['items']))
        sent = f.mail('send', f.agent, 'Please inspect the transfer result.')
        captured = wait_for(lambda page: any('Automated StateEngine notice' in body(item)
                                             and 'Read each message_id' in body(item) for item in page['items']))
        notice = next(item for item in captured['items'] if 'Read each message_id' in body(item))
        assert sent['message_id'] in body(notice), 'fixture captured an unrelated notice'

        def readable_history():
            result, text = plain('history', 'history', '--agent', f.agent, '--kind', 'session.turn', '--limit', '100')
            assert result.returncode == 0 and ANSWER in text and HUMAN in text, text
            assert 'Read each message_id with stateengine_msg_read' not in text, text
            assert 'Mail senders (verified sender references)' not in text, text
            assert re.search(r'notice|notification|mail', text, re.IGNORECASE), 'notice disappeared without a human summary'
            # The presentation change must not delete the original captured turn.
            exact = f.ok('--project', f.project, 'history', '--event', notice['event_id'])
            assert body(exact) == body(notice), exact
            assert len(history()['items']) >= len(captured['items']), 'history rows disappeared'
        judge('plain replies summarize machine notices and retain human text plus raw exact events', readable_history)

        down, stopped = plain('down', 'down')
        assert down.returncode == 0, (down.stdout, down.stderr)
        for pid, birth in f.processes:
            try:
                fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
                assert fields[19] != birth or fields[0] == 'Z', 'plain down returned before an owned birth exited'
            except FileNotFoundError:
                pass

        def readable_down():
            assert 'complete' in stopped.lower() and 'saved' in stopped.lower(), stopped
            for raw in ['Uncontained {', 'Some(ObservedEmpty)', 'NoDelegation', 'lifecycle=', 'life_',
                        'no provider resume command was independently verified']:
                assert raw not in stopped, stopped
            assert '--json' in stopped, 'no route to full diagnostic receipt'
        judge('normal shutdown gives a human result with a diagnostic escape hatch', readable_down)
        judge('healthy stopped status offers reopening without a doctor alarm', lambda: healthy_status('stopped-status'))

        def readable_preview():
            before = f.ok('--project', f.project, 'agent', 'show', f.agent)
            result, text = plain('preview', 'resume', '--preview', f.agent, '--budget', '65536')
            assert result.returncode == 0 and ANSWER in text and 'Recipient' in text, text
            for raw in ['Who am I?', 'needs_read', 'No saved working state.']:
                assert raw not in text, text
            assert re.search(r'owner|preview|context for', text, re.IGNORECASE), text
            assert re.search(r'notes', text, re.IGNORECASE), 'absent separate notes are unexplained'
            after = f.ok('--project', f.project, 'agent', 'show', f.agent)
            assert after['agent']['value']['session']['session_id'] == before['agent']['value']['session']['session_id']
            assert f.mail('list', '--to', f.agent)['unread_total'] == 1, 'owner preview acknowledged the recipient mail'
        judge('owner preview explains absent notes without implying lost conversation or marking mail read', readable_preview)

        def reopen_alias():
            result, stdout = plain('resume-agent', 'resume', 'Recipient')
            stderr = result.stderr.decode()
            assert result.returncode in [0, 64], (result.returncode, stdout, stderr)
            # A concise refusal preserves the public exit/JSON contract; the
            # human recovery must be just as executable as successful advice.
            if result.returncode:
                assert not stdout and stderr.startswith('error['), (stdout, stderr)
            text = stdout + stderr
            assert 'provider conversation reopen' not in text and 'context read' not in text, text
            assert len([line for line in text.splitlines() if line.strip()]) <= 3, text
            command = next((line[line.index('se --home '):] for line in text.splitlines()
                            if 'se --home ' in line and ' launch ' in line), None)
            assert command, 'resume AGENT must offer an executable reopen command'
            words = shlex.split(command)
            assert words[0] == 'se' and words[words.index('--home') + 1] == str(f.home), words
            assert words[words.index('--project') + 1] == f.project, words
            assert words[words.index('launch') + 1] in [f.agent, 'Recipient'] and '--new' not in words, words
            shown = f.ok('--project', f.project, 'agent', 'show', f.agent)['agent']['value']
            assert shown['session']['state'] == 'stopped', 'resume advice unexpectedly launched a process'
            reopened = subprocess.run([str(f.se), '--json', *words[1:]], env=f.env,
                                      cwd=f.repo, stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
            (args.output / 'executed-reopen.stdout').write_bytes(reopened.stdout)
            (args.output / 'executed-reopen.stderr').write_bytes(reopened.stderr)
            assert reopened.returncode == 0, (reopened.stdout, reopened.stderr)
            value = json.loads(reopened.stdout)
            assert value['conversation_id'] == launch['conversation_id'], value
            f.session = value['session_id']
            remember()
        judge('resume AGENT gives concise read-only advice whose exact-home command reopens the same conversation', reopen_alias)
    finally:
        f.close()
        with (f.home / 'runtime.lock').open('rb') as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (args.output / 'outside.json').write_text(json.dumps({'births': f.processes,
            'observed_births_not_executing': True, 'endpoint_absent': not (f.home / 'endpoint.json').exists(),
            'lease_free': True}, indent=2))
        result = {'image_sha256': hashlib.sha256(args.se.read_bytes()).hexdigest(), 'checks': checks,
                  'passed': sum(item['passed'] for item in checks), 'failed': sum(not item['passed'] for item in checks)}
        (args.output / 'result.json').write_text(json.dumps(result, indent=2))
        print('1..' + str(len(checks)), flush=True)
        for child in runtime.iterdir():
            if child.is_dir():
                child.rmdir()
        runtime.rmdir()
    assert not result['failed'], 'first-hour plain CLI regressions remain; see result.json'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())
