"""Real CLI/MCP force controls over owned synthetic provider processes (Linux)."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import traceback
from mail_cli import Fixture as MailFixture
from launch_startup import pin, exited



class Fixture(MailFixture):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # This reader now requests native settings before launch. The old shared
        # mail fixture predates that protocol; supply its real response shape.
        source = self.root / 'provider.rs'
        text = source.read_text()
        needle = 'if a.get(1).map(String::as_str)==Some("--version")'
        assert text.count(needle) == 1
        reply = {"type": "control_response", "response": {"subtype": "success", "request_id": "settings",
                 "response": {"effective": {}, "sources": [], "errors": []}}}
        safe = 'if a.iter().any(|v|v=="--safe-mode") {println!("{}", r#"' + json.dumps(reply) + '"#);loop {std::thread::sleep(std::time::Duration::from_secs(1));}}\n'
        source.write_text(text.replace(needle, safe + needle, 1))
        subprocess.run(['rustc', '--edition=2024', str(source), '-o', str(self.root / 'provider')],
                       capture_output=True, check=True, timeout=60)


def wait_for(probe, name, seconds=20):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = probe()
        if value:
            return value
        time.sleep(.03)
    raise AssertionError('deadline: ' + name)


def interrupted(binary, root):
    f = Fixture(binary, root, provider_helper=Path(__file__).with_name('launch_startup_provider.py'), log_directory='calls')
    (f.repo / 'startup-mode').write_text('idle')
    up = f.ok('up')
    identities = [pin(up['process']['pid'])]
    first = subprocess.Popen([str(binary), '--json', '--home', str(f.home), '--project', f.project,
                              '--key', 'interrupted-original', 'launch', f.agent, '--detach', '--task', 'Original'],
                             env=f.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    failure = None
    try:
        marker = f.repo / 'startup-pids.json'
        wait_for(marker.exists, 'native startup')
        identities.extend(pin(pid) for pid in json.loads(marker.read_text()))
        wait_for(lambda: (f.repo / 'startup-owner-probe.json').exists(), 'startup admission probe')
        refused = f.call('--project', f.project, 'launch', f.agent, '--detach')
        text = refused.stdout + refused.stderr
        assert refused.returncode and b'--force' in text and b'No process was stopped' in text, text
        assert all(not exited(p) for p in identities), 'plain launch stopped original startup'
        (f.repo / 'startup-mode').write_text('ready')
        forced = f.ok('--project', f.project, '--key', 'interrupted-force', 'launch', f.agent, '--detach', '--force')
        assert forced['state'] == 'running' and forced['takeover'], forced
        output, error = first.communicate(timeout=35)
        (root / 'original.stdout').write_bytes(output)
        (root / 'original.stderr').write_bytes(error)
        assert first.returncode != 0, (output, error)
        assert all(exited(p) for p in identities[1:]), 'old startup has a surviving process'
        ready = json.loads((f.repo / 'provider-ready.json').read_text())
        fresh = [pin(ready['native_root_pid']), pin(ready['helper_pid'])]
        identities.extend(fresh)
        replay = f.ok('--project', f.project, '--key', 'interrupted-force', 'launch', f.agent, '--detach', '--force')
        assert replay['session_id'] == forced['session_id'] and replay['takeover'] == forced['takeover']
        assert all(not exited(p) for p in fresh), 'same-key replay stopped successor'
        print('ok - nonterminal starting inventory; force joins interrupted startup; replay preserves successor', flush=True)
    except BaseException:
        failure = traceback.format_exc()
        (root / 'failure.txt').write_text(failure)
    finally:
        f.close()
        output, error = first.communicate(timeout=35)
        (root / 'original.stdout').write_bytes(output)
        (root / 'original.stderr').write_bytes(error)
        closure = [{'pid': p[0], 'birth': p[1], 'exited': exited(p)} for p in identities]
        (root / 'closure.json').write_text(json.dumps(closure, indent=2))
        assert all(row['exited'] for row in closure), closure
    if failure:
        raise AssertionError(failure)


def managed(binary, root):
    # No detached/escaped work in this fixture: all jobs must close with the scope.
    f = Fixture(binary, root, provider_helper=Path(__file__).with_name('force_relaunch_provider.py'), log_directory='calls')
    identities = []
    failure = None
    try:
        up = f.ok('up')
        identities.append(pin(up['process']['pid']))
        f.launch()
        old = f.session
        job_path = f.repo / 'force-job.json'
        wait_for(job_path.exists, 'managed child')
        child = json.loads(job_path.read_text())
        old_pins = [pin(pid) for pid in child['pids']]
        identities.extend(old_pins)
        refusal = f.call('--project', f.project, 'launch', f.agent, '--detach')
        body = refusal.stdout + refusal.stderr
        assert refusal.returncode and b'--force' in body and b'force-owned-child' in body, body
        assert all(not exited(p) for p in old_pins)
        mcp = f.rpc('stateengine_agent_launch', {'idempotency_key': 'mcp-no-force'})
        assert mcp.get('isError') and '--force' in json.dumps(mcp), mcp
        job_path.unlink()
        (f.repo / 'provider-ready.json').unlink()
        result = f.ok('--project', f.project, '--key', 'managed-force', 'launch', f.agent, '--detach', '--force')
        report = result['takeover']
        assert report['previous_session'] == old and result['session_id'] != old, result
        assert all(exited(p) for p in old_pins), 'forced scope retains old native work'
        assert any(j['pid'] == child['pids'][-1] for j in report['jobs_stopped']), report
        assert not report.get('jobs_remaining') and not report.get('jobs_unproved'), report
        wait_for(job_path.exists, 'successor child')
        new = json.loads(job_path.read_text())
        new_pins = [pin(pid) for pid in new['pids']]
        identities.extend(new_pins)
        f.session = result['session_id']
        assert not f.rpc('stateengine_resume', {}).get('isError')
        f.session = old
        assert f.call('--project', f.project, 'resume', recipient=True).returncode != 0
        f.session = result['session_id']
        replay = f.ok('--project', f.project, '--key', 'managed-force', 'launch', f.agent, '--detach', '--force')
        assert replay['session_id'] == f.session and all(not exited(p) for p in new_pins)
        print('ok - plain CLI/MCP preserve busy work; force witnesses jobs and revokes old admission; replay safe', flush=True)
    except BaseException:
        failure = traceback.format_exc()
        (root / 'failure.txt').write_text(failure)
    finally:
        f.close()
        closure = [{'pid': p[0], 'birth': p[1], 'exited': exited(p)} for p in identities]
        (root / 'closure.json').write_text(json.dumps(closure, indent=2))
        assert all(row['exited'] for row in closure), closure
    if failure:
        raise AssertionError(failure)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--se', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    for name, case in [('managed', managed), ('interrupted', interrupted)]:
        case(args.se.resolve(), args.output / name)
    print('PASS 2 real-consumer force journeys', flush=True)


if __name__ == '__main__':
    main()
