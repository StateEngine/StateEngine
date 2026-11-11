"""Compare a real owned Codex launch with its installed package entry point.

Linux only. Requires --se, --launcher, --payload, --node and a fresh, short
--output path. Uses an isolated home and loopback model, without account login.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from codex_first_launch import Model


def observe(pid):
    root = Path('/proc') / str(pid)
    fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'birth': fields[19], 'state': fields[0],
            'image': os.readlink(root / 'exe'), 'cwd': os.readlink(root / 'cwd'),
            'argv': [os.fsdecode(x) for x in (root / 'cmdline').read_bytes().split(b'\0') if x],
            'environment': dict(os.fsdecode(x).split('=', 1)
                                for x in (root / 'environ').read_bytes().split(b'\0') if x)}


def same_process(saved):
    try:
        current = observe(saved['pid'])
        return current['birth'] == saved['birth'] and current['state'] != 'Z'
    except FileNotFoundError:
        return False


def native_descendant(pid, payload):
    todo, visited = [pid], set()
    while todo:
        selected = todo.pop()
        if selected in visited:
            continue
        visited.add(selected)
        try:
            value = observe(selected)
            if value['image'] == str(payload):
                return value
            children = Path(f'/proc/{selected}/task/{selected}/children').read_text()
            todo.extend(int(x) for x in children.split())
        except FileNotFoundError:
            pass
    return None


class ReplyModel(Model):
    def respond(self, handler, request):
        self.requests.append(request)
        title = 'title' in request.get('text', {}).get('format', {}).get('schema', {}).get('properties', {})
        item = {'id': 'msg_' + uuid.uuid4().hex, 'type': 'message', 'role': 'assistant',
                'status': 'completed', 'phase': 'final_answer',
                'content': [{'type': 'output_text', 'text': json.dumps({'title': 'Package parity'})
                             if title else 'PACKAGE_PARITY_DONE', 'annotations': [], 'logprobs': []}]}
        response = {'id': 'resp_' + uuid.uuid4().hex, 'object': 'response',
                    'created_at': int(time.time()), 'model': request.get('model', 'synthetic-model'),
                    'status': 'in_progress', 'output': []}
        events = [{'type': 'response.created', 'response': response},
                  {'type': 'response.output_item.added', 'output_index': 0,
                   'item': {**item, 'status': 'in_progress'}},
                  {'type': 'response.output_item.done', 'output_index': 0, 'item': item},
                  {'type': 'response.completed', 'response': {**response, 'status': 'completed',
                   'output': [item], 'usage': {'input_tokens': 1, 'output_tokens': 1,
                   'total_tokens': 2, 'output_tokens_details': {'reasoning_tokens': 0}}}}]
        body = ''.join('event: ' + e['type'] + '\ndata: ' + json.dumps({**e, 'sequence_number': i})
                       + '\n\n' for i, e in enumerate(events)).encode()
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/event-stream')
        handler.send_header('Content-Length', str(len(body)))
        handler.end_headers()
        try:
            handler.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def reference(options, direct, environment, repo):
    # The recorded endpoint belongs to this fresh fixture; its runtime is down.
    address = direct['argv'][-1]
    assert address.startswith('unix://'), direct['argv']
    socket = Path(address.removeprefix('unix://'))
    assert socket.is_relative_to(options.output), 'select a shorter owned output path'
    assert not socket.exists(), 'the owned provider endpoint was not retired'
    socket.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # All fixture inputs are admitted provider variables; only session/scratch values
    # come from the public launch. Do not seed the reference from the actual child's
    # other values: doing so would hide missing or unexpected environment entries.
    baseline = dict(environment)
    for key in ['SE_SESSION', 'TMPDIR', 'TMP', 'TEMP']:
        baseline[key] = direct['environment'][key]
    assert all(Path(baseline[key]).is_relative_to(options.output)
               for key in ['TMPDIR', 'TMP', 'TEMP']), 'scratch escaped the owned fixture'
    child = subprocess.Popen([str(options.node), str(options.launcher), *direct['argv'][1:]],
                             env=baseline, cwd=repo, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    found = None
    closure = {'joined': False, 'native_absent': None}
    try:
        end = time.monotonic() + 10
        while found is None and time.monotonic() < end:
            assert child.poll() is None, 'package reference exited before observation'
            found = native_descendant(child.pid, options.payload)
            time.sleep(.01)
        assert found is not None, 'no native package reference within ten seconds'
        return found
    finally:
        if child.poll() is None:
            identity = observe(child.pid)
            current = observe(child.pid)
            assert all(current[k] == identity[k] for k in ['birth', 'image', 'argv']), 'reference process identity changed'
            child.terminate()
        stdout, stderr = child.communicate(timeout=10)
        closure['joined'] = True
        (options.output / 'reference.stdout').write_bytes(stdout)
        (options.output / 'reference.stderr').write_bytes(stderr)
        if found:
            end = time.monotonic() + 5
            while same_process(found) and time.monotonic() < end:
                time.sleep(.02)
            closure['native_absent'] = not same_process(found)
            assert closure['native_absent'], 'package reference child remained live'
        (options.output / 'reference-closure.json').write_text(json.dumps(closure, indent=2))
        if socket.exists():
            assert stat.S_ISSOCK(socket.lstat().st_mode), 'retain unexpected endpoint replacement'
            socket.unlink()


def run(options):
    options.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = options.output
    repo, owner, home, tools, temporary = [root / name for name in ['repo', 'owner', 'state', 'tools', 'tmp']]
    code_home = owner / '.codex'
    for path in [repo, owner, code_home, tools, temporary]:
        path.mkdir(mode=0o700)
    # Keep ordinary prerequisites and select the package's Node explicitly.
    for directory in os.get_exec_path({'PATH': '/usr/local/bin' + os.pathsep + os.defpath}):
        for utility in Path(directory).iterdir():
            destination = tools / utility.name
            if utility.is_file() and os.access(utility, os.X_OK) and not destination.exists():
                destination.symlink_to(utility.resolve())
    for name in ['git', 'node', 'python3', 'env', 'sh', 'bash']:
        source = options.node if name == 'node' else Path(shutil.which(name) or '')
        assert source.is_file(), 'required native fixture utility missing: ' + name
        destination = tools / name
        if destination.is_symlink():
            destination.unlink()
        destination.symlink_to(source.resolve())
    environment = {'HOME': str(owner), 'USERPROFILE': str(owner), 'CODEX_HOME': str(code_home),
                   'PATH': str(tools), 'SHELL': '/bin/bash', 'LANG': 'C.UTF-8', 'TMPDIR': str(temporary)}
    for key in ['XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME']:
        selected = owner / key.lower()
        selected.mkdir(mode=0o700)
        environment[key] = str(selected)
    model = ReplyModel(root, repo)
    (code_home / 'config.toml').write_text('model="synthetic-model"\nmodel_provider="fixture"\n'
        '[model_providers.fixture]\nname="Owned loopback"\nbase_url=' +
        json.dumps(f'http://127.0.0.1:{model.server.server_port}/v1') +
        '\nwire_api="responses"\nrequires_openai_auth=false\n')
    sequence, direct = 0, None
    result = {'checks': {}, 'errors': [], 'cleanup': []}

    def call(*args):
        nonlocal sequence
        sequence += 1
        child = subprocess.run([str(options.se), '--json', '--home', str(home), *args],
                               env=environment, cwd=repo, stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=90)
        (root / f'call-{sequence:02}.stdout').write_bytes(child.stdout)
        (root / f'call-{sequence:02}.stderr').write_bytes(child.stderr)
        assert child.returncode == 0, f'public call {sequence} failed: {args}'
        return json.loads(child.stdout)

    try:
        initialized = call('init', '--repo', str(repo), '--name', 'Package environment',
                           '--agent', 'Initial', '--provider', 'codex', '--model', 'synthetic-model')
        project, agent = initialized['project']['id'], initialized['agent']['id']
        config = home / 'config.toml'
        config.write_text(config.read_text().replace('[providers.codex]',
            '[providers.codex]\ncommand=' + json.dumps(str(options.launcher)), 1))
        launched = call('--project', project, 'launch', agent, '--detach',
                        '--task', 'Reply PACKAGE_PARITY_DONE without calling any tools.')
        direct = observe(launched['process']['pid'])
        result['direct'] = direct
        result['checks']['native_root'] = direct['image'] == str(options.payload)
    except Exception as error:
        result['errors'].append(str(error))
    finally:
        try:
            down = call('down')
            assert down['complete'] and down['witness']['state'] == 'witnessed', down
            if direct:
                assert not same_process(direct), 'managed native provider remained live'
        except Exception as error:
            result['cleanup'].append(str(error))
        model.close()
        (root / 'model-requests.json').write_text(json.dumps(model.requests, indent=2))
    if direct and not result['cleanup']:
        try:
            ordinary = reference(options, direct, environment, repo)
            result['package_reference'] = ordinary
            result['checks']['argv_parity'] = direct['argv'] == ordinary['argv']
            result['checks']['cwd_parity'] = direct['cwd'] == ordinary['cwd'] == str(repo)
            result['checks']['path_parity'] = direct['environment'].get('PATH') == ordinary['environment'].get('PATH')
            result['checks']['environment_parity'] = direct['environment'] == ordinary['environment']
        except Exception as error:
            result['errors'].append(str(error))
        closure = root / 'reference-closure.json'
        if not closure.exists() or not json.loads(closure.read_text()).get('joined'):
            result['cleanup'].append('package reference join unqualified')
        elif json.loads(closure.read_text()).get('native_absent') is not True:
            result['cleanup'].append('package reference native absence unqualified')
    (root / 'result.json').write_text(json.dumps(result, indent=2))
    passed = len(result['checks']) == 5 and all(result['checks'].values()) and not result['errors'] and not result['cleanup']
    print(json.dumps({'passed': passed, 'checks': result['checks'], 'errors': result['errors'],
                      'cleanup': result['cleanup']}), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['se', 'launcher', 'payload', 'node', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    options = parser.parse_args()
    for name in ['se', 'payload', 'node', 'output']:
        setattr(options, name, getattr(options, name).resolve())
    options.launcher = options.launcher.absolute()
    assert sys.platform == 'linux', 'this consumer requires native Linux process readback'
    raise SystemExit(run(options))
