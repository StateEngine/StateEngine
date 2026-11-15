"""Pair two outside-process clocks over one unchanged packaged CLI fixture."""
import hashlib
import json
import math
from pathlib import Path
import select
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'agent_list_package'))
from build import unpack, digest
from support import prepare, timed, validate, status, close, load, save, require

SOURCE = 'b1d82b307791b95d2c8332852555490041ca1b5a'
ARCHIVE = '8f2efdd848abee4a9d339f1c6342623d9a4afcb34e7aa4ffb3aced3e8eddf7ba'
IMAGE = 'bc5f20fd2d5873ff3cce3f00bc43b7caac18c30a046334b641521c4167785ff9'


def receive(server):
    require(select.select([server.stdout], [], [], 20)[0], 'Nightly observer protocol timed out')
    line = server.stdout.readline()
    require(line, 'Nightly observer exited without a response')
    return json.loads(line)


def stop_server(server):
    if not server.stdin.closed:
        server.stdin.close()
    try:
        return server.wait(timeout=20)
    except subprocess.TimeoutExpired:
        actual = Path(f'/proc/{server.pid}/cmdline').read_bytes().split(b'\0')[:-1]
        require(actual == [str(arg).encode() for arg in server.args], 'Observer identity changed')
        server.kill()
        server.wait(timeout=5)
        raise RuntimeError('Nightly observer did not join on EOF')


def summary(rows):
    values = sorted(row['ms'] for row in rows)
    return dict(count=len(rows), p95_ms=values[math.ceil(.95 * len(values))-1],
                max_ms=max(values), blocks_30=[
                    dict(count=len(block), p95_ms=sorted(block)[math.ceil(.95*len(block))-1])
                    for offset in range(0, len(rows), 30)
                    if (block := [row['ms'] for row in rows[offset:offset+30]])])


def main():
    supplied, output = map(lambda value: Path(value).resolve(), sys.argv[1:])
    output.mkdir()
    archive = next((supplied/'archive').glob('*.tar.gz'))
    require(digest(archive) == ARCHIVE, 'Prior hosted package archive changed')
    metadata = json.loads((supplied/'build.json').read_text())
    require(metadata['source_commit'] == SOURCE, 'Product source changed')
    executable, manifest = unpack(archive, output/'extracted', metadata)
    require(digest(executable) == IMAGE, 'Prior stripped executable changed')
    image = dict(image=str(executable), sha256=IMAGE, source=SOURCE)
    frozen = json.loads((HERE/'frozen.json').read_text())
    for name, entry in frozen.items():
        expected = entry['sha256'] if isinstance(entry, dict) else entry
        require(digest(HERE/'nightly'/name) == expected, 'Nightly module changed: '+name)
    save(output/'provenance.json', dict(source=SOURCE, archive_sha256=ARCHIVE,
         executable_sha256=IMAGE, frozen=frozen, manifest=manifest))
    record = dict(exit=1, load_before=load(), samples=[], cleanup={}, process_closure={},
        scope='one clean Codex-selected saved agent; never launched; same package and host for both timers',
        method='180 interleaved pairs, alternating which clock runs first; first pair separate; '
               'nightly clock is unchanged cliOnce, sample validation off timer; six blocks of 30 pairs')
    smokes, server = {}, None
    try:
        smoke, pid = prepare(output/'fixture', image, 'codex', False, smokes, 'package', 1)
        record['identity_before'] = status(smoke, pid, False, 1, 'host-before')
        initial = smoke.call(['agent', 'list'], 'initial-list')
        saved = {row['name']: row['id'] for row in initial['items']}
        argv = list(map(str, [smoke.binary, 'agent', 'list', '--home', smoke.state,
                              '--project', smoke.project, '--json']))
        settings = output/'observer-settings.json'
        save(settings, dict(binary=str(smoke.binary), home=str(smoke.home),
             cwd=str(smoke.repository), project=smoke.project,
             env=smoke.commands.environment, argv=argv))
        with (output/'observer.stderr').open('w') as stderr:
            server = subprocess.Popen([shutil.which('node'), str(HERE/'server.mjs'), str(settings)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True, bufsize=1)
            record['observer'] = dict(pid=server.pid, argv=server.args)
            require(receive(server) == dict(ready=True, argv=argv), 'Nightly command spelling differs')
            for index in range(181):
                pair = dict(index=index)
                order = ('python', 'nightly') if index % 2 == 0 else ('nightly', 'python')
                pair['order'] = order
                record['samples'].append(pair)
                for method in order:
                    if method == 'python':
                        sample = timed(smoke, ['agent', 'list'])
                    else:
                        server.stdin.write('sample\n')
                        server.stdin.flush()
                        sample = receive(server)
                        require(sample['unresolved'] == [], 'Nightly child did not close')
                    pair[method] = sample
                    save(output/'result.json', record)
                    value = validate(sample, smoke, 1, 'codex', saved)
                    require(value['items'][0]['provider_activity']['state'] == 'absent',
                            'Never-launched nightly cohort became a runtime-observation cohort')
                save(output/'result.json', record)
            record['observer_exit'] = stop_server(server)
            require(record['observer_exit'] == 0, 'Nightly observer failed to join cleanly')
            server = None
        record['identity_after'] = status(smoke, pid, False, 1, 'host-after')
        require(record['identity_before'] == record['identity_after'], 'Serving host changed')
        record['summary'] = {method: summary([row[method] for row in record['samples'][1:]])
                             for method in ('python', 'nightly')}
        record['exit'] = 0
    except Exception as error:
        record['error'] = str(error)
    finally:
        if server is not None:
            try:
                record['observer_exit'] = stop_server(server)
            except Exception as error:
                record['observer_closure_error'] = str(error)
                record['exit'] = 1
        close(smokes, record)
        record['load_after'] = load()
        save(output/'result.json', record)
    raise SystemExit(record['exit'])


if __name__ == '__main__':
    main()
