"""Public startup timings with proof and closure observations outside the timer."""
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness_matrix.flow import Smoke
from harness_matrix.io import require, save


def timed(smoke):
    argv = [str(smoke.binary), 'up', '--home', str(smoke.state), '--json', '--no-color']
    started = time.perf_counter_ns()
    child = subprocess.Popen(argv, cwd=smoke.repository, env=smoke.commands.environment,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = child.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        current = Path(f'/proc/{child.pid}/cmdline').read_bytes().split(b'\0')[:-1]
        require(current == [os.fsencode(arg) for arg in argv], 'Timed-out command identity changed')
        child.kill()
        stdout, stderr = child.communicate(timeout=5)
        raise RuntimeError('Public up exceeded 30 seconds: '+stderr.decode(errors='replace'))
    elapsed = (time.perf_counter_ns()-started)/1e6
    require(child.returncode == 0, 'Public up failed: '+stderr.decode(errors='replace'))
    return dict(ms=elapsed, exit=child.returncode, stdout=stdout.decode(), stderr=stderr.decode())


def prepare(directory, image):
    directory.mkdir(mode=0o700)
    smoke = Smoke(directory, None, {'id':'claude','driver':'native'}, {'provider':'claude'},
                  {'PATH':os.environ['PATH']})
    smoke.state = smoke.home/'stateengine-state'
    smoke.commands.environment['SE_HOME'] = str(smoke.state)
    smoke.binary.parent.mkdir(parents=True)
    shutil.copyfile(image['image'], smoke.binary)
    smoke.binary.chmod(0o500)
    require(hashlib.file_digest(smoke.binary.open('rb'),'sha256').hexdigest()==image['sha256'],
            'Installed image differs')
    subprocess.run(['git','init','--initial-branch=measurement',str(smoke.repository)],
                   env=smoke.commands.environment,capture_output=True,check=True)
    smoke.initialization_attempted = True
    profile = smoke.call(['init','--repo',smoke.repository,'--agent','main','--provider','claude'],
                         'init',terminal=True,project=False)['profile']
    smoke.project,smoke.agent,smoke.owner = (profile[k] for k in ('project','agent_id','human_id'))
    require(smoke.commands.observer.observe()==[], 'Initialized fixture already has a live process')
    return smoke


def sample(smoke):
    require(smoke.commands.observer.observe()==[], 'A previous runtime is still live')
    record = timed(smoke)
    started = json.loads(record['stdout'])
    require(started.get('state')=='running', 'Up did not report running')
    pid = started['process']['pid']
    processes = smoke.commands.observer.observe(pid)
    record['outside_process'] = next(row for row in processes if row['pid']==pid)
    status = Path(f'/proc/{pid}/status').read_text().splitlines()
    record['memory'] = {line.split(':',1)[0]:line.split(':',1)[1].strip()
                        for line in status if line.startswith(('VmRSS:','VmHWM:','VmSize:'))}
    public = smoke.call(['status'],'status')
    require(public['runtime']['process']['pid']==pid, 'Status did not rediscover the started runtime')
    record['public_status'] = public['runtime']
    stopped = smoke.call(['down'],'down',project=False)
    require(stopped.get('complete') is True and stopped.get('witness',{}).get('state')=='witnessed',
            'Down has no complete witnessed closure')
    record['down'] = stopped
    record['outside_closure'] = smoke.commands.observer.observe()
    require(record['outside_closure']==[], 'Runtime survived witnessed down')
    return record


def main(output, images):
    all_smokes = []
    receipt = dict(result='NOT RUN', qualification='author measurement; distribution profile; cached file pages; not cold disk',
                   first_initialized_home=[], restarted_home=[], cleanup=[])
    try:
        # Each pair's first startup uses an independently initialized state root.
        for index in range(10):
            pair = dict(index=index,samples={})
            receipt['first_initialized_home'].append(pair)
            for side in (('base','head') if index%2==0 else ('head','base')):
                smoke=prepare(output/f'fresh-{index}-{side}',images[side]);all_smokes.append(smoke)
                pair['samples'][side]=sample(smoke)
                save(output/'startup.json',receipt)
        smokes={side:prepare(output/('restart-'+side),images[side]) for side in ('base','head')}
        all_smokes.extend(smokes.values())
        for index in range(101):
            pair=dict(index=index,samples={})
            receipt['restarted_home'].append(pair)
            for side in (('base','head') if index%2==0 else ('head','base')):
                pair['samples'][side]=sample(smokes[side])
                save(output/'startup.json',receipt)
        receipt['summary']={}
        for condition in ('first_initialized_home','restarted_home'):
            pairs=receipt[condition]
            if condition=='restarted_home': pairs=pairs[1:]
            summary={}
            for side in ('base','head'):
                values=sorted(pair['samples'][side]['ms'] for pair in pairs)
                summary[side]=dict(count=len(values),p50_ms=statistics.median(values),
                                   p95_ms=values[math.ceil(.95*len(values))-1],max_ms=max(values))
            summary['median_paired_saved_ms']=statistics.median(pair['samples']['base']['ms']-pair['samples']['head']['ms'] for pair in pairs)
            receipt['summary'][condition]=summary
        receipt['result']='OBSERVED'
    except BaseException as error:
        receipt.update(result='FAIL',failure=str(error) or type(error).__name__)
        raise
    finally:
        for smoke in all_smokes:
            try:
                smoke.cleanup();smoke.save()
                receipt['cleanup'].append(dict(home=str(smoke.home),errors=smoke.record['cleanup'],
                                                outside=smoke.record['process_closure']))
            except Exception as error:
                receipt['cleanup'].append(dict(home=str(smoke.home),error=str(error)))
        save(output/'startup.json',receipt)
    require(all(row.get('errors')==[] and row.get('outside')==[] for row in receipt['cleanup']),
            'Fixture closure failed')
    print(json.dumps(receipt['summary']),flush=True)

if __name__=='__main__':
    root=Path(sys.argv[1]); main(root,json.loads((root/'images.json').read_text()))
