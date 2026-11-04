"""Author first-hour consumer of a real candidate release archive; no provider."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--archive',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
root=a.output.resolve();root.mkdir(parents=True,exist_ok=False)
bundle=root/'bundle';bundle.mkdir()
with tarfile.open(a.archive) as archive:
    archive.extractall(bundle,filter='data')
installers=list(bundle.glob('*/install.sh'));assert len(installers)==1
owner=root/"stranger O’Brien's home";owner.mkdir(mode=0o700)
state=owner/'state'
repo=root/'repository';repo.mkdir()
work=repo/'user-work.txt';work.write_bytes(b'Existing user work survives first setup.\n')
env={k:v for k,v in os.environ.items() if not k.startswith(('SE_','STATEENGINE_','CODEX_','CLAUDE'))}
env.update(HOME=str(owner),USERPROFILE=str(owner),SE_HOME=str(state),SHELL='/bin/sh')
se=owner/'.local/bin/se'
calls=0
def call(*args,install=False):
    global calls
    calls+=1
    argv=['/bin/sh',str(installers[0])] if install else [str(se),'--home',str(state),'--json',*args]
    r=subprocess.run(argv,env=env,cwd=repo,capture_output=True,timeout=180)
    prefix=root/f'call-{calls:02d}'
    prefix.with_suffix('.stdout').write_bytes(r.stdout);prefix.with_suffix('.stderr').write_bytes(r.stderr)
    prefix.with_suffix('.exit').write_text(str(r.returncode))
    return r
def ok(*args,**kwargs):
    r=call(*args,**kwargs);assert r.returncode==0,(args,r.stdout,r.stderr)
    return json.loads(r.stdout)
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
try:
    installed=call(install=True);assert installed.returncode==0,installed.stderr
    assert se.is_file() and (state/'standalone-install.json').is_file()
    assert (state/'machine.json').is_file() and not (state/'state.db').exists()
    assert not (state/'credential').exists()
    machine=digest(state/'machine.json')
    print('ok 1 - real archive install creates machine identity without a store',flush=True)
    before=ok('status');assert before['setup']['state']=='not-set-up',before
    resume=call('resume');assert resume.returncode!=0
    error=json.loads(resume.stdout);assert error['code']=='setup-required',error
    assert machine==digest(state/'machine.json') and not (state/'state.db').exists()
    print('ok 2 - installed-only identity remains fresh on status and resume',flush=True)
    initialized=ok('init','--repo',str(repo),'--name','Installed first-hour consumer','--provider','claude')
    assert initialized['owner']['human_id']
    assert (state/'state.db').is_file() and (state/'credential').is_file()
    assert machine==digest(state/'machine.json')
    assert ok('status')['setup']['state']=='configured'
    assert work.read_bytes()==b'Existing user work survives first setup.\n'
    print('ok 3 - installed binary initializes without identity surgery or lost user work',flush=True)
finally:
    if se.exists():
        down=ok('down');assert down['complete'],down
        assert not (state/'endpoint.json').exists()
        if (state/'runtime.lock').exists():
            with (state/'runtime.lock').open('rb') as lock:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        (root/'outside-closure.json').write_text(json.dumps(dict(public_down=True,endpoint_absent=True,runtime_lease_free=True,provider_launched=False),indent=2))
print('1..3',flush=True)
