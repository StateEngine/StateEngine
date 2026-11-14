"""Build frozen uninstrumented distribution images on one disposable runner."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
BASE='73bfce70aa64e63f869378656537821866f54bd0'
HEAD='11ee8741386a99eaa7f5f8a0a1d81ce723156030'


def save(path,value):
    path.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n')


def run(command,cwd,environment,log,timeout=2700):
    with log.open('xb') as output:
        code=subprocess.run(command,cwd=cwd,env=environment,stdout=output,stderr=subprocess.STDOUT,
                            timeout=timeout).returncode
    if code: raise RuntimeError(f'{log.name} failed with exit {code}')


def main():
    if sys.platform!='linux': raise RuntimeError('Linux measurement only')
    output=Path(sys.argv[1]).resolve();output.mkdir(parents=True,exist_ok=False)
    images=output/'images';images.mkdir()
    revision=subprocess.check_output(['git','rev-parse',HEAD+'^{commit}'],cwd=ROOT,text=True).strip()
    subprocess.run(['git','merge-base','--is-ancestor',BASE,revision],cwd=ROOT,check=True)
    facts=dict(cpu=Path('/proc/cpuinfo').read_text(),os=platform.platform(),
               rustc=subprocess.check_output(['rustc','-Vv'],text=True),
               cargo=subprocess.check_output(['cargo','-V'],text=True),
               flags={k:v for k,v in os.environ.items() if k in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS')},
               profile='distribution; opt-level=s; thin LTO; one codegen unit; sha2 opt-level=3',
               load_before=os.getloadavg())
    save(output/'environment.json',facts)
    manifest={}
    environments={};trees={};targets={}
    for side,source in (('base',BASE),('head',revision)):
        tree=output/('source-'+side);target=output/('target-'+side)
        subprocess.run(['git','worktree','add','--detach',str(tree),source],cwd=ROOT,check=True)
        environment=dict(os.environ,CARGO_TARGET_DIR=str(target),CARGO_INCREMENTAL='0',
                         CARGO_TERM_COLOR='never',CARGO_BUILD_JOBS='2')
        trees[side],environments[side],targets[side]=tree,environment,target
        command=['cargo','build','-p','se','--bin','se','--profile','distribution','--locked',
                 '--no-default-features','--features','remote','--jobs','2']
        started=time.monotonic();run(command,tree,environment,output/(side+'-build.log'))
        image=images/side;shutil.copyfile(target/'distribution/se',image);image.chmod(0o500)
        with image.open('rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
        manifest[side]=dict(source=source,image=str(image),sha256=digest,bytes=image.stat().st_size,
                            command=command,build_seconds=time.monotonic()-started)
        save(output/'images.json',manifest)
    # Timed executables are copied before adding this disposable measurement example.
    example=trees['head']/'crates/se-proc/examples/digest_measure.rs'
    example.parent.mkdir(exist_ok=True)
    shutil.copyfile(ROOT/'crates/se-proc/examples/digest_measure.rs',example)
    run(['cargo','build','-p','se-proc','--example','digest_measure','--features','native-sha256',
         '--profile','distribution','--locked','--jobs','2'],trees['head'],environments['head'],
        output/'digest-build.log')
    executable=targets['head']/'distribution/examples/digest_measure'
    digest_results=[]
    # Same retained image, compiler, CPU, chunking and profile for both backends.
    for mode,backends in (('file',('sha2','native')),('memory',('native','sha2'))):
        for backend in backends:
            measured=subprocess.check_output([str(executable),manifest['base']['image'],backend,mode],
                                             text=True,timeout=180)
            value=json.loads(measured);digest_results.append(value)
            save(output/'digest.json',digest_results)
            if value['digest']!=manifest['base']['sha256']:
                raise RuntimeError('Backend disagrees with retained input digest')
    subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('startup.py')),str(output)],
                   cwd=ROOT,check=True,timeout=900)
    tests=['image_cache','image_cache_upgrade','ipc_peer_pin_independent','native_ipc',
           'remote_hint_boundary_independent','unix_socket_cleanup']
    for side in ('base','head'):
        command=['cargo','test','-p','se-proc','--locked','--no-default-features','--jobs','2']
        if side=='head': command+=['--features','native-sha256']
        for test in tests: command+=['--test',test]
        command+=['--','--test-threads=1']
        environment=dict(environments[side],CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0')
        run(command,trees[side],environment,output/(side+'-existing-controls.log'),timeout=1200)
    # Independent minimal consumer must also build and exercise the original backend.
    run(['cargo','test','-p','se-proc','--locked','--no-default-features','--test','image_cache',
         '--jobs','2','--','--test-threads=1'],trees['head'],
        dict(environments['head'],CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0'),
        output/'minimal-existing-controls.log',timeout=1200)
    facts['load_after']=os.getloadavg();save(output/'environment.json',facts)
    print(json.dumps(dict(images=manifest,result='OBSERVED',controls='completed')),flush=True)

if __name__=='__main__': main()
