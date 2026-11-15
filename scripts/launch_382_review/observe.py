"""Independent native paired scope and public launch controls."""
import hashlib,json,os,shutil,subprocess,sys
from pathlib import Path
from public_failure import run as public_failure
SOURCE=Path(__file__).resolve().parents[2]
OBSERVER=Path(os.environ['SE382_OBSERVER']).resolve()
BASE='bda8e1e7a2c7905cb9b8537c35aad29e9242cb99'
HEAD='6fa72f37928db40c98de8238d9a39d92d2b21d66'
CASES={
 'same_birth_descendant_exec_settles_without_duplicate_obligations':False,
 'persistent_descendant_esrch_stays_unknown_and_keeps_original_bound':False,
 'root_image_unreadability_never_gets_descendant_retry':True,
 'malformed_image_keeps_its_reason_without_retry':True,
 'descendant_access_denial_is_not_a_settling_exec':True,
 'different_root_birth_never_becomes_live_original':True,
}
root=Path(os.environ['RUNNER_TEMP'])/'launch382-independent';root.mkdir()
summary={'product_head':HEAD,'base':BASE,'arms':[]}
def save(): (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def command(args,cwd,env,log,timeout=2400):
    with (root/(log+'.stdout')).open('wb') as out,(root/(log+'.stderr')).open('wb') as err:
        result=subprocess.run(args,cwd=cwd,env=env,stdout=out,stderr=err,timeout=timeout)
    return result.returncode
native=subprocess.check_output(['rustc','--print','host-tuple'],text=True).strip()
assert native=='aarch64-apple-darwin'
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=OBSERVER,text=True).strip()=='844fac50c7aae28f8a40afb7ef2be3cb2fc2d331'
library=root/'boundary.dylib';outside=root/'outside'
subprocess.run(['/usr/bin/cc','-std=c11','-dynamiclib','-Wall','-Wextra','-Werror',str(SOURCE/'crates/se-proc/tests/support/launch_382_review/interpose.c'),'-o',str(library),'-lproc'],check=True)
subprocess.run(['/usr/bin/cc','-std=c11','-Wall','-Wextra','-Werror',str(SOURCE/'scripts/launch_382_review/outside.c'),'-o',str(outside),'-lproc'],check=True)
overlays=['crates/se-proc/tests/launch_382_review.rs','crates/se-proc/tests/support/macos_runtime/provider.rs','crates/se-proc/tests/support/launch_382_review/interpose.c']
summary['inputs']={'observer_source':subprocess.check_output(['git','rev-parse','HEAD'],cwd=OBSERVER,text=True).strip(),'judge_source':subprocess.check_output(['git','rev-parse','HEAD'],cwd=SOURCE,text=True).strip(),'native_host':native,'library_sha256':digest(library),'outside_sha256':digest(outside),'overlay_sha256':{p:digest(SOURCE/p) for p in overlays}}
save()
for arm,revision in [('base',BASE),('head',HEAD)]:
    checkout=root/('source-'+arm)
    subprocess.run(['git','worktree','add','--detach',str(checkout),revision],cwd=SOURCE,check=True)
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=checkout,text=True).strip()==revision
    for p in overlays:
        dest=checkout/p;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(SOURCE/p,dest)
    target=root/('target-'+arm);env=dict(os.environ,CARGO_TARGET_DIR=str(target),CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0')
    row={'arm':arm,'source':revision,'cases':[]};summary['arms'].append(row);save()
    code=command(['cargo','build','--locked','-p','se','--bin','se'],checkout,env,arm+'-se-build');row['image_build_exit']=code;save()
    if code:raise RuntimeError('Native product build failed')
    code=command(['cargo','test','--locked','-p','se-proc','--test','launch_382_review','--no-run','--message-format=json'],checkout,env,arm+'-judge-build');row['judge_build_exit']=code;save()
    if code:raise RuntimeError('Reviewer fixture did not compile; no native verdict')
    events=[json.loads(line) for line in (root/(arm+'-judge-build.stdout')).read_text().splitlines()]
    paths={e['executable'] for e in events if e.get('reason')=='compiler-artifact' and e.get('target',{}).get('name')=='launch_382_review' and e.get('executable')}
    assert len(paths)==1
    binary=Path(paths.pop());image=target/'debug/se'
    row.update(binary_sha256=digest(binary),image_sha256=digest(image));save()
    for name,base_pass in CASES.items():
        case=root/(arm+'-'+name);case.mkdir()
        testenv=dict(env,DYLD_INSERT_LIBRARIES=str(library),SE382_CONTROL_DIR=str(case),SE_MACOS_HELPER=str(image))
        code=command([str(binary),'--exact',name,'--nocapture'],checkout,testenv,arm+'-'+name,timeout=90)
        home=Path((case/'native-home').read_text()) if (case/'native-home').exists() else None
        custody=[]
        if home and home.exists():
            for pinfile in home.glob('pin-*.json'):
                pin=json.loads(pinfile.read_text());identity=pin['identity'];pid=str(identity['pid'])
                observed=json.loads(subprocess.check_output([str(outside),pid],text=True))
                expected=identity['start']['MacOs'];same=observed.get('seconds')==int(expected['seconds']) and observed.get('microseconds')==expected['microseconds']
                if observed['state']=='record' and same and observed['status']!=5:raise RuntimeError('Original owned native process remains; stop this dependent path')
                custody.append({'expected':identity,'actual':observed})
            shutil.copytree(home,case/'native-home-evidence',ignore=shutil.ignore_patterns('next-child','host-only-descriptor'))
        passed=code==0;expected=arm=='head' or base_pass
        row['cases'].append({'name':name,'exit':code,'passed':passed,'expected_pass':expected,'custody':custody});save()
        if home is None:raise RuntimeError('Fixture stopped before owning a native scope')
    public=public_failure(image,OBSERVER,root/(arm+'-public-failure'),library)
    row['public_failure']=public;save()
    # Builds and every owned process are joined before releasing our compiler cache.
    shutil.rmtree(target)
summary['qualified']=all(all(c['passed']==c['expected_pass'] for c in a['cases']) and a['public_failure']['passed']==(a['arm']=='head') for a in summary['arms'])
save()
print(json.dumps({'qualified':summary['qualified'],'arms':[{'arm':a['arm'],'cases':[(c['name'],c['passed']) for c in a['cases']],'public_failure':a['public_failure']['passed']} for a in summary['arms']]}),flush=True)
raise SystemExit(0 if summary['qualified'] else 1)
