"""Re-observe the retained Linux package without rebuilding its product bytes."""
import json,os,shutil,subprocess,sys
from pathlib import Path
from build import digest,save,unpack
root=Path(sys.argv[1]).resolve()
prior=Path(os.environ['STARTUP_REUSE_ROOT']).resolve()
root.mkdir(parents=True,exist_ok=False)
archive=next((prior/'archive').glob('*.tar.gz'))
expected='85ca4e13d51bd432a64d8265bdfa23c634cace0941df7755905e6ce95be15e5b'
if digest(archive)!=expected:raise ValueError('Retained Linux archive differs')
(root/'archive').mkdir()
retained=root/'archive'/archive.name
shutil.copyfile(archive,retained)
build=json.loads((prior/'build.json').read_text())
if build['source_commit']!='329efa795e4739319e612fc7818bfeac786c83d1':raise ValueError('Retained Linux source differs')
image,manifest=unpack(retained,root/'extracted',build)
save(root/'build.json',build);save(root/'manifest.json',manifest)
save(root/'image.json',dict(image=str(image),sha256=digest(image),bytes=image.stat().st_size,source=build['source_commit'],archive=dict(path=str(retained),bytes=retained.stat().st_size,sha256=expected),stripping=build['stripping']))
save(root/'reuse.json',dict(prior_run=43653318293,archive_sha256=expected,scope='same Linux package, new hosted runner; syscall diagnostic only'))
env=dict(os.environ,STARTUP_DIAGNOSTIC_ONLY='1',STARTUP_SYSCALL_TRACE='1')
subprocess.run([sys.executable,'-B',Path(__file__).with_name('observe.py'),root],env=env,check=True,timeout=1800)
