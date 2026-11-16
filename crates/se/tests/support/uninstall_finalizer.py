"""Public Windows uninstall, interrupted custody and ordinary-command recovery."""
import ctypes as C
from ctypes import wintypes as W
import hashlib,json,os,struct,subprocess,sys,time,traceback
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from uninstall_debugger import Debugger,bind,k,require

mode,root_arg,home_arg,host_arg,image_arg=sys.argv[1:]
root,home,host,image=map(Path,[root_arg,home_arg,host_arg,image_arg])
record=home/'standalone-install.json';journal=home/'uninstall-helper-cleanup.json'
report={'case':mode,'qualified':False};changed_attributes=[]
attributes=bind(k,'GetFileAttributesW',[W.LPCWSTR],W.DWORD)
set_attributes=bind(k,'SetFileAttributesW',[W.LPCWSTR,W.DWORD],W.BOOL)
file_id=bind(k,'GetFileInformationByHandleEx',[C.c_void_p,C.c_int,C.c_void_p,W.DWORD],W.BOOL)
create_file=bind(k,'CreateFileW',[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,C.c_void_p],C.c_void_p)
close=bind(k,'CloseHandle',[C.c_void_p],W.BOOL)

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def absent(path):
 try:path.lstat();return False
 except FileNotFoundError:return True

def directory_entries(path):
 try:return sorted(p.name for p in path.iterdir())
 except FileNotFoundError:return None

def wait_absent(paths,seconds=45):
 deadline=time.monotonic()+seconds
 while True:
  missing=[str(p) for p in paths if not absent(p)]
  if not missing:return
  if time.monotonic()>=deadline:raise AssertionError(('completion not witnessed',missing))
  time.sleep(.02)

def native_path(value):
 assert value['encoding']=='windows_utf16' and len(value['units'])<=32768
 assert all(isinstance(v,int) and 0<v<=65535 for v in value['units'])
 return Path(struct.pack('<'+'H'*len(value['units']),*value['units']).decode('utf-16-le'))

def readonly(path):
 before=attributes(str(path));assert before!=0xffffffff
 require(set_attributes(str(path),before|1),'set owned readonly control')
 assert attributes(str(path))&1;changed_attributes.append(path)

def copy_security(source,target):
 a=C.WinDLL('advapi32',use_last_error=True);P=C.c_void_p;D=W.DWORD
 get=bind(a,'GetNamedSecurityInfoW',[W.LPCWSTR,C.c_int,D,C.POINTER(P),C.POINTER(P),C.POINTER(P),C.POINTER(P),C.POINTER(P)],D)
 put=bind(a,'SetNamedSecurityInfoW',[W.LPCWSTR,C.c_int,D,P,P,P,P],D)
 free=bind(k,'LocalFree',[P],P)
 owner,group,dacl,sd=P(),P(),P(),P()
 code=get(str(source),1,7,C.byref(owner),C.byref(group),C.byref(dacl),None,C.byref(sd));assert code==0,('read own replacement descriptor',code)
 try:assert put(str(target),1,0x80000007,owner,group,dacl,None)==0,'protect own replacement record'
 finally:free(sd)

def verify_copy(path,debt):
 assert path.name.startswith('.se-stage-') and path.suffix=='.exe' and len(path.stem.removeprefix('.se-stage-'))==32
 assert path.parent==home or (path.parent.parent==home and path.parent.name.startswith('.se-uninstall-'))
 h=create_file(str(path),0x80,7,None,3,0x00200000,None)
 assert h not in [None,C.c_void_p(-1).value],'created copy unreadable'
 try:
  data=C.create_string_buffer(24);require(file_id(h,18,data,len(data)),'read independent copy identity')
  volume=struct.unpack_from('<Q',data.raw)[0]
  assert volume==int(debt['file']['volume']) and list(data.raw[8:24])==debt['file']['index'],'debt does not identify copied file'
 finally:require(close(h),'close independent identity resource')
 assert sha(path)==sha(host),'private copy differs from actual CLI'

original_image=sha(image);original_record=record.read_bytes()
retained={n:sha(home/n) for n in ['machine.json','credential','config.toml']}
copy=None;debt_bytes=None;replacement_image=None;replacement_record=None;foreign_copy=None;debugger=None

def at_carrier(debugger,pid,args):
 global copy,debt_bytes,replacement_image,replacement_record
 report['carrier_observed']=True
 report['base_same_image_without_custody']=absent(journal) and Path(args[0]).resolve()==image.resolve()
 assert not absent(journal),'durable separate-carrier custody absent before native child execution'
 debt_bytes=journal.read_bytes();debt=json.loads(debt_bytes);copy=native_path(debt['path'])
 assert Path(args[0]).resolve()==copy.resolve() and copy.resolve()!=image.resolve(),'carrier must execute a separately identified private copy'
 verify_copy(copy,debt);report['copy']=str(copy);report['debt_version']=debt['version']
 if mode in ['readonly','killed-recovery']:readonly(copy)
 if mode.startswith('killed'):
  # Stop before the carrier executes. Also stop its exact creator and every
  # debug-owned cleanup child, so only ordinary startup can retire this debt.
  debugger.crash_family()
 elif mode=='replacement-install':
  old_image=image.with_suffix('.original.exe');old_record=record.with_suffix('.original.json')
  image.rename(old_image);record.rename(old_record)
  image.write_bytes(host.read_bytes()+b'\nprivate replacement image marker\n')
  replacement=json.loads(original_record)
  replacement['files'][0]['sha256']=sha(image)
  record.write_text(json.dumps(replacement));copy_security(old_record,record)
  replacement_image=sha(image);replacement_record=record.read_bytes()
  report['replacement_image_sha256']=replacement_image

try:
 if mode=='readonly':readonly(image)
 debugger=Debugger(image,home,at_carrier)
 debug=debugger.run();report['debug']=debug
 assert copy is not None and debt_bytes is not None
 root_row=next(p for p in debug['processes'] if p['pid']==debug['root_pid'])
 if mode.startswith('killed'):
  assert root_row['exit']==222 and journal.read_bytes()==debt_bytes and copy.is_file(),'crash debt was not retained'
  assert sha(image)==original_image and record.read_bytes()==original_record,'pre-authorization crash changed installation'
  if mode=='killed-replacement':
   moved=copy.with_suffix('.preserved.exe');copy.rename(moved)
   copy.write_bytes(b'private foreign replacement; preserve exactly')
   copy_security(moved,copy);foreign_copy=copy.read_bytes()
  report['staging_before_recovery']=directory_entries(copy.parent)
  recovery=subprocess.run([str(host),'--json','--home',str(home),'status'],capture_output=True,timeout=35)
  report['recovery']={'exit':recovery.returncode,'stdout':recovery.stdout.decode(errors='replace'),'stderr':recovery.stderr.decode(errors='replace')}
  report['staging_after_recovery']=directory_entries(copy.parent)
  if mode=='killed-recovery':
   assert recovery.returncode==0,report['recovery']
   wait_absent([copy,journal])
  else:
   assert recovery.returncode!=0,'replacement copy debt incorrectly reported recovered'
   assert copy.read_bytes()==foreign_copy and journal.read_bytes()==debt_bytes,'recovery changed replacement copy or discarded custody'
  assert sha(image)==original_image and record.read_bytes()==original_record,'ordinary recovery removed installation'
 elif mode=='replacement-install':
  assert root_row['exit']==75,'parent lost deferred uninstall result'
  wait_absent([copy,journal]+([copy.parent] if copy.parent!=home else []))
  assert sha(image)==replacement_image and record.read_bytes()==replacement_record,'replacement installation changed'
 else:
  assert root_row['exit']==75,'parent lost deferred uninstall result'
  wait_absent([image,record,copy,journal]+([copy.parent] if copy.parent!=home else []))
 # Uninstall may append its own durable records; these immutable home facts and
 # the independent repository marker must survive every case.
 for name in ['machine.json','credential','config.toml']:assert sha(home/name)==retained[name],('retained home bytes changed',name)
 assert (root/'repository/user-work.txt').read_bytes()==b'retained user work'
 report['qualified']=True
except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc())
finally:
 if debugger is not None:report['debug_events']=debugger.events
 for path in changed_attributes:
  if not absent(path):require(set_attributes(str(path),attributes(str(path))&~1),'restore owned readonly fixture control')
 (root/'uninstall-finalizer-report.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report))
raise SystemExit(0 if report['qualified'] else 1)
