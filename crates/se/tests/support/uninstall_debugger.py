"""Exact owned-process control at native child creation, without timing hooks."""
import ctypes as C
from ctypes import wintypes as W
import os,subprocess,time

assert os.name == 'nt'
H=C.c_void_p;D=W.DWORD;P=H;S=C.c_size_t
k=C.WinDLL('kernel32',use_last_error=True)
n=C.WinDLL('ntdll');shell=C.WinDLL('shell32',use_last_error=True)
def bind(lib,name,args,result):
 f=getattr(lib,name);f.argtypes=args;f.restype=result;return f
class Startup(C.Structure):
 _fields_=[('cb',D),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',D),('y',D),('width',D),('height',D),('chars_x',D),('chars_y',D),('fill',D),('flags',D),('show',W.WORD),('reserved_size',W.WORD),('reserved_bytes',P),('stdin',H),('stdout',H),('stderr',H)]
class ProcessInfo(C.Structure):
 _fields_=[('process',H),('thread',H),('pid',D),('tid',D)]
class Creation(C.Structure):
 _fields_=[('file',H),('process',H),('thread',H),('base',P),('debug_offset',D),('debug_size',D),('thread_local',P),('start',P),('name',P),('unicode',W.WORD)]
class ExceptionRecord(C.Structure):
 _fields_=[('code',D),('flags',D),('next',P),('address',P),('count',D),('parameters',S*15)]
class ExceptionInfo(C.Structure):
 _fields_=[('record',ExceptionRecord),('first_chance',D)]
class Load(C.Structure):
 _fields_=[('file',H),('base',P),('offset',D),('size',D),('name',P),('unicode',W.WORD)]
class EventInfo(C.Union):
 _fields_=[('creation',Creation),('exception',ExceptionInfo),('load',Load),('exit',D)]
class Event(C.Structure):
 _fields_=[('code',D),('pid',D),('tid',D),('info',EventInfo)]
class Unicode(C.Structure):
 _fields_=[('length',W.USHORT),('capacity',W.USHORT),('buffer',P)]
create=bind(k,'CreateProcessW',[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,D,P,W.LPCWSTR,C.POINTER(Startup),C.POINTER(ProcessInfo)],W.BOOL)
wait=bind(k,'WaitForDebugEvent',[C.POINTER(Event),D],W.BOOL)
resume=bind(k,'ContinueDebugEvent',[D,D,D],W.BOOL)
kill_on_exit=bind(k,'DebugSetProcessKillOnExit',[W.BOOL],W.BOOL)
close=bind(k,'CloseHandle',[H],W.BOOL)
duplicate=bind(k,'DuplicateHandle',[H,H,H,C.POINTER(H),D,W.BOOL,D],W.BOOL)
terminate=bind(k,'TerminateProcess',[H,W.UINT],W.BOOL)
signaled=bind(k,'WaitForSingleObject',[H,D],D)
query=bind(n,'NtQueryInformationProcess',[H,C.c_int,P,D,C.POINTER(D)],C.c_long)
argv_native=bind(shell,'CommandLineToArgvW',[W.LPCWSTR,C.POINTER(C.c_int)],C.POINTER(W.LPWSTR))
free=bind(k,'LocalFree',[H],H)

def require(ok,what):
 if not ok:raise OSError(C.get_last_error(),what)

def command_line(handle):
 size=D();query(handle,60,None,0,C.byref(size))
 assert 0<size.value<=131072,'bounded native command line required'
 data=C.create_string_buffer(size.value)
 status=query(handle,60,data,len(data),C.byref(size));assert status>=0,('native command line unreadable',status)
 text=C.cast(data,C.POINTER(Unicode)).contents
 start=C.addressof(data);assert text.length%2==0 and start<=text.buffer<=start+len(data)-text.length
 return C.string_at(text.buffer,text.length).decode('utf-16-le')

def arguments(text):
 count=C.c_int();parts=argv_native(text,C.byref(count));require(bool(parts),'parse observed process command line')
 try:return [parts[i] for i in range(count.value)]
 finally:free(parts)

class Debugger:
 def __init__(self,image,home,on_carrier):
  self.image=image;self.home=home;self.on_carrier=on_carrier
  self.processes={};self.events=[];self.carrier=None;self.pending=None;self.crashing=False
 def stop(self,pid,code):
  item=self.processes[pid]
  # The same retained debug handle supplies the full command line and signal.
  if signaled(item['handle'],0)==0:return
  try:text=command_line(item['handle'])
  except BaseException:
   if signaled(item['handle'],0)==0:return
   raise
  assert text==item['command_line'] and item['argv'], 'owned process command identity changed'
  if not terminate(item['handle'],code):
   require(signaled(item['handle'],0)==0,'stop exact observed fixture process')
 def crash_family(self):
  self.crashing=True
  for pid,item in self.processes.items():
   if signaled(item['handle'],0)==258:
    self.stop(pid,222 if pid==self.root_pid else 221 if pid==self.carrier else 223)
 def observe_creation(self,event):
  raw=event.info.creation;held=H()
  require(duplicate(H(-1),raw.process,H(-1),C.byref(held),0,False,2),'retain exact debug-created process')
  try:
   text=command_line(held);args=arguments(text);assert args,'created process has no command identity'
   self.processes[event.pid]={'handle':held.value,'command_line':text,'argv':args}
   self.events.append({'pid':event.pid,'command_line':text,'argv':args})
   return args
  except BaseException:
   close(held);raise
  finally:
   if raw.file:require(close(raw.file),'close debug image file resource')
 def run(self):
  line=subprocess.list2cmdline([str(self.image),'--json','--home',str(self.home),'uninstall'])
  startup=Startup();startup.cb=C.sizeof(startup);process=ProcessInfo()
  require(create(str(self.image),C.create_unicode_buffer(line),None,None,False,0x11,None,None,C.byref(startup),C.byref(process)),'start owned console/debug fixture')
  self.root_pid=process.pid
  require(close(process.thread),'close original thread resource');require(close(process.process),'close original process resource')
  require(kill_on_exit(False),'disable implicit debugger-exit process termination')
  deadline=time.monotonic()+110
  try:
   while time.monotonic()<deadline:
    event=Event()
    if not wait(C.byref(event),200):
     assert C.get_last_error()==121,'native debug wait failed'
     if self.processes and all('exit' in p for p in self.processes.values()):break
     continue
    self.pending=(event.pid,event.tid)
    disposition=0x10002
    if event.code==3:
     args=self.observe_creation(event)
     text=self.processes[event.pid]['command_line']
     if self.crashing:
      self.stop(event.pid,223)
     elif event.pid==self.root_pid:
      assert text==line,'root command differs from constructed invocation'
     elif len(args)==2 and args[1]=='__uninstall-carrier':
      assert self.carrier is None,'multiple native carriers'
      self.carrier=event.pid
      self.on_carrier(self,event.pid,args)
    elif event.code==6 and event.info.load.file:
     require(close(event.info.load.file),'close debug module file resource')
    elif event.code==5:
     self.processes[event.pid]['exit']=event.info.exit
    elif event.code==1:
     if event.info.exception.record.code not in [0x80000003,0x80000004]:disposition=0x80010001
    require(resume(event.pid,event.tid,disposition),'continue owned native debug event');self.pending=None
   else:raise TimeoutError('owned uninstall debug family exceeded deadline')
   assert self.carrier is not None,'separate native carrier was never observed'
   assert all('exit' in p for p in self.processes.values()),'owned process exit missing'
   return {'root_pid':self.root_pid,'carrier_pid':self.carrier,'processes':[{k:v for k,v in p.items() if k!='handle'}|{'pid':pid} for pid,p in self.processes.items()]}
  finally:
   # On failure, signal only handles whose complete command lines were read.
   for pid,item in reversed(list(self.processes.items())):
    if signaled(item['handle'],0)==258:self.stop(pid,224)
   if self.pending:
    require(resume(*self.pending,0x10002),'release final debug event');self.pending=None
   end=time.monotonic()+5
   while any(signaled(p['handle'],0)==258 for p in self.processes.values()) and time.monotonic()<end:
    event=Event()
    if wait(C.byref(event),100):
     if event.code==3:
      self.observe_creation(event);self.stop(event.pid,224)
     elif event.code==6 and event.info.load.file:close(event.info.load.file)
     require(resume(event.pid,event.tid,0x10002),'drain exact fixture shutdown event')
   for item in self.processes.values():
    require(signaled(item['handle'],0)==0,'exact fixture process exit not witnessed')
    require(close(item['handle']),'close retained observed process')
