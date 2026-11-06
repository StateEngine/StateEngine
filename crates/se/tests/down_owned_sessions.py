#!/usr/bin/env python3
"""Regression: public down stops eight stock Codex roots within its original bound.
Linux only; no account or paid model calls. An isolated loopback Responses fixture
asks each real provider to write a file, then keeps all eight sessions resident.
Run: python3 down_owned_sessions.py --se /absolute/se --codex /absolute/codex --output NEW_DIRECTORY
"""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse,sys,os,json,re,subprocess,time,traceback,hashlib,threading,secrets,uuid,shlex,fcntl,sqlite3
class NativeWitness:
 def __init__(self,pid):
  self.pid=pid;row=Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split();self.birth=row[19]
  self.identity={'pid':pid,'birth_ticks':self.birth,'image':os.readlink(f'/proc/{pid}/exe')}
 def exited(self):
  try:
   row=Path(f'/proc/{self.pid}/stat').read_text().rsplit(') ',1)[1].split();return row[19]!=self.birth or row[0]=='Z'
  except FileNotFoundError:return True
 def close(self):pass
class ReturnModel:
 def __init__(self,root,repo):
  self.root=Path(root);self.repo=Path(repo);self.phase=0;self.nonce=secrets.token_hex(12);self.requests=[];self.first=self.repo/'loopback-work.txt';self.second=self.repo/'resumed-work.txt';self.receipts={};self.peer=None;owner=self
  class Handler(BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def reply(self,data,kind):
    self.send_response(200);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
   def do_GET(self):self.reply(json.dumps({'object':'list','data':[{'id':'se-loopback','object':'model','owned_by':'local-protocol-fixture'}]}).encode(),'application/json')
   def do_POST(self):
    try:
     size=int(self.headers['Content-Length']);assert size<=2097152;body=json.loads(self.rfile.read(size));phase=owner.phase;prior=f'FIRST_WORK_DONE_{owner.nonce}'
     owner.requests.append({'phase':phase,'path':self.path,'saw_prior_assistant':prior in json.dumps(body),'body':body});(owner.root/'model-requests.json').write_text(json.dumps(owner.requests,indent=2),encoding='utf-8')
     item=owner.plan(body)
     if item['type']=='function_call':
      args=item['arguments'];events=[('response.output_item.added',{'output_index':0,'item':{**item,'arguments':''}}),('response.function_call_arguments.delta',{'item_id':item['id'],'output_index':0,'delta':args}),('response.function_call_arguments.done',{'item_id':item['id'],'output_index':0,'arguments':args}),('response.output_item.done',{'output_index':0,'item':item})]
     else:
      text=item['content'][0]['text'];events=[('response.output_item.added',{'output_index':0,'item':{**item,'status':'in_progress','content':[]}}),('response.output_text.delta',{'item_id':item['id'],'output_index':0,'content_index':0,'delta':text}),('response.output_item.done',{'output_index':0,'item':item})]
     response={'id':f'resp_{len(owner.requests)}','object':'response','created_at':int(time.time()),'status':'completed','model':'se-loopback','output':[item],'error':None,'usage':{'input_tokens':0,'output_tokens':0,'total_tokens':0}}
     events=[('response.created',{'response':{**response,'output':[],'status':'in_progress'}}),*events,('response.completed',{'response':response})]
     payload=''.join('event: '+name+'\ndata: '+json.dumps({'type':name,'sequence_number':i,**value})+'\n\n' for i,(name,value) in enumerate(events)).encode();self.reply(payload,'text/event-stream')
    except Exception as error:
     import traceback
     (owner.root/'model-error.txt').write_text(traceback.format_exc());self.send_error(500,str(error))
  self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
 def call(self,cid,name,args,namespace=None):
  item={'type':'function_call','id':'fc_'+cid,'call_id':cid,'name':name,'arguments':json.dumps(args),'status':'completed'}
  if namespace:item['namespace']=namespace
  return item
 def mcp(self,body,cid,name,args):
  for tool in body['tools']:
   if tool.get('type')=='namespace' and any(x.get('name')==name for x in tool.get('tools',[])):return self.call(cid,name,args,tool['name'])
   if tool.get('name','').endswith('__'+name) or tool.get('name')==name:return self.call(cid,tool['name'],args)
  raise RuntimeError('Stock provider did not expose required MCP tool '+name)
 def shell(self,body,cid,cmd):
  tools={x.get('name'):x for x in body['tools']};tool=next((x for x in ['exec_command','shell_command','shell'] if x in tools),None);assert tool,'Stock shell tool is absent'
  key='cmd' if tool=='exec_command' else 'command'
  if tool=='shell':cmd=['powershell.exe','-NoProfile','-Command',cmd] if os.name=='nt' else ['/bin/sh','-c',cmd]
  return self.call(cid,tool,{key:cmd,'workdir':str(self.repo)})
 def write_command(self,leaf,text):
  if os.name=='nt':return '[IO.File]::WriteAllText('+repr(leaf)+','+repr(text.rstrip('\n'))+'+[char]10)'
  return 'printf %s '+shlex.quote(text)+' > '+shlex.quote(leaf)
 def key(self,cid):return str(uuid.uuid5(uuid.NAMESPACE_OID,self.nonce+cid))
 def done(self,text):return {'type':'message','id':'msg_'+str(len(self.requests)),'role':'assistant','status':'completed','content':[{'type':'output_text','text':text,'annotations':[]}]}
 def save(self,name,value):
  self.receipts[name]=value;(self.root/(name+'.json')).write_text(json.dumps(value,indent=2),encoding='utf-8')
 def configure(self,home):
  home.mkdir(mode=0o700);(home/'config.toml').write_text('model="se-loopback"\nmodel_provider="local_fixture"\napproval_policy="never"\nsandbox_mode="workspace-write"\n[model_providers.local_fixture]\nname="local owned Responses fixture"\n'+f'base_url="http://127.0.0.1:{self.server.server_port}/v1"\n'+'wire_api="responses"\nrequires_openai_auth=false\nsupports_websockets=false\nrequest_max_retries=0\nstream_max_retries=0\n',encoding='utf-8')
 def close(self):self.server.shutdown();self.server.server_close();self.thread.join()

parser=argparse.ArgumentParser(description=__doc__)
for name in ['se','codex','output']:parser.add_argument('--'+name,type=Path,required=True)
parser.add_argument('--block-writer',action='store_true',help='hold a real SQLite writer to require a named incomplete stop')
args=parser.parse_args();assert sys.platform=='linux','Linux native observer required'
root=args.output.resolve();root.mkdir(mode=0o700);binary=args.se.resolve()
home=root/'profile';home.mkdir(mode=0o700);state=home/'state';repo=home/'repo';repo.mkdir();(repo/'user.txt').write_text('preserved\n')
env={k:v for k,v in os.environ.items() if not k.startswith(('SE_','STATEENGINE_','SECODE_','CODEX_','CLAUDE','OPENAI','ANTHROPIC')) and not any(x in k for x in ['TOKEN','SECRET','API_KEY','PROXY'])};env.update(HOME=str(home),USERPROFILE=str(home),CODEX_HOME=str(home/'.codex'),NO_PROXY='127.0.0.1,localhost')
codex=str(args.codex.resolve())
class Model(ReturnModel):
 def plan(self,body):
  ids=re.findall(r'SE_DOWN_(\d+)',json.dumps(body.get('input',[])));assert ids
  idx=ids[-1];cid='write_'+idx;outputs={x['call_id']:x for x in body.get('input',[]) if x.get('type')=='function_call_output'}
  if cid not in outputs:return self.shell(body,cid,self.write_command('work-'+idx+'.txt',self.nonce+'\n'))
  assert (repo/('work-'+idx+'.txt')).read_text()==self.nonce+'\n'
  (root/('done-'+idx)).write_text('done');return self.done('DONE '+idx)
model=Model(root,repo);pins={};calls=[];lock=None;result={'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
def call(label,*args,required=True):
 t=time.monotonic();p=subprocess.run([str(binary),'--home',str(state),'--json',*map(str,args)],cwd=repo,env=env,capture_output=True,stdin=subprocess.DEVNULL,timeout=75)
 (root/(label+'.stdout')).write_bytes(p.stdout);(root/(label+'.stderr')).write_bytes(p.stderr);calls.append({'label':label,'code':p.returncode,'seconds':time.monotonic()-t});print(calls[-1],flush=True)
 if required:assert p.returncode==0,(label,p.stdout,p.stderr)
 return json.loads(p.stdout) if p.stdout else None
try:
 init=call('init','init','--repo',repo,'--name','Down regression','--agent','Down0','--provider','codex','--model','se-loopback');project=init['project']['id'];first=init['agent']['id'];model.configure(home/'.codex')
 config=state/'config.toml';config.write_text(config.read_text().replace('[providers.codex]','[providers.codex]\ncommand = '+json.dumps(codex),1));call('up','up')
 for idx in range(8):
  agent=first if idx==0 else call('add-'+str(idx),'--project',project,'agent','add','Down'+str(idx),'--provider','codex','--model','se-loopback')['agent']['id']
  call('launch-'+str(idx),'--project',project,'launch',agent,'--detach','--task','SE_DOWN_'+str(idx)+': write your assigned work file.')
  until=time.monotonic()+60
  while not (root/('done-'+str(idx))).exists() and time.monotonic()<until:time.sleep(.1)
  assert (root/('done-'+str(idx))).exists(),'work absent'
 before=call('before','--project',project,'status');roots=[a['session']['process']['pid'] for a in before['agents']['items'] if a['session']['state']=='running'];assert len(roots)==8
 for pid in [before['runtime']['process']['pid'],*roots]:
  pin=NativeWitness(pid);pin.identity['command']=Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0',b' ').decode();pins[pid]=pin
 result['identities']={pid:p.identity for pid,p in pins.items()}
 if args.block_writer:
  lock=sqlite3.connect(state/'state.db');lock.execute('BEGIN IMMEDIATE')
 result['down']=call('down','down',required=False);time.sleep(.5);result['outside_after_down']={pid:p.exited() for pid,p in pins.items()};print('OUTSIDE',result['outside_after_down'],flush=True)
except Exception:result['error']=traceback.format_exc();print(result['error'],flush=True)
finally:
 if lock is not None:lock.rollback();lock.close()
 try:
  if args.block_writer and result.get('down',{}).get('complete') is False:
   commands=re.findall(r'`([^`]+)`',result['down']['witness']['detail'])
   assert len(commands)>=2,'literal cleanup commands absent'
   for index,command in enumerate(commands):
    words=shlex.split(command);assert words[0]=='se' and words[words.index('--home')+1]==str(state)
    if 'stop' in words:assert words[words.index('--project')+1]==project
    p=subprocess.run([str(binary),'--json',*words[1:]],cwd=repo,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=75)
    (root/f'printed-retry-{index}.stdout').write_bytes(p.stdout);(root/f'printed-retry-{index}.stderr').write_bytes(p.stderr)
    assert p.returncode==0,(command,p.stdout,p.stderr)
    assert json.loads(p.stdout)['complete'], 'printed cleanup command did not witness completion'
   result['printed_retry_executed']=True
  elif pins and not all(p.exited() for p in pins.values()):
   call('recovery-status','status',required=False);call('recovery-stop','stop','--all',required=False);call('recovery-down','down',required=False)
  time.sleep(.5);result['outside_final']={pid:p.exited() for pid,p in pins.items()};result['endpoint_absent']=not (state/'endpoint.json').exists();result['user_work_preserved']=(repo/'user.txt').read_text()=='preserved\n'
 except Exception:result['cleanup_error']=traceback.format_exc()
 model.close();result['calls']=calls;(root/'result.json').write_text(json.dumps(result,indent=2));print('RESULT',json.dumps({k:v for k,v in result.items() if k not in ('down','identities','calls')}),flush=True)
 for pin in pins.values():pin.close()

assert 'error' not in result,result.get('error')
assert 'cleanup_error' not in result,result.get('cleanup_error')
if args.block_writer:
 assert result['down'].get('complete') is False, 'busy writer invented a successful native stop'
 assert len(result['down']['stops'])==8, 'incomplete shutdown omitted owned agents'
 detail=result['down']['witness']['detail']
 assert 'stop --all' in detail and '--home' in detail and str(state) in detail, 'incomplete stop omitted the exact-home cleanup retry'
 assert any(not value for value in result['outside_after_down'].values()), 'failure control did not retain a provider'
else:
 assert result['down'].get('complete') is True, 'public down did not complete within the original bound'
 assert len(result['down']['stops'])==8 and all(x['complete'] for x in result['down']['stops']), 'one owned lifecycle was omitted'
 assert all(result['outside_after_down'].values()), 'down returned while an exact owned native root survived'
assert all(result['outside_final'].values()), 'public retry did not close every owned root'
assert result['endpoint_absent'] and result['user_work_preserved']
with (state/'runtime.lock').open('r+b') as lease:fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
print('ok 1 - all eight real provider sessions have individually named stop results; failure control includes exact-home retry' if args.block_writer else 'ok 1 - all eight real provider sessions have witnessed exit results')
print('ok 2 - outside native births exited, endpoint absent, exclusive lease free and user work preserved')
print('1..2')
