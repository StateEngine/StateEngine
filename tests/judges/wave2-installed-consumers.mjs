// Public installed consumers, independent of all Rust crate implementations.
// Run through the scheduled OS owner runner, outside managed-agent ancestry:
// node tests/judges/wave2-installed-consumers.mjs FIXTURE.json activation|shutdown
// FIXTURE: {executable,home,repo,output,environment:{...},model:"claude-sonnet-5-5"}.
// The caller supplies an isolated authenticated HOME, a fresh --home, and a
// disposable Git repository. This driver neither installs nor changes auth.
// Native Windows pending-ticket/port proof belongs to the separate harness
// judge; a quiet real provider plus complete CLI stop is only its public mirror.
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {execFileSync,spawn} from 'node:child_process';
import {readFile,writeFile,mkdir,lstat} from 'node:fs/promises';
import {isAbsolute,join,resolve} from 'node:path';
import {setTimeout as pause} from 'node:timers/promises';

const [fixturePath,mode]=process.argv.slice(2);
assert.ok(['activation','shutdown'].includes(mode),'select activation or shutdown');
const f=JSON.parse(await readFile(resolve(fixturePath),'utf8'));
for(const key of ['executable','home','repo','output']) assert.ok(isAbsolute(f[key]),`absolute ${key} required`);
assert.equal(f.model,'claude-sonnet-5-5','this judge uses the admitted Sonnet model');
assert.ok(f.environment && typeof f.environment==='object','explicit isolated native environment required');
assert.notEqual(f.environment.HOME,process.env.HOME,'prepare a separate authenticated fixture HOME');
assert.notEqual(f.environment.USERPROFILE,process.env.USERPROFILE,'prepare a separate authenticated fixture USERPROFILE');
for(const key of Object.keys(f.environment)) assert.ok(!/^(STATEENGINE_|CODEX_|CLAUDECODE$|SE_SESSION$|SE_CAPABILITY$)/u.test(key),`managed ancestry variable ${key} must not enter owner fixture`);
await mkdir(f.output,{recursive:false});
try {await lstat(f.home); throw Error('fixture StateEngine home must be absent before init');}
catch(error) {if(error.code!=='ENOENT') throw error;}
const journal=[]; let ordinal=0, agent, project, hostIdentity;
const hash=data=>createHash('sha256').update(data).digest('hex');
const selected=()=>['--project',project];
async function command(label,args,{select=false,key=false,allowError=false}={}) {
 const original=key?randomUUID():null;
 const argv=[...args,...(select?selected():[]),'--home',f.home,...(original?['--key',original]:[]),'--json'];
 const index=++ordinal;
 const result=await new Promise((settle,reject)=>{
  const child=spawn(f.executable,argv,{cwd:f.repo,env:f.environment,windowsHide:true,stdio:['ignore','pipe','pipe']});
  let stdout='',stderr=''; let overflow=false;
  const collect=(name,chunk)=>{
   if(name==='stdout') stdout+=chunk; else stderr+=chunk;
   if(stdout.length+stderr.length>8*1024*1024) {overflow=true; child.kill();}
  };
  child.stdout.on('data',b=>collect('stdout',b)); child.stderr.on('data',b=>collect('stderr',b));
  child.once('error',reject); child.once('close',(code,signal)=>settle({code,signal,stdout,stderr,overflow}));
 });
 await writeFile(join(f.output,`${index}-${label}.stdout`),result.stdout);
 await writeFile(join(f.output,`${index}-${label}.stderr`),result.stderr);
 journal.push({index,label,argv,key:original,code:result.code,signal:result.signal});
 await writeFile(join(f.output,'commands.json'),JSON.stringify(journal,null,2));
 assert.equal(result.overflow,false,`${label}: output exceeded the finite bound`);
 const value=JSON.parse(result.stdout);
 if(!allowError) {assert.equal(result.code,0,`${label}: ${result.stdout}\n${result.stderr}`); assert.notEqual(value.ok,false,label); assert.notEqual(value.schema,'se.error/v1',label);}
 return {value,...result};
}
function processIdentity(pid) {
 assert.ok(Number.isSafeInteger(pid)&&pid>0,'exact positive process PID required');
 if(process.platform==='linux') {
  try {
   const stat=execFileSync('/bin/cat',[`/proc/${pid}/stat`],{encoding:'utf8',stdio:['ignore','pipe','pipe']});
   const fields=stat.slice(stat.lastIndexOf(')')+2).split(' ');
   return {pid,birth:fields[19],command:execFileSync('/bin/cat',[`/proc/${pid}/cmdline`],{encoding:'utf8',stdio:['ignore','pipe','pipe']})};
  } catch(error) {if(String(error.stderr).includes('No such file or directory')) return null; throw error;}
 }
 assert.equal(process.platform,'win32','native Linux or Windows required');
 const script=`$ErrorActionPreference='Stop'; $p=Get-CimInstance Win32_Process -Filter 'ProcessId=${pid}'; if($null -eq $p){'null'}else{@{pid=[int]$p.ProcessId;birth=$p.CreationDate.ToUniversalTime().Ticks.ToString();command=$p.CommandLine}|ConvertTo-Json -Compress}`;
 const result=JSON.parse(execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{encoding:'utf8',windowsHide:true,timeout:20000}));
 if(result) assert.ok(result.birth && result.command,'native process identity unreadable');
 return result;
}
async function gone(identity) {
 const until=Date.now()+20000;
 while(Date.now()<until) {
  const now=processIdentity(identity.pid);
  if(now===null || now.birth!==identity.birth) return;
  assert.equal(now.command,identity.command,'same-birth process identity changed unexpectedly');
  await pause(100);
 }
 throw Error(`exact process ${identity.pid}/${identity.birth} still live`);
}
async function absent(path) {
 try {await lstat(path); return false;} catch(error) {if(error.code==='ENOENT') return true; throw error;}
}
try {
 const before=await readFile(join(f.repo,'README.md'));
 const init=(await command('init',['init','--repo',f.repo,'--name','Independent host judge','--agent','Judge','--provider','claude','--model',f.model],{key:true})).value;
 assert.equal(init.schema,'se.init/v1'); project=init.profile.project; agent=init.profile.agent_id;
 const up=(await command('up',['up'],{key:true})).value;
 assert.equal(up.schema,'se.runtime-start/v1'); hostIdentity=processIdentity(up.process.pid);
 assert.ok(hostIdentity,'up returned an absent host');
 await writeFile(join(f.output,'host-before.json'),JSON.stringify(hostIdentity,null,2));
 if(mode==='activation') {
  const token=randomUUID(); const filename=`judge-${token}.txt`;
  const task=`Write ${filename} containing exactly ${token}. Read it back, then use StateEngine to send owner ${init.profile.human_id} a done message containing ${token}. Afterward wait for mail.`;
  const launch=(await command('launch',['launch',agent,'--provider','claude','--model',f.model,'--detach','--task',task],{select:true,key:true})).value;
  assert.equal(launch.schema,'se.launch/v1'); assert.equal(launch.state,'running');
  assert.ok(launch.session_id && launch.conversation_id && launch.lifecycle_id,'launch lacks joined activation identities');
  const provider=processIdentity(launch.process.pid); assert.ok(provider,'launched provider is absent');
  await writeFile(join(f.output,'provider-before.json'),JSON.stringify(provider,null,2));
  const agentView=(await command('agent',['agent','show',agent],{select:true})).value;
  assert.equal(agentView.agent.state,'present','activated agent is unreadable');
  assert.equal(agentView.agent.value.session.session_id,launch.session_id,'public agent read differs from activation receipt');
  let replied=false; const until=Date.now()+180000;
  while(Date.now()<until) {
   const page=(await command('mail',['msg','list','--all','--full','--limit','100'],{select:true})).value;
   assert.equal(page.schema,'se.message-page/v1');
   assert.equal(page.window.complete,true); assert.equal(page.next,null);
   replied=page.items.some(row=>row.from.id===agent && row.to.id===init.profile.human_id && row.kind==='done' && row.body.complete===true && row.unreadable===null && row.body.text.includes(token));
   if(replied) break; await pause(2000);
  }
  assert.equal(replied,true,'no real provider/MCP task completion after activation');
  assert.equal((await readFile(join(f.repo,filename),'utf8')).trim(),token,'task bytes do not match provider receipt');
  await pause(2000); // Quiet provider: both production drains normally wait here.
  const stop=(await command('stop',['stop',agent],{select:true,key:true})).value;
  assert.equal(stop.schema,'se.stop/v1'); assert.equal(stop.complete,true); assert.equal(stop.witness.state,'witnessed');
  assert.deepEqual(stop.remaining,[]); assert.equal(stop.capture.flushed,true);
  await gone(provider);
 }
 const down=(await command('down',['down'],{key:true})).value;
 assert.equal(down.schema,'se.runtime-stop/v1'); assert.equal(down.complete,true,'shutdown did not prove its complete fact set');
 assert.equal(down.witness.state,'witnessed'); assert.ok(Array.isArray(down.stops) && down.stops.every(stop=>stop.complete && stop.witness.state==='witnessed'));
 await gone(hostIdentity);
 assert.equal(await absent(join(f.home,'endpoint.json')),true,'endpoint publication remains');
 const status=(await command('status',['status'],{select:true})).value;
 assert.equal(status.runtime.state,'stopped'); assert.equal(status.runtime.process,null);
 const current=await readFile(join(f.repo,'README.md')); assert.equal(hash(current),hash(before),'user README changed');
 await writeFile(join(f.output,'result.json'),JSON.stringify({mode,platform:process.platform,passed:true,qualification:'diagnostic consumer only; installed bundle provenance is supplied by the producer',commands:journal.length},null,2));
 console.log(`${mode}: 1 passed; 0 failed`);
} catch(error) {
 const cleanup=[];
 if(project && agent) {
  try {const stop=await command('cleanup-stop',['stop',agent],{select:true,key:true,allowError:true}); if(stop.code!==0 || stop.value.complete!==true) cleanup.push({stage:'stop',result:stop.value});} catch(cause) {cleanup.push({stage:'stop',error:cause.message});}
 }
 if(hostIdentity) {
  try {const down=await command('cleanup-down',['down'],{key:true,allowError:true}); if(down.code!==0 || down.value.complete!==true) cleanup.push({stage:'down',result:down.value});} catch(cause) {cleanup.push({stage:'down',error:cause.message});}
 }
 await writeFile(join(f.output,'result.json'),JSON.stringify({mode,platform:process.platform,passed:false,error:error.message,cleanup,retained_home:f.home,retained_repo:f.repo,commands:journal.length},null,2));
 // Preserve the exact home and original mutation keys after public cleanup.
 // A refused cleanup remains named; never signal a census PID or delete.
 console.error(`${mode}: 0 passed; 1 failed; ${error.message}`); process.exitCode=1;
}
