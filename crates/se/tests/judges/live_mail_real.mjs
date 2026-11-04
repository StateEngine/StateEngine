// Protects: installed real Claude receives post-launch tasks without polling and preserves busy/stopped boundaries.
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {setTimeout as pause} from 'node:timers/promises';
import {pathToFileURL} from 'node:url';
const runner=process.env.JUDGE_RUNNER, root=process.env.JUDGE_OUTPUT;
if(!runner || !root) throw Error('JUDGE_RUNNER and JUDGE_OUTPUT are required');
const {BudgetRun}=await import(pathToFileURL(path.join(runner,'journeys/budgets.mjs')));
const {terminalCommand}=await import(pathToFileURL(path.join(runner,'journeys/terminal.mjs')));
const rows=[], cases=[];
let once=false;
const save=()=>fs.writeFileSync(path.join(root,'mail-observations.json'),JSON.stringify({scope:'P0 installed mail diagnostic; no performance-budget qualification',cases,commands:rows},null,2));
// This diagnostic uses the journey's installation/auth/cleanup fixture only.
for(const name of ['version','noSession','seat','check']) BudgetRun.prototype[name]=async()=>{};
BudgetRun.prototype.finish=function(){return true;};
BudgetRun.prototype.oneSession=async function(t){
 if(once)return; once=true;
 const ctx=['--home',t.profile.registry_root,'--project',t.profile.project,'--json'];
 const run=async(label,args,owner=false)=>{
  const argv=[...t.se,...args], started=new Date().toISOString();
  const result=await t.command(owner?terminalCommand(argv):argv,[],{allowFailure:true,timeout:180000});
  const row={label,argv,started,ended:new Date().toISOString(),...result};
  try{row.parsed=JSON.parse(result.stdout);}catch{}
  rows.push(row);save();t.observe();
  if(result.code!==0 || !row.parsed)throw Error(`${label}: public command failed (${result.code})`);
  return row.parsed;
 };
 const inbox=()=>run('owner-inbox',['msg','list','--all','--full','--limit','100',...ctx]);
 const inspection=async(id)=>{
  const value=await run('inspect-original',['msg','read',id,...ctx]);
  if(value.inspection!==true || value.marked_read!==false)throw Error('Owner inspection changed recipient unread state');
  return value.message;
 };
 const expectReply=async(token,source)=>{
  const end=Date.now()+45000;
  while(Date.now()<end){
   const page=await inbox();
   const found=page.items.filter(m=>m.from.id===t.profile.agent_id && m.to.id===t.profile.human_id && m.kind==='done' && m.body.complete===true && m.body.text.trim()===token);
   if(found.length){
    if(found.length!==1)throw Error('Duplicate exact done reply');
    const original=await inspection(source.message_id);
    if(original.delivery.state!=='delivered' || original.disposition.state!=='read')throw Error('Reply did not leave delivered/read source mail');
    return found[0];
   }
   await pause(500);
  }
  throw Error('Post-launch task never produced its exact recipient-authored owner reply');
 };
 const token='wake-'+randomUUID();
 fs.writeFileSync(path.join(root,'fixture.json'),JSON.stringify({home:t.home,profile:t.profile},null,2));
 const before=await run('running-before',['agent','show',t.profile.agent_id,...ctx]);
 const idle=await run('post-launch-wake-send',['msg','send',t.profile.agent_id,`Reply to owner ${t.profile.human_id} with a done message containing exactly ${token}; this is a new post-launch task. Do not poll inbox or start a timer. Finish this turn after replying.`,'--kind','task',...ctx],true);
 await expectReply(token,idle);cases.push({case:'idle-post-launch',passed:true,message_id:idle.message_id});save();
 const busy='busy-'+randomUUID(), queued='queued-'+randomUUID();
 const marker=path.join(t.profile.repo_root,'independent-busy-started.txt');
 const first=await run('start-busy',['msg','send',t.profile.agent_id,`Write exactly ${busy} to independent-busy-started.txt. Then run Bash command sleep 10 exactly once to hold this diagnostic turn open. After it returns, send owner ${t.profile.human_id} a done message containing exactly ${busy}. Do not poll inbox. Finish the turn after replying.`,'--kind','task',...ctx],true);
 const until=Date.now()+45000;
 while(Date.now()<until && (!fs.existsSync(marker) || fs.readFileSync(marker,'utf8').trim()!==busy))await pause(100);
 if(!fs.existsSync(marker)||fs.readFileSync(marker,'utf8').trim()!==busy)throw Error('Real busy task did not write its start witness');
 const second=await run('send-during-busy',['msg','send',t.profile.agent_id,`Reply to owner ${t.profile.human_id} with a done message containing exactly ${queued}; this task was sent while your preceding turn is busy. Do not poll inbox or start a timer. Finish this turn after replying.`,'--kind','task',...ctx],true);
 const during=await inspection(second.message_id);
 if(during.delivery.state!=='pending' || during.disposition.state!=='unread')throw Error('Busy mail was offered before the active turn boundary');
 await expectReply(busy,first); await expectReply(queued,second);
 const after=await run('running-after',['agent','show',t.profile.agent_id,...ctx]);
 if(before.agent.value.session.session_id!==after.agent.value.session.session_id || before.agent.value.session.process.pid!==after.agent.value.session.process.pid)throw Error('Mail replaced the live provider');
 cases.push({case:'busy-boundary-same-provider',passed:true,message_id:second.message_id});save();
 const stop=await run('stop-before-pending',['stop',t.profile.agent_id,...ctx],true);
 if(stop.complete!==true)throw Error('Stop not complete');
 const stopped=await run('send-to-stopped',['msg','send',t.profile.agent_id,'Stopped pending '+randomUUID(),'--kind','task',...ctx],true);
 const pending=await inspection(stopped.message_id);
 if(stopped.delivery.state!=='pending' || pending.delivery.state!=='pending' || pending.disposition.state!=='unread')throw Error('Stopped session mail was not pending/unread');
 cases.push({case:'stopped-pending',passed:true,message_id:stopped.message_id});save();
};
process.argv=[process.execPath,path.join(runner,'journeys/run.mjs'),...process.argv.slice(2)];
await import(pathToFileURL(path.join(runner,'journeys/run.mjs')));
if(!once || cases.length!==3)throw Error('Independent mail diagnostic did not reach all three cases');
