"""Public CLI/MCP notification consumer, with two owned Claude protocol doubles.
Requires the serialized account-install slot: Fixture uses public init, then
public down closes its runtime. The private initialized home remains for
inspection; it has no installer-owned record. No paid account is used.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--se',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
if sys.platform!='linux':
    raise SystemExit('This consumer requires Linux native process and pipe witnesses.')
judges=Path(__file__).with_name('judges')
sys.path.insert(0,str(judges))
from mail_cli import Fixture
helper=a.output.with_name(a.output.name+'-provider.py')
s=(judges/'mail_provider.py').read_text()
anchor='    (cwd / "provider-ready.json").write_text'
assert s.count(anchor)==1
s=s.replace(anchor,'''    # The wrapper has already closed its inherited read end. Only this exact
    # child owns stdin now, so closing it proves a zero-byte broken-pipe offer.
    if (cwd / 'close-stdin').exists():
        os.close(0)
    print(json.dumps({'type':'result','subtype':'success','session_id':conversation,'is_error':False,'result':'ready'}),flush=True)
'''+anchor)
helper.write_text(s)
f=Fixture(a.se,a.output,provider_helper=helper)
# Let the actual native shim remain alive for custody, but close its own read
# end after spawning the Python child. Thus the child controls its own pipe.
source=f.root/'provider.rs'
s=source.read_text()
assert s.count('let s=std::process::Command::new')==1
s=s.replace('let s=std::process::Command::new','let mut child=std::process::Command::new').replace('.status().unwrap();','.spawn().unwrap();\nunsafe extern "C" {fn close(fd:i32)->i32;}\nunsafe {close(0);}\nlet s=child.wait().unwrap();')
source.write_text(s)
subprocess.run(['rustc','--edition=2024',str(source),'-o',str(f.root/'provider')],capture_output=True,check=True,timeout=60)
checks=[]
def check(name):
    checks.append(name);print(f'ok {len(checks)} - {name}',flush=True)
def content(result):
    assert not result.get('isError'),result
    return result.get('structuredContent') or json.loads(result['content'][0]['text'])
def owner_row(id):
    return next(row for row in f.mail('list','--all','--full')['items'] if row['id']==id)
def counts():
    with sqlite3.connect(f.home.as_uri()+'/state.db?mode=ro',uri=True) as db:
        return dict(db.execute("SELECT kind,count(*) FROM events WHERE kind IN ('message.sent','message.work_sent','effect.requested','effect.offered','message.read','message.delivered') GROUP BY kind"))
def until(probe,reason):
    end=time.monotonic()+12
    while True:
        value=probe()
        if value:return value
        assert time.monotonic()<end,reason
        time.sleep(.05)
try:
    f.launch()
    first=f.session
    second=f.ok('--key','notification-agent','--project',f.project,'agent','add','Pipe closed','--provider','claude','--model','claude-sonnet-5-5')['agent']['id']
    (f.repo/'close-stdin').touch()
    launched=f.ok('--key','notification-launch','--project',f.project,'launch',second,'--detach','--task','Notification failure consumer')
    assert launched['state']=='running',launched
    second_session=launched['session_id']
    ready=json.loads((f.repo/'provider-ready.json').read_text())
    for pid in [ready['native_root_pid'],ready['helper_pid']]:
        f.processes.append((pid,Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[19]))
    check('two real native roots, authenticated MCP and a closed recipient input pipe')
    baseline=counts()
    quiet=f.mail('send',f.agent,'Quiet CLI note','--no-wake','--key','quiet-cli')
    assert quiet['notification']['intent']=='quiet'
    assert quiet['notification']['recipients'][0]['state']=='quiet'
    args=dict(to=second,body='Quiet MCP note',quiet=True,idempotency_key='quiet-mcp')
    sent=content(f.rpc('stateengine_msg_send',args))
    replay=content(f.rpc('stateengine_msg_send',args))
    assert replay['message_id']==sent['message_id'] and replay['notification']['intent']=='quiet'
    floor_args=['send','floor','Quiet shared note','--kind','finding','--work-action','finding','--addressee',f.agent,'--addressee',second,'--no-wake','--key','quiet-floor']
    floor=f.mail(*floor_args)
    assert len(floor['notification']['recipients'])==2
    assert all(row['state']=='quiet' for row in floor['notification']['recipients'])
    time.sleep(.3)
    after=counts()
    assert after.get('effect.requested',0)==baseline.get('effect.requested',0),'quiet mail reserved a notification'
    assert after.get('effect.offered',0)==baseline.get('effect.offered',0),'quiet mail offered a notification'
    check('CLI, MCP and shared quiet intent survive key replay without notification effects')
    inbox=content(f.rpc('stateengine_msg_list',dict(view='unread',full=True)))
    assert {quiet['message_id'],floor['message_id']}<={row['id'] for row in inbox['items']}
    shared=next(row for row in inbox['items'] if row['id']==floor['message_id'])
    assert len(shared['notification']['recipients'])==1
    assert shared['notification']['recipients'][0]['recipient']['id']==f.agent
    f.session=second_session
    foreign=f.rpc('stateengine_msg_read',dict(msg_id=quiet['message_id']))
    assert foreign['isError'],foreign
    f.session=first
    check('quiet notes remain unread and recipient inspection excludes another recipient outcome')
    notify_args=['send','floor','Notify both recipients','--kind','finding','--work-action','finding','--addressee',f.agent,'--addressee',second,'--key','notify-floor']
    notice=f.mail(*notify_args)
    def observed():
        row=owner_row(notice['message_id'])
        states={n['recipient']['id']:n['state'] for n in row['notification']['recipients']}
        return row if states.get(f.agent)=='offered' and states.get(second)=='failed' else None
    observed_row=until(observed,'independent transport success/zero-byte failure did not persist')
    failure=next(n for n in observed_row['notification']['recipients'] if n['recipient']['id']==second)
    assert failure['code']=='zero-byte-write' and failure['event_id'] and failure['at']
    check('real pipe success and zero-byte failure persist independently for addressed recipients')
    before_retry=counts()
    repeated=f.mail(*notify_args)
    assert repeated['message_id']==notice['message_id']
    until(lambda:counts().get('effect.offered',0)>before_retry.get('effect.offered',0),'same-key retry did not re-drive the failed recipient')
    after_retry=counts()
    assert after_retry.get('message.work_sent',0)==before_retry.get('message.work_sent',0),'retry duplicated a message'
    changed=f.call('--project',f.project,'msg',*notify_args,'--no-wake')
    assert changed.returncode!=0 and b'idempotency' in changed.stderr.lower(),(changed.stdout,changed.stderr)
    check('same-key retry reuses mail identity; changed quiet intent refuses')
    after=counts()
    for kind in ['message.read','message.delivered']:
        assert after.get(kind,0)==baseline.get(kind,0),'inspection or transport fabricated '+kind
    f.close()
    f.ok('--key','notification-up','up')
    row=owner_row(floor['message_id'])
    assert row['notification']['intent']=='quiet' and all(n['state']=='quiet' for n in row['notification']['recipients'])
    assert not any(counts().get(k,0)!=after.get(k,0) for k in ['message.read','message.delivered','effect.offered'])
    check('restart preserves quiet intent and observations without fabricated delivery/read marks')
finally:
    f.close()
    assert not (f.home/'endpoint.json').exists()
    with (f.home/'runtime.lock').open('rb') as lock:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    (f.root/'outside.json').write_text(json.dumps(dict(endpoint_absent=True,lease_free=True,provider_births_closed=f.processes,public_down=True,initialized_home_retained=True,counts=counts()),indent=2))
print(f'1..{len(checks)}',flush=True)
