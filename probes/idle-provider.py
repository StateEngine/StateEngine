"""Account-free completed-turn idle producer for author host attribution."""
import json,os,socket,time
from pathlib import Path
import mail_provider

def complete_then_park():
 repo=Path.cwd(); endpoint=json.loads((repo/'idle-control.json').read_text());ready=json.loads((repo/'provider-ready.json').read_text())
 connection=socket.create_connection(('127.0.0.1',endpoint['port']),timeout=30)
 connection.sendall((endpoint['nonce']+'\n').encode()); connection.settimeout(30)
 with connection,connection.makefile('rb') as control:
  if control.readline()!=b'complete\n':raise RuntimeError('Unexpected author control request')
  candidates=list((Path(os.environ['HOME'])/'.claude/projects').rglob(ready['conversation']+'.jsonl'))
  if len(candidates)!=1:raise RuntimeError('Expected one native transcript')
  record=dict(type='assistant',sessionId=ready['conversation'],uuid='idle-turn',message=dict(role='assistant',content=[dict(type='text',text='Done')]))
  with candidates[0].open('a') as transcript:transcript.write(json.dumps(record)+'\n')
  print(json.dumps(dict(type='assistant',session_id=ready['conversation'],message=record['message'])),flush=True)
  print(json.dumps(dict(type='result',session_id=ready['conversation'],result='Done',is_error=False)),flush=True)
  connection.sendall(b'completed\n');connection.settimeout(None)
  # No producer timer or repeated transcript read/write remains during idle.
  if control.readline():raise RuntimeError('Unexpected second author control request')
  raise RuntimeError('Author control closed before public shutdown')

if __name__=='__main__':mail_provider.main(complete_then_park)
