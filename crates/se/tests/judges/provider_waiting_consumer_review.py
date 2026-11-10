"""Independent CLI/MCP provider waiting and explicit-retry controls.

Run with --se BINARY --codex STOCK_NATIVE_CODEX --output NEW_DIRECTORY.
The loopback model uses synthetic credentials in fresh homes and never a paid account.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from codex_first_launch import Model
from mail_cli import Fixture as MailFixture

class Fixture(MailFixture):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Settings discovery must remain in the retained native child: killing
        # a wrapper that left a helper behind would not prove probe closure.
        source = self.root / 'provider.rs'
        text = source.read_text()
        needle = 'if a.get(1).map(String::as_str)==Some("--version")'
        assert text.count(needle) == 1
        reply = {'type': 'control_response', 'response': {'subtype': 'success',
            'request_id': 'settings', 'response': {'effective': {}, 'sources': [], 'errors': []}}}
        safe = ('if a.iter().any(|v|v=="--safe-mode") {println!("{}", r#"'
            + json.dumps(reply) + '"#);loop {std::thread::sleep(std::time::Duration::from_secs(1));}}\n')
        source.write_text(text.replace(needle, safe + needle, 1))
        subprocess.run(['rustc', '--edition=2024', str(source), '-o', str(self.root / 'provider')],
            capture_output=True, check=True, timeout=60)

MARKER = 'REVIEW_RECOVERED_OK'
class Loopback(Model):
    def __init__(self, root, repo, mode):
        self.mode = mode
        self.entered = threading.Event()
        self.release = threading.Event()
        super().__init__(root, repo)
    def respond(self, handler, request):
        self.requests.append(request)
        self.entered.set()
        (self.root/'review-model-requests.json').write_text(json.dumps(self.requests, indent=2))
        if self.mode == 'quiet':
            assert self.release.wait(100), 'owned model release timed out'
        if self.mode == 'auth':
            data = json.dumps({'error': {'message': 'PRIVATE_FIXTURE_DETAIL',
                'type': 'authentication_error', 'code': 'invalid_api_key'}}).encode()
            handler.send_response(401)
            handler.send_header('Content-Type','application/json')
        else:
            rid = 'resp_'+uuid.uuid4().hex
            item = {'id':'msg_'+uuid.uuid4().hex, 'type':'message', 'role':'assistant',
                'status':'completed','phase':'final_answer',
                'content':[{'type':'output_text','text':MARKER,'annotations':[],'logprobs':[]}]}
            response = {'id':rid,'object':'response','created_at':int(time.time()),
                'model':request.get('model','review'),'status':'in_progress','output':[]}
            events = [{'type':'response.created','response':response},
                {'type':'response.output_item.added','output_index':0,'item':{**item,'status':'in_progress'}},
                {'type':'response.output_item.done','output_index':0,'item':item},
                {'type':'response.completed','response':{**response,'status':'completed','output':[item],
                    'usage':{'input_tokens':32,'output_tokens':8,'total_tokens':40,
                             'output_tokens_details':{'reasoning_tokens':0}}}}]
            data = ''.join('event: '+e['type']+'\ndata: '+json.dumps({**e,'sequence_number':i})+'\n\n'
                           for i,e in enumerate(events)).encode()
            handler.send_response(200)
            handler.send_header('Content-Type','text/event-stream')
        handler.send_header('Content-Length',str(len(data)))
        handler.end_headers()
        try: handler.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError): pass
    def close(self):
        self.release.set()
        super().close()

def activity(value, agent, strict=True):
    if isinstance(value, dict):
        if value.get('id') == agent and 'provider_activity' in value:
            read = value['provider_activity']
            if not strict and read['state'] != 'present':
                return None
            assert read['state'] == 'present', read
            return read['value']
        for child in value.values():
            found = activity(child, agent, strict)
            if found is not None: return found
    elif isinstance(value, list):
        for child in value:
            found = activity(child, agent, strict)
            if found is not None: return found
    return None

def observe(f, expected):
    observations = []
    for arguments in [('status',),('agent','show',f.agent)]:
        started = time.monotonic()
        value = f.ok('--project', f.project, *arguments)
        elapsed = time.monotonic()-started
        current = activity(value,f.agent)
        assert current is not None and current['activity'] == expected, (expected,current,value)
        assert 'PRIVATE_FIXTURE_DETAIL' not in json.dumps(current), current
        assert elapsed < 30, elapsed
        observations.append({'consumer':' '.join(arguments),'seconds':elapsed,'activity':current})
    result = f.rpc('stateengine_status',{})
    current = activity(result,f.agent)
    assert current is not None and current['activity'] == expected, (expected,current,result)
    observations.append({'consumer':'authenticated MCP status','activity':current})
    plain = subprocess.run([str(f.se),'--home',str(f.home),'--project',f.project,'status'],
        env=f.env,stdin=subprocess.DEVNULL,capture_output=True,timeout=35)
    (f.root/'review-plain.stdout').write_bytes(plain.stdout)
    (f.root/'review-plain.stderr').write_bytes(plain.stderr)
    assert plain.returncode == 0 and expected.encode() in plain.stdout, (plain.stdout,plain.stderr)
    (f.root/('review-'+expected+'.json')).write_text(json.dumps(observations,indent=2))
    return observations

def await_phase(f, expected):
    end = time.monotonic()+20
    while True:
        value = f.ok('--project',f.project,'status')
        current = activity(value,f.agent,strict=False)
        if current and current['activity'] == expected: return
        assert time.monotonic()<end, (expected,current,value)
        time.sleep(.2)

def pin_native_tree(f, root_pid, birth=None):
    if sys.platform != 'linux':
        return
    rows = {}
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            fields = (path/'stat').read_text().rsplit(') ', 1)[1].split()
            rows[int(path.name)] = (int(fields[1]), fields[19])
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    if birth is not None and (root_pid not in rows or rows[root_pid][1] != birth):
        return
    selected = {root_pid}
    while True:
        more = {pid for pid, (parent, _) in rows.items() if parent in selected} - selected
        if not more:
            break
        selected |= more
    for pid in selected:
        if pid in rows:
            f.processes.append((pid, rows[pid][1]))

def launch(f, task):
    host = f.ok('up')
    pin_native_tree(f, host['process']['pid'])
    result = f.ok('--key',str(uuid.uuid4()),'--project',f.project,'launch',f.agent,
                  '--detach','--task',task)
    assert result['state'] == 'running',result
    f.session = result['session_id']
    pin_native_tree(f, result['process']['pid'])

def codex(f, binary, mode):
    model = Loopback(f.root,f.repo,mode)
    try:
        home = f.root/'owned-codex';home.mkdir(mode=0o700)
        # Native Unix listener aliases need a short runtime directory even
        # when retained evidence lives under a long caller-selected path.
        f.review_short = Path(tempfile.mkdtemp(prefix='se-wait-', dir='/tmp' if sys.platform == 'linux' else None))
        f.env.update(CODEX_HOME=str(home),OPENAI_API_KEY='sk-synthetic-loopback-review-only',
                     XDG_RUNTIME_DIR=str(f.review_short),TMPDIR=str(f.review_short))
        (home/'config.toml').write_text('model_provider="review-loopback"\n'
            '[model_providers.review-loopback]\nname="Synthetic review loopback"\n'
            +'base_url='+json.dumps('http://127.0.0.1:'+str(model.server.server_port)+'/v1')+'\n'
            +'wire_api="responses"\nrequires_openai_auth=false\nrequest_max_retries=0\nstream_max_retries=0\n')
        login = subprocess.run([str(binary),'login','--with-api-key'],input=f.env['OPENAI_API_KEY'],
            env=f.env,text=True,capture_output=True,timeout=20)
        assert login.returncode==0,login.stderr
        config=f.home/'config.toml'
        config.write_text(config.read_text().replace('[providers.codex]',
            '[providers.codex]\ncommand='+json.dumps(str(binary)),1))
        f.agent=f.ok('--project',f.project,'agent','add','Review Codex',
                     '--provider','codex','--model','gpt-6.1-sol')['agent']['id']
    except BaseException:
        model.close()
        raise
    return model

def run(options, name):
    helper=Path(__file__).with_name('provider_waiting_protocol_review.py')
    f=Fixture(options.se,options.output/name,provider_helper=helper)
    model=None
    result={'case':name}
    try:
        if name.startswith('codex'):
            model=codex(f,options.codex,'quiet' if name.endswith('quiet') else 'auth')
        elif name.endswith('failure'):
            (f.repo/'review-failure').touch()
        launch(f,'Observe the owned fixture response without resubmitting input.')
        if name.endswith('quiet'):
            if model: assert model.entered.wait(15),'native model request absent'
            else:
                end=time.monotonic()+15
                while not (f.repo/'review-provider-ready').exists():
                    assert time.monotonic()<end,'native provider readiness absent'
                    time.sleep(.05)
            time.sleep(33)
            result['waiting']=observe(f,'waiting')
            history=f.ok('--project',f.project,'history','--agent',f.agent,'--kind','session.turn')
            assert MARKER not in json.dumps(history),'waiting fabricated a provider answer'
            if model:
                assert len(model.requests)==1,'silence automatically resubmitted input'
                model.release.set()
            else: (f.repo/'review-release').touch()
            await_phase(f,'turn-completed')
            result['completed']=observe(f,'turn-completed')
        elif name=='codex-auth-retry':
            assert model.entered.wait(15),'native model request absent'
            await_phase(f,'authentication-required')
            result['authentication']=observe(f,'authentication-required')
            assert 'codex login' in result['authentication'][0]['activity']['next_step']
            assert len(model.requests)==1,'authentication failure resubmitted input'
            model.mode='ok'
            f.ok('--project',f.project,'stop',f.agent)
            launch(f,'Request the corrected response exactly once.')
            await_phase(f,'turn-completed')
            result['recovered']=observe(f,'turn-completed')
            assert len(model.requests)==2,'explicit retry was duplicated or never reached the model'
        else:
            (f.repo/'review-release').touch()
            await_phase(f,'failed')
            result['failure']=observe(f,'failed')
            assert 'claude auth' in result['failure'][0]['activity']['next_step']
        result['outcome']='pass'
    except BaseException as failure:
        result['outcome']='fail';result['error']=repr(failure)
    finally:
        if model:model.release.set()
        (f.repo/'review-release').touch()
        try:
            for pid, birth in list(f.processes):
                pin_native_tree(f, pid, birth)
            f.close()
            if hasattr(f, 'review_short'):
                child = f.review_short/'stateengine'
                if child.exists():
                    child.rmdir()
                f.review_short.rmdir()
            result['cleanup']='joined'
        except BaseException as failure:
            result['cleanup']='unproved';result['cleanup_error']=repr(failure)
        if model:model.close()
        (f.root/'review-result.json').write_text(json.dumps(result,indent=2))
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se',type=Path,required=True)
    parser.add_argument('--codex',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--case',action='append',choices=['codex-quiet','codex-auth-retry','claude-quiet','claude-failure'])
    options=parser.parse_args();os.umask(0o077)
    for key in list(os.environ):
        if key.startswith(('OPENAI_','ANTHROPIC_','CODEX_','CLAUDE','SE_','STATEENGINE_')) or key.upper() in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY'):
            os.environ.pop(key,None)
    options.output.mkdir(mode=0o700)
    results=[]
    for name in options.case or ['codex-quiet','codex-auth-retry','claude-quiet','claude-failure']:
        results.append(run(options,name))
        if results[-1]['cleanup']!='joined':break
    (options.output/'results.json').write_text(json.dumps(results,indent=2))
    for result in results:print(json.dumps({'case':result['case'],'outcome':result['outcome'],'cleanup':result['cleanup']}),flush=True)
    assert all(r['outcome']=='pass' and r['cleanup']=='joined' for r in results),results
if __name__=='__main__':main()
