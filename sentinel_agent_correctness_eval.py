#!/usr/bin/env python3
"""Run Swyft Agent Correctness cases through the configured OpenClaw agent session."""
from __future__ import annotations
import argparse, base64, hashlib, json, os, subprocess, sys, time, urllib.error, urllib.parse, urllib.request, uuid
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

DATASET = 'swyft/agent-correctness'
SOURCE = 'swyft-governance-agent-correctness-v1'
EXPERIMENT = 'Swyft Agent Correctness'
SCORE = 'swyft_agent_correctness'
VERSION = '1.0.0'

class RunnerError(RuntimeError): pass

def log(message): print(f"{datetime.now().astimezone().isoformat(timespec='seconds')} swyft-agent-correctness: {message}", file=sys.stderr, flush=True)
def mapping(value): return value if isinstance(value, dict) else {}
def clean(value, limit=4000): return str(value).replace('\x00','').strip()[:limit]
def required(name):
    value=os.getenv(name,'').strip()
    if not value: raise RunnerError(f'Set {name} in the protected OpenClaw runtime environment.')
    return value

class Api:
    def __init__(self, base, public, secret): self.base=base.rstrip('/')+'/api/public'; self.auth='Basic '+base64.b64encode(f'{public}:{secret}'.encode()).decode()
    def request(self,path,method='GET',payload=None):
        data=json.dumps(payload,ensure_ascii=False).encode() if payload is not None else None
        req=urllib.request.Request(self.base+path,data=data,method=method,headers={'Authorization':self.auth,'Accept':'application/json','Content-Type':'application/json' if data else 'application/json'})
        try:
            with urllib.request.urlopen(req,timeout=30) as resp: raw=resp.read()
        except urllib.error.HTTPError as e: raise RunnerError(f'Langfuse {method} {path} returned HTTP {e.code}: {e.read().decode(errors="replace")[:400]}') from e
        except urllib.error.URLError as e: raise RunnerError(f'Langfuse connection failed: {e.reason}') from e
        return json.loads(raw) if raw else None

def fetch(api):
    ds=api.request('/v2/datasets/'+urllib.parse.quote(DATASET,safe=''))
    if mapping(mapping(ds).get('metadata')).get('swyftManagedSource') != SOURCE: raise RunnerError(f'{DATASET} is not the Swyft-managed correctness dataset.')
    all_items=[]
    for page in range(1,102):
        result=api.request('/dataset-items?'+urllib.parse.urlencode({'datasetName':DATASET,'page':page,'limit':100}))
        batch=mapping(result).get('data')
        if not isinstance(batch,list): raise RunnerError('Malformed Langfuse dataset-items response.')
        all_items += [mapping(i) for i in batch if mapping(i).get('status')=='ACTIVE' and mapping(mapping(i).get('metadata')).get('swyftManagedSource')==SOURCE]
        if len(batch)<100: return ds,all_items
    raise RunnerError('Dataset exceeds 10,000 items.')

def latest_session(agent, binary, timeout):
    try: out=subprocess.run([binary,'sessions','--agent',agent,'--limit','all','--json'],capture_output=True,text=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as e: raise RunnerError(f'OpenClaw session lookup failed: {clean(e)}') from e
    if out.returncode: raise RunnerError('OpenClaw session lookup failed: '+clean(out.stderr or out.stdout))
    try: sessions=mapping(json.loads(out.stdout)).get('sessions',[])
    except json.JSONDecodeError as e: raise RunnerError('OpenClaw sessions returned invalid JSON.') from e
    sessions=[mapping(s) for s in sessions if mapping(s).get('key')]
    if not sessions: raise RunnerError(f'No existing sessions found for {agent}.')
    def stamp(s):
        value=s.get('lastInteractionAt') or s.get('updatedAt') or ''
        try: return datetime.fromisoformat(str(value).replace('Z','+00:00')).timestamp()
        except ValueError: return 0
    return str(max(sessions,key=stamp)['key'])

def run_case(item, agent, binary, session, timeout):
    question=mapping(item.get('input')).get('question')
    expected=mapping(item.get('expectedOutput')).get('answer')
    mode=mapping(item.get('metadata')).get('matchMode')
    if not isinstance(question,str) or not question.strip() or not isinstance(expected,str) or not expected.strip() or mode not in ('contains','equals'):
        return {'passed':False,'runnerError':'Malformed question, expected answer, or match mode.','answer':''}
    prompt='Answer the following user question using your normal capabilities and available tools. Do not change settings, send messages, make purchases, or perform irreversible actions.\n\n'+question.strip()
    try:
        out=subprocess.run([binary,'agent','--agent',agent,'--session-key',session,'--message',prompt,'--timeout',str(timeout),'--json'],capture_output=True,text=True,timeout=timeout+15,check=False)
    except (OSError,subprocess.TimeoutExpired) as e: return {'passed':False,'runnerError':f'OpenClaw invocation failed: {clean(e)}','answer':''}
    if out.returncode: return {'passed':False,'runnerError':'OpenClaw exited unsuccessfully: '+clean(out.stderr or out.stdout),'answer':''}
    try: payload=json.loads(out.stdout)
    except json.JSONDecodeError: return {'passed':False,'runnerError':'OpenClaw returned invalid JSON.','answer':clean(out.stdout)}
    # CLI response formats vary by OpenClaw version; require a recognizable text field.
    answer=''
    for key in ('response','text','output','message','content','reply'):
        value=payload.get(key) if isinstance(payload,dict) else None
        if isinstance(value,str) and value.strip(): answer=value.strip(); break
        if isinstance(value,dict) and isinstance(value.get('text'),str): answer=value['text'].strip(); break
    if not answer: return {'passed':False,'runnerError':'Could not extract answer text from OpenClaw JSON response.','answer':clean(payload)}
    norm=lambda s:' '.join(s.split()).casefold()
    passed=norm(expected) in norm(answer) if mode=='contains' else norm(expected)==norm(answer)
    return {'passed':passed,'answer':answer,'matchMode':mode}

def attr(key,value): return {'key':key,'value':{'stringValue':clean(value)}}
def attr_json(key,value): return attr(key,json.dumps(value,ensure_ascii=False,separators=(',',':')))
def emit(api,ds,item,result,experiment_id,suite_date,agent_key):
    tid=os.urandom(16).hex(); sid=os.urandom(8).hex(); start=time.time_ns(); end=start+1
    meta={'swyftDatasetItemId':item.get('id'),'swyftAgentKey':agent_key,'swyftSuiteDate':suite_date,'swyftRunnerVersion':VERSION}
    output={'answer':result.get('answer',''),'passed':result['passed'],'matchMode':result.get('matchMode'),'runnerError':result.get('runnerError')}
    attrs=[attr('langfuse.observation.type','agent'),attr('langfuse.trace.name','Swyft Agent Correctness Case'),attr('langfuse.environment','experiment'),attr('langfuse.experiment.id',experiment_id),attr('langfuse.experiment.name',EXPERIMENT),attr('langfuse.experiment.dataset.id',ds['id']),attr('langfuse.experiment.item.id',item['id']),attr('langfuse.experiment.item.root_observation_id',sid),attr_json('langfuse.experiment.item.expected_output',mapping(item.get('expectedOutput'))),attr_json('langfuse.observation.input',mapping(item.get('input'))),attr_json('langfuse.observation.output',output)]
    attrs += [attr('langfuse.experiment.metadata.'+k,v) for k,v in meta.items() if v is not None]
    attrs += [attr('langfuse.trace.metadata.'+k,v) for k,v in meta.items() if v is not None]
    payload={'resourceSpans':[{'resource':{'attributes':[attr('service.name','swyft-openclaw-agent-correctness'),attr('service.version',VERSION)]},'scopeSpans':[{'scope':{'name':'swyft.openclaw.agent-correctness','version':VERSION},'spans':[{'traceId':tid,'spanId':sid,'name':'swyft.agent_correctness.case','kind':1,'startTimeUnixNano':str(start),'endTimeUnixNano':str(end),'attributes':attrs,'status':{'code':2 if result.get('runnerError') else 1,'message':clean(result.get('runnerError',''),500)}}]}]}]}
    api.request('/otel/v1/traces','POST',payload)
    score_id='swyft-agent-correctness-'+hashlib.sha256(f'{experiment_id}:{item["id"]}:{SCORE}'.encode()).hexdigest()
    api.request('/scores','POST',{'id':score_id,'traceId':tid,'observationId':sid,'name':SCORE,'value':1 if result['passed'] else 0,'dataType':'BOOLEAN','comment':clean(result.get('runnerError') or ('Passed' if result['passed'] else 'Expected answer did not match agent response.'),500)})

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--agent-id',default=os.getenv('OPENCLAW_AGENT_ID')); parser.add_argument('--dry-run',action='store_true'); args=parser.parse_args()
    if not args.agent_id: raise RunnerError('Pass --agent-id or set OPENCLAW_AGENT_ID.')
    timeout=int(os.getenv('OPENCLAW_EVAL_TIMEOUT_SECONDS','120')); binary=os.getenv('OPENCLAW_BIN','openclaw'); timezone=os.getenv('SWYFT_EVAL_TIME_ZONE','UTC')
    suite=datetime.now(ZoneInfo(timezone)).date().isoformat(); agent_key=os.getenv('SWYFT_EXPECTED_AGENT_KEY',args.agent_id)
    api=Api(os.getenv('LANGFUSE_BASE_URL','https://cloud.langfuse.com'),required('LANGFUSE_PUBLIC_KEY'),required('LANGFUSE_SECRET_KEY'))
    ds,cases=fetch(api)
    if args.dry_run:
        print(json.dumps({'dataset':DATASET,'activeTestCount':len(cases),'suiteDate':suite,'tests':[{'id':i.get('id'),'question':mapping(i.get('input')).get('question'),'matchMode':mapping(i.get('metadata')).get('matchMode')} for i in cases]},indent=2)); return 0
    if not cases: log('no active cases; exiting successfully'); return 0
    session=latest_session(args.agent_id,binary,timeout); experiment=f'swyft-agent-correctness-{agent_key}-{suite}'
    summary={'total':len(cases),'passed':0,'failed':0,'deliveryErrors':0}; log(f'Running {len(cases)} case(s) through existing session {session}.')
    for item in cases:
        result=run_case(item,args.agent_id,binary,session,timeout); summary['passed' if result['passed'] else 'failed']+=1
        try: emit(api,ds,item,result,experiment,suite,agent_key)
        except Exception as e: summary['deliveryErrors']+=1; log(f'Langfuse delivery failed for item {item.get("id")}: {clean(e)}')
    log(json.dumps(summary)); return 1 if summary['deliveryErrors'] else 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except (RunnerError,ValueError) as error: log(str(error)); raise SystemExit(1)
