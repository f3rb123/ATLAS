"""Provider-neutral typed adapters, identity-bound credentials and budget reservations."""
import json,time,threading
from typing import Literal,Protocol,AsyncIterator
from urllib.parse import urlsplit,urlunsplit
from pydantic import Field
from .policy import Strict,Scope,Rule,normalize,addresses,request,Denied
from .config import settings
from .db import Document,document,canonical,append,uid,digest,now
from .vault import seal,open_secret

ADAPTERS=['openai_chat_completions','openai_responses','anthropic_messages','gemini','ollama_openai_compatible','custom_openai_compatible','deepseek']
BLOCK_HEADERS={'host','content-length','connection','transfer-encoding','upgrade','proxy-authorization','proxy-connection','forwarded','x-forwarded-host','x-forwarded-for','cookie','set-cookie','te','trailer'}
class ProviderInput(Strict):
    display_name:str=Field(min_length=1,max_length=100)
    adapter_type:Literal['openai_chat_completions','openai_responses','anthropic_messages','gemini','ollama_openai_compatible','custom_openai_compatible','deepseek']='custom_openai_compatible'
    base_url:str
    api_path:str|None=None
    auth_mode:Literal['bearer','x-api-key','anthropic','gemini','custom','none']='bearer'
    auth_header_name:str|None=None
    api_key:str=Field(default='',max_length=8192,repr=False)
    headers:dict[str,str]={}
    secret_headers:dict[str,str]=Field(default={},repr=False)
    organization_id:str|None=None
    enabled:bool=True
class ModelInput(Strict):
    model_id:str=Field(min_length=1,max_length=200,pattern=r'^[a-zA-Z0-9_.:/-]+$')
    display_name:str=''
    context_window:int=Field(default=32000,ge=512,le=2000000)
    max_output_tokens:int=Field(default=2048,ge=1,le=100000)
    capabilities:dict[str,bool]={}
    input_price:float=Field(default=10,ge=0,le=1000)
    output_price:float=Field(default=30,ge=0,le=1000)
class ModelRequest(Strict):
    model:str
    messages:list[dict]
    max_tokens:int=Field(default=2048,ge=1,le=100000)
    temperature:float=Field(default=0.2,ge=0,le=2)
    structured:bool=True
    tools:list[dict]=[]
class ModelResponse(Strict):
    content:str
    structured_content:dict|None=None
    tool_calls:list[dict]=[]
    finish_reason:str|None=None
    input_tokens:int=0;output_tokens:int=0
    usage_estimated:bool=False
    model_id:str='';request_id:str|None=None;latency_ms:float=0
    warnings:list[str]=[]
class ModelProvider(Protocol):
    def generate(self,request:ModelRequest)->ModelResponse:...
    def stream(self,request:ModelRequest):...
    def list_models(self)->list:...
    def health_check(self)->dict:...

class ProviderError(ValueError): pass

def validate_headers(h):
    import re
    for k,v in h.items():
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,63}',k) or k.lower() in BLOCK_HEADERS or k.lower().startswith(('proxy-','x-forwarded-')) or '\r' in v or '\n' in v:raise Denied('Unsafe provider header')

def provider_scope(url):
    n,h,p,path,scheme=normalize(url)
    exact=f'{h}:{p}';local=exact in settings().provider_local_allowlist
    if scheme!='https' and not local:raise Denied('HTTPS required; local inference requires operator allowlist')
    if settings().provider_allowlist and exact not in settings().provider_allowlist and not local:raise Denied('Provider not in operator egress allowlist')
    labs=[]
    if local:
        import socket
        labs=[ip+('/128' if ':' in ip else '/32') for ip in {r[4][0] for r in socket.getaddrinfo(h,p,type=socket.SOCK_STREAM)}]
    addresses(h,p,labs)
    return Scope(allow=[Rule(host=h,ports=[p],schemes=[scheme],methods=['GET','POST'])],lab_networks=labs)

def safe_metadata(d):
    v=d.value();return {'id':d.id,'version':d.version,**{k:x for k,x in v.items() if k not in ('secret','secret_headers','headers')},'headers':{k:val for k,val in v.get('headers',{}).items() if k.lower() not in ('authorization','x-api-key')},'secret_configured':bool(v.get('secret'))}

def create_provider(db,owner,input,id=None):
    v=input.model_dump();validate_headers(v['headers']);validate_headers(v['secret_headers']);provider_scope(v['base_url'])
    if v['auth_header_name']:validate_headers({v['auth_header_name']:'x'})
    if any(k.lower() in ('authorization','x-api-key','x-goog-api-key') for k in v['headers']):raise Denied('Credentials must use encrypted fields')
    if v['api_path'] and (not v['api_path'].startswith('/') or '://' in v['api_path'] or '..' in v['api_path'] or '?' in v['api_path']):raise Denied('Invalid path override')
    id=id or uid();key=v.pop('api_key');secret_headers=v.pop('secret_headers');v['fingerprint']=digest(key)[:12] if key else None
    v['secret']=seal(key,f'provider:{owner}:{id}:1') if key else None
    v['secret_headers']=seal(canonical(secret_headers),f'headers:{owner}:{id}:1')
    v['health_status']='untested';v['created_at']=now()
    d=document(db,'provider',owner,v,id);append(db,owner,owner,'provider_created',{'id':id,'fingerprint':v['fingerprint']});return d

class Adapter:
    version='1.0'
    def __init__(self,d):self.d=d;self.v=d.value()
    def path(self,kind,model=''):
        base=self.v['base_url'].rstrip('/');u=urlsplit(base)
        if u.query or u.fragment:raise Denied('Provider base URLs cannot include query or fragment')
        protocol=self.v['adapter_type'];override=self.v.get('api_path')
        if kind=='models':suffix='/models'
        elif override:suffix=override
        elif protocol=='openai_responses':suffix='/responses'
        elif protocol=='anthropic_messages':suffix='/messages'
        elif protocol=='gemini':suffix=f'/models/{model}:generateContent'
        else:suffix='/chat/completions'
        return base+suffix
    def headers(self):
        v=self.v;h={'Content-Type':'application/json','Accept-Encoding':'identity',**v.get('headers',{})}
        key=open_secret(v['secret'],f'provider:{self.d.owner}:{self.d.id}:1') if v.get('secret') else ''
        h.update(json.loads(open_secret(v['secret_headers'],f'headers:{self.d.owner}:{self.d.id}:1')))
        if v['auth_mode']=='bearer':h['Authorization']='Bearer '+key
        elif v['auth_mode'] in ('x-api-key','anthropic'):h['x-api-key']=key
        elif v['auth_mode']=='gemini':h['x-goog-api-key']=key
        elif v['auth_mode']=='custom':h[v['auth_header_name']]=key
        if v['adapter_type']=='anthropic_messages':h['anthropic-version']='2023-06-01'
        if v.get('organization_id'):h['OpenAI-Organization']=v['organization_id']
        validate_headers(h);return h
    def serialize(self,r,stream=False):
        protocol=self.v['adapter_type'];messages=r.messages
        if protocol=='anthropic_messages':
            result={'model':r.model,'max_tokens':r.max_tokens,'messages':[m for m in messages if m['role']!='system'],'system':'\n'.join(m['content'] for m in messages if m['role']=='system')}
        elif protocol=='gemini':
            result={'contents':[{'role':'model' if m['role']=='assistant' else 'user','parts':[{'text':m['content']}]} for m in messages if m['role']!='system'],'generationConfig':{'maxOutputTokens':r.max_tokens,'temperature':r.temperature}}
            system='\n'.join(m['content'] for m in messages if m['role']=='system')
            if system:result['systemInstruction']={'parts':[{'text':system}]}
            if r.structured:result['generationConfig']['responseMimeType']='application/json'
        elif protocol=='openai_responses':result={'model':r.model,'input':messages,'max_output_tokens':r.max_tokens}
        else:
            result={'model':r.model,'messages':messages,'max_tokens':r.max_tokens,'temperature':r.temperature}
            if r.structured:result['response_format']={'type':'json_object'}
            if r.tools:result['tools']=r.tools
        if stream:
            if protocol=='gemini':raise ProviderError('Gemini streaming requires streamGenerateContent transport; unsupported')
            result['stream']=True
        return result
    def normalize(self,p,r):
        protocol=self.v['adapter_type'];usage=p.get('usage') or {};calls=[];finish=None
        if protocol=='anthropic_messages':
            content=''.join(c.get('text','') for c in p['content'] if c['type']=='text');calls=[c for c in p['content'] if c['type']=='tool_use'];inp=usage.get('input_tokens');out=usage.get('output_tokens');finish=p.get('stop_reason')
        elif protocol=='gemini':
            cand=p['candidates'][0];parts=cand['content']['parts'];content=''.join(c.get('text','') for c in parts);calls=[c['functionCall'] for c in parts if 'functionCall' in c];u=p.get('usageMetadata',{});inp=u.get('promptTokenCount');out=u.get('candidatesTokenCount');finish=cand.get('finishReason')
        elif protocol=='openai_responses':
            content=''.join(c.get('text','') for o in p.get('output',[]) for c in o.get('content',[]) if c.get('type')=='output_text');calls=[o for o in p.get('output',[]) if o.get('type')=='function_call'];inp=usage.get('input_tokens');out=usage.get('output_tokens');finish=p.get('status')
        else:
            c=p['choices'][0];m=c['message'];content=m.get('content') or '';calls=m.get('tool_calls',[]);inp=usage.get('prompt_tokens');out=usage.get('completion_tokens');finish=c.get('finish_reason')
        est=inp is None or out is None
        inp=inp if isinstance(inp,int) and inp>=0 else sum(len(m.get('content','')) for m in r.messages)
        out=out if isinstance(out,int) and out>=0 else len(content)
        if inp>10000000 or out>10000000:raise ProviderError('Malformed usage counters')
        structured=None
        if r.structured:
            try:structured=json.loads(content)
            except (TypeError,json.JSONDecodeError):raise ProviderError('Provider did not return valid JSON')
            if not isinstance(structured,dict):raise ProviderError('Structured object required')
        return ModelResponse(content=content,structured_content=structured,tool_calls=calls,finish_reason=finish,input_tokens=inp,output_tokens=out,usage_estimated=est,model_id=r.model,request_id=p.get('id'))
    def generate(self,r):
        url=self.path('generate',r.model);scope=provider_scope(url);t=time.monotonic()
        try:
            status,_,body=request(url,'POST',self.headers(),canonical(self.serialize(r)).encode(),scope,2*1024*1024,30)
            if status!=200:raise ProviderError({401:'authentication_failed',403:'access_denied',429:'rate_limited'}.get(status,'provider_http_error'))
            result=self.normalize(json.loads(body),r);result.latency_ms=(time.monotonic()-t)*1000;return result
        except (TimeoutError,ConnectionError,OSError):raise ProviderError('Provider transport/TLS failure') from None
        except (KeyError,IndexError,json.JSONDecodeError):raise ProviderError('Provider response parse failure') from None
    def stream(self,r):
        # Real protocol event iterator; no simulated streaming of a buffered response.
        from .policy import authorize,PinnedConnection
        url=self.path('generate',r.model);n,h,p,ips=authorize(provider_scope(url),url,'POST');u=urlsplit(n)
        c=PinnedConnection(h,ips[0],p,u.scheme=='https',30)
        try:
            c.request('POST',u.path,body=canonical(self.serialize(r,True)).encode(),headers=self.headers());response=c.getresponse()
            if response.status!=200:raise ProviderError('Streaming provider request failed')
            total=0
            while True:
                line=response.readline(65537);total+=len(line)
                if len(line)>65536 or total>2*1024*1024:raise ProviderError('Stream quota exceeded')
                if not line:break
                if not line.startswith(b'data:'):continue
                data=line[5:].strip()
                if data==b'[DONE]':break
                event=json.loads(data);protocol=self.v['adapter_type']
                if protocol=='anthropic_messages':text=event.get('delta',{}).get('text','')
                elif protocol=='openai_responses':text=event.get('delta','') if event.get('type')=='response.output_text.delta' else ''
                else:text=next(iter(event.get('choices',[])),{}).get('delta',{}).get('content','')
                yield {'type':'content_delta','text':text}
        finally:c.close()
    def list_models(self):
        url=self.path('models');status,_,body=request(url,'GET',self.headers(),scope=provider_scope(url),max_bytes=256000,timeout=10)
        if status!=200:raise ProviderError('Model discovery unavailable; manual entry is supported')
        p=json.loads(body);return p.get('data',p.get('models',[]))
    def health_check(self):return {'status':'reachable','models':self.list_models()}

def reserve(db,owner,run_id,ceiling):
    # Global mutex row locks serialize reservations across workers and request contexts.
    d=db.query(Document).filter_by(id='budget-global').with_for_update().first()
    if not d:d=document(db,'budget','system',{'cap':settings().monthly_budget,'spent':{},'reserved':{}},'budget-global')
    v=d.value();month=now()[:7];spent=v['spent'].get(month,0);pending=sum(x['amount'] for x in v['reserved'].values())
    if spent+pending+ceiling>v['cap']:raise ProviderError('Monthly budget exhausted')
    id=uid();v['reserved'][id]={'amount':ceiling,'month':month,'run_id':run_id};d.data=canonical(v);db.commit();return id

def settle(db,reservation,cost):
    d=db.query(Document).filter_by(id='budget-global').with_for_update().one();v=d.value();r=v['reserved'].pop(reservation)
    v['spent'][r['month']]=v['spent'].get(r['month'],0)+cost;d.data=canonical(v)

def generate_budgeted(db,provider,model,req,run):
    m=model.value();rv=run.value();estimate=(sum(len(x['content']) for x in req.messages)*m['input_price']+req.max_tokens*m['output_price'])/1000000
    if rv.get('budget_used',0)+estimate>rv['budget_limit']:raise ProviderError('Run budget exhausted')
    reservation=reserve(db,run.owner,run.id,estimate)
    # Unknown transport outcomes retain their full reservation; never assume no bill.
    try:response=Adapter(provider).generate(req)
    except Exception:raise
    cost=(response.input_tokens*m['input_price']+response.output_tokens*m['output_price'])/1000000
    settle(db,reservation,max(cost,estimate) if response.usage_estimated else cost)
    document(db,'usage',run.owner,{'run_id':run.id,'provider_id':provider.id,'model':req.model,'input_tokens':response.input_tokens,'output_tokens':response.output_tokens,'cost':cost,'estimated':response.usage_estimated})
    rv['budget_used']=rv.get('budget_used',0)+cost;run.data=canonical(rv);db.commit();return response
