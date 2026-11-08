"""Authenticated versioned HTTP API shared by the Web UI and CLI."""
import asyncio,json,secrets,time,io,zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from fastapi import FastAPI,Request,Response,HTTPException,Depends,UploadFile,File
from fastapi.responses import JSONResponse,StreamingResponse
from fastapi.exceptions import RequestValidationError
from pydantic import Field
from sqlalchemy import text
from .config import settings
from .source_policy import SourcePolicy
from .db import session,engine,User,Session,Document,Journal,Knowledge,Chunk,Alias,document,append,canonical,digest,uid,now
from . import auth
from .policy import Strict,Scope,Denied
from .gateway import ProviderInput,ModelInput,create_provider,safe_metadata,Adapter,ADAPTERS,ProviderError,ModelRequest
from .workflow import control
from .vault import master,seal

@asynccontextmanager
async def lifespan(app):
    from .logging import configure
    configure()
    master()
    with engine().connect() as c:c.execute(text('SELECT 1'))
    yield
app=FastAPI(title='ATLAS',version='0.1.0',docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)

def cookie_name():return auth.COOKIE if settings().production else 'atlas_dev'

def db_dep():
    with session() as db:
        try:yield db
        finally:db.close()

def identity(request:Request,db=Depends(db_dep)):
    bearer=request.headers.get('authorization','')
    token=bearer[7:] if bearer.startswith('Bearer ') else request.cookies.get(cookie_name(),'')
    if not token:raise HTTPException(401,'Authentication required')
    try:u,s=auth.identify(db,token)
    except ValueError:raise HTTPException(401,'Authentication required')
    if bearer:
        if s.scopes=='browser':raise HTTPException(401,'Use a dedicated CLI token')
        collection=request.url.path.split('/')[3]
        needed='read' if request.method=='GET' else {'campaigns':'campaign','runs':'run','providers':'provider','skills':'skill','budgets':'budget','model-configs':'model-config','corpus':'corpus','knowledge':'knowledge','findings':'finding','reports':'report','repositories':'repo','benchmarks':'benchmark'}.get(collection,collection)
        if needed not in json.loads(s.scopes):raise HTTPException(403,'Token scope denied')
    elif request.method not in ('GET','HEAD'):
        if request.headers.get('origin')!=settings().external_url:raise HTTPException(403,'Origin denied')
        if digest(request.headers.get('x-csrf-token',''))!=s.csrf_hash:raise HTTPException(403,'CSRF validation failed')
    if u.role=='read_only' and request.method not in ('GET','HEAD'):raise HTTPException(403,'Read-only identity')
    if request.method not in ('GET','HEAD'):auth.throttle(db,'mutation:'+u.id,120,60)
    db.commit();return u,s

def enrolled(request:Request,who=Depends(identity),db=Depends(db_dep)):
    u,s=who
    if not s.mfa:raise HTTPException(403,'Complete MFA authentication/enrollment')
    if not db.query(Document).filter_by(kind='passkey',owner=u.id).first():raise HTTPException(403,'Passkey enrollment required')
    if settings().production and not settings().passkey_only_recovery:
        if not u.totp or not db.query(Document).filter_by(kind='recovery',owner=u.id).first():raise HTTPException(403,'Complete TOTP fallback and recovery code setup in Security')
    return who

def admin(who=Depends(enrolled)):
    if who[0].role!='owner_admin':raise HTTPException(403,'Owner administrator required')
    return who

def stepup(who=Depends(admin)):
    if who[1].stepup<time.time()-300:raise HTTPException(403,'Recent WebAuthn step-up required')
    return who

def security_stepup(who=Depends(identity),db=Depends(db_dep)):
    u,s=who
    if u.role!='owner_admin' or not s.mfa or s.stepup<time.time()-300 or not db.query(Document).filter_by(kind='passkey',owner=u.id).first():raise HTTPException(403,'Recent owner WebAuthn step-up required')
    return who

def own(db,id,kind,owner,lock=False):
    q=db.query(Document).filter_by(id=id,kind=kind,owner=owner)
    d=q.with_for_update().first() if lock else q.first()
    if not d:raise HTTPException(404,'Resource not found')
    return d

def expose(d):return {'id':d.id,'version':d.version,**d.value()}
def audit(db,owner,action,data):append(db,owner,owner,action,data)

def set_session(response,s,token,csrf):
    response.set_cookie(cookie_name(),token,secure=settings().production,httponly=True,samesite='strict',path='/',max_age=int(s.expires-time.time()))
    return {'csrf_token':csrf,'mfa':bool(s.mfa)}

@app.middleware('http')
async def security(request,call_next):
    correlation=uid();started=time.monotonic()
    if len(request.headers.get('content-length','0'))>12:return JSONResponse({'error':'Request too large'},413)
    try:
        if int(request.headers.get('content-length','0'))>21*1024*1024:return JSONResponse({'error':'Request too large'},413)
    except ValueError:return JSONResponse({'error':'Invalid request length'},400)
    if settings().production and request.headers.get('host')!=__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(settings().external_url).netloc:return JSONResponse({'error':'Unknown host'},400)
    response=await call_next(request)
    for k,v in {'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",'X-Correlation-ID':correlation}.items():response.headers[k]=v
    if settings().production:response.headers['Strict-Transport-Security']='max-age=31536000'
    import logging
    route=request.scope.get('route');route_name=getattr(route,'path','[unmatched]')
    logging.getLogger('atlas').info('http_request',extra={'correlation_id':correlation,'route':route_name,'method':request.method,'status':response.status_code,'duration_ms':round((time.monotonic()-started)*1000,2)})
    return response

@app.exception_handler(RequestValidationError)
async def invalid_request(request,exc):
    return JSONResponse({'error':{'code':'invalid_request','details':[{'location':e['loc'],'message':e['msg'],'type':e['type']} for e in exc.errors()]}},422)

@app.exception_handler(ValueError)
async def invalid(request,exc):return JSONResponse({'error':{'code':'validation_failed','message':str(exc)[:300]}},400)
@app.exception_handler(Denied)
async def denied(request,exc):return JSONResponse({'error':{'code':'policy_denied','message':str(exc)[:300]}},403)
@app.exception_handler(ProviderError)
async def provider_error(request,exc):return JSONResponse({'error':{'code':'provider_error','message':str(exc)[:200]}},409)

@app.get('/health/live')
def live():return {'status':'alive'}
@app.get('/health/ready')
def ready(db=Depends(db_dep)):
    try:
        master();db.execute(text('SELECT 1'))
        if settings().production:
            u=db.query(User).filter_by(role='owner_admin').first()
            if not u or not db.query(Document).filter_by(kind='passkey',owner=u.id).first() or (not settings().passkey_only_recovery and (not u.totp or not db.query(Document).filter_by(kind='recovery',owner=u.id).first())):raise HTTPException(503,'Owner security enrollment required')
        return {'status':'ready'}
    except HTTPException:raise
    except Exception:raise HTTPException(503,'Dependency unavailable')
@app.get('/api/v1/schema')
def schema(who=Depends(enrolled)):return app.openapi()

class Bootstrap(Strict):token:str=Field(repr=False,max_length=200);email:str=Field(min_length=3,max_length=254,pattern=r'^[^@\s]+@[^@\s]+$');password:str=Field(repr=False,max_length=1024)
class Login(Strict):email:str=Field(max_length=254);password:str=Field(repr=False,max_length=1024)
class Code(Strict):code:str=Field(repr=False)
class Credential(Strict):credential:dict

@app.post('/api/v1/auth/bootstrap')
def bootstrap(body:Bootstrap,response:Response,request:Request,db=Depends(db_dep)):
    auth.throttle(db,'bootstrap:'+str(request.client.host),5)
    u=auth.bootstrap(db,body.token,body.email,body.password)
    document(db,'bootstrap_complete','system',{'completed':now()},'owner-bootstrap-complete')
    s,t,c=auth.issue(db,u);db.commit();return set_session(response,s,t,c)
@app.post('/api/v1/auth/login')
def login(body:Login,response:Response,request:Request,db=Depends(db_dep)):
    auth.throttle(db,'login-ip:'+str(request.client.host),30)
    auth.throttle(db,'login-account:'+body.email.lower(),8)
    s,t,c=auth.login(db,body.email,body.password);db.commit();return set_session(response,s,t,c)
@app.get('/api/v1/users/me')
def me(who=Depends(identity),db=Depends(db_dep)):
    u,s=who;csrf=secrets.token_urlsafe(32);s=db.get(Session,s.id);s.csrf_hash=digest(csrf);db.commit()
    return {'id':u.id,'email':u.email,'role':u.role,'mfa':bool(s.mfa),'stepup_recent':s.stepup>time.time()-300,'passkey_count':db.query(Document).filter_by(kind='passkey',owner=u.id).count(),'totp_enrolled':bool(u.totp),'csrf_token':csrf}
@app.post('/api/v1/auth/logout')
def logout(response:Response,who=Depends(identity),db=Depends(db_dep)):
    db.delete(db.get(Session,who[1].id));db.commit();response.delete_cookie(cookie_name(),path='/');return {'status':'logged_out'}

@app.post('/api/v1/auth/webauthn/{kind}/options')
def options(kind:str,who=Depends(identity),db=Depends(db_dep)):
    if kind not in ('registration','authentication'):raise HTTPException(404)
    u,s=who;auth.throttle(db,'passkey:'+s.id,20)
    result=auth.challenge(db,db.get(User,u.id),db.get(Session,s.id),kind);db.commit();return result
@app.post('/api/v1/auth/webauthn/{kind}/verify')
def verify(kind:str,body:Credential,response:Response,who=Depends(identity),db=Depends(db_dep)):
    if kind not in ('registration','authentication'):raise HTTPException(404)
    u,s=who;u=db.get(User,u.id);s=db.get(Session,s.id)
    try:auth.verify_passkey(db,u,s,body.credential,kind)
    except Exception:
        db.commit();raise HTTPException(400,'Passkey verification failed') from None
    if kind=='authentication':
        old=s;s,t,c=auth.issue(db,u,True);s.stepup=time.time();db.delete(old);db.commit();return set_session(response,s,t,c)
    previous_mfa=bool(s.mfa);db.query(Session).filter_by(user_id=u.id).delete();s,t,c=auth.issue(db,u,previous_mfa);db.commit()
    return {**set_session(response,s,t,c),'status':'enrolled','next':'Authenticate with passkey to complete MFA'}
@app.post('/api/v1/auth/totp/setup')
def totp_setup(who=Depends(identity),db=Depends(db_dep)):
    result=auth.totp_setup(db,db.get(User,who[0].id),db.get(Session,who[1].id));db.commit();return {'provisioning_uri':result}
@app.post('/api/v1/auth/totp/{action}')
def totp_verify(action:str,body:Code,response:Response,who=Depends(identity),db=Depends(db_dep)):
    if action not in ('enroll','verify'):raise HTTPException(404)
    u=db.get(User,who[0].id);s=db.get(Session,who[1].id);auth.throttle(db,'totp:'+u.id,5)
    auth.totp_verify(db,u,s,body.code,enroll=action=='enroll')
    if action=='verify':
        old=s;s,t,c=auth.issue(db,u,True);db.delete(old);db.commit();return set_session(response,s,t,c)
    previous_mfa=bool(s.mfa);db.query(Session).filter_by(user_id=u.id).delete();s,t,c=auth.issue(db,u,previous_mfa);db.commit();return {**set_session(response,s,t,c),'status':'totp_enrolled'}
@app.post('/api/v1/auth/recovery-codes/regenerate')
def codes(who=Depends(security_stepup),db=Depends(db_dep)):
    result=auth.recovery_codes(db,db.get(User,who[0].id));db.commit();return {'codes':result,'notice':'Store securely; displayed only once'}
@app.post('/api/v1/auth/recovery/consume')
def recover(body:Code,response:Response,who=Depends(identity),db=Depends(db_dep)):
    u=db.get(User,who[0].id);s=db.get(Session,who[1].id);auth.throttle(db,'recovery:'+u.id,5);auth.recovery_consume(db,u,s,body.code)
    old=s;s,t,c=auth.issue(db,u,True);db.delete(old);db.commit();return set_session(response,s,t,c)
@app.get('/api/v1/auth/sessions')
def sessions(who=Depends(enrolled),db=Depends(db_dep)):
    return [{'id':s.id,'created':s.created,'last_used':s.used,'expires':s.expires,'scopes':s.scopes,'current':s.id==who[1].id} for s in db.query(Session).filter_by(user_id=who[0].id)]
@app.delete('/api/v1/auth/sessions/{id}')
def revoke_session(id:str,who=Depends(stepup),db=Depends(db_dep)):
    s=db.get(Session,id)
    if not s or s.user_id!=who[0].id:raise HTTPException(404)
    db.delete(s);audit(db,who[0].id,'session_revoked',{'id':id});db.commit();return {'status':'revoked'}
class TokenInput(Strict):
    scopes:list[Literal['read','campaign','run','knowledge','provider','corpus','skill','budget','model-config','benchmark','finding','repo','report']]=['read']
    expires_hours:int=Field(default=24,ge=1,le=168)
@app.post('/api/v1/auth/cli-tokens')
def cli_token(body:TokenInput,who=Depends(stepup),db=Depends(db_dep)):
    sensitive=bool(set(body.scopes)&{'provider','corpus','skill','budget','model-config','benchmark','report'})
    s,t,c=auth.issue(db,who[0],True,canonical(body.scopes),300 if sensitive else body.expires_hours*3600)
    if sensitive:s.stepup=who[1].stepup
    audit(db,who[0].id,'cli_token_created',{'id':s.id,'scopes':body.scopes});db.commit();return {'id':s.id,'token':t,'expires':s.expires}

class CampaignInput(Strict):
    name:str=Field(min_length=1,max_length=200)
    description:str=''
    mode:Literal['knowledge','repository','passive','safe-active','lab']='repository'
    authorization_ref:str=Field(min_length=1,max_length=2000)
    authorization_attested:bool
    scope:Scope=Field(default_factory=Scope)
    policy_notes:str=''
    budget_limit:float=Field(default=10,gt=0,le=1000)
@app.post('/api/v1/campaigns')
def campaign_create(body:CampaignInput,who=Depends(enrolled),db=Depends(db_dep)):
    if not body.authorization_attested:raise Denied('Explicit authorization attestation required')
    v=body.model_dump();scope=v.pop('scope');c=document(db,'campaign',who[0].id,v)
    p=document(db,'policy',who[0].id,{'campaign_id':c.id,'scope':scope,'hash':digest(canonical(scope)),'approved_by':who[0].id})
    v['policy_id']=p.id;c.data=canonical(v);audit(db,who[0].id,'campaign_created',{'id':c.id,'policy_hash':p.value()['hash']});db.commit();return expose(c)
@app.post('/api/v1/campaigns/{id}/scope/validate')
def scope_validate(id:str,body:Scope,who=Depends(enrolled),db=Depends(db_dep)):
    own(db,id,'campaign',who[0].id)
    from .policy import host
    for rule in body.allow+body.deny:
        if '/' in rule.host:
            __import__('ipaddress').ip_network(rule.host,strict=False)
        else:host(rule.host.removeprefix('*.'))
    return {'normalized':body.model_dump(),'hash':digest(canonical(body.model_dump()))}
@app.post('/api/v1/campaigns/{id}/scope/versions')
def scope_version(id:str,body:Scope,who=Depends(stepup),db=Depends(db_dep)):
    c=own(db,id,'campaign',who[0].id,True);p=document(db,'policy',who[0].id,{'campaign_id':id,'scope':body.model_dump(),'hash':digest(canonical(body.model_dump())),'approved_by':who[0].id})
    v=c.value();v['policy_id']=p.id;c.data=canonical(v);c.version+=1;audit(db,who[0].id,'scope_version_created',{'campaign_id':id,'policy_id':p.id});db.commit();return expose(p)
@app.post('/api/v1/campaigns/{id}/repositories')
async def repository_upload(id:str,file:UploadFile=File(...),who=Depends(enrolled),db=Depends(db_dep)):
    own(db,id,'campaign',who[0].id)
    from .tools import upload_snapshot,Repository
    data=await file.read(20*1024*1024+1);root=upload_snapshot(data);inventory=Repository(root).inventory()
    d=document(db,'repository',who[0].id,{'campaign_id':id,'path':str(root),'inventory':inventory,'origin':'owner_upload','snapshot_hash':inventory['snapshot_hash']});db.commit();return {'id':d.id,'inventory':inventory}
class RunInput(Strict):
    repository_id:str|None=None
    budget_limit:float=Field(default=1,gt=0,le=100)
    max_seconds:int=Field(default=1800,ge=30,le=86400)
    max_tool_calls:int=Field(default=50,ge=1,le=500)
    offline_execution_approved:bool=False
    knowledge_ids:list[str]=[]
    max_model_calls:int=Field(default=20,ge=1,le=100)
    role_budgets:dict[str,float]={}
@app.post('/api/v1/campaigns/{id}/runs')
def run_start(id:str,body:RunInput,request:Request,who=Depends(enrolled),db=Depends(db_dep)):
    c=own(db,id,'campaign',who[0].id);p=own(db,c.value()['policy_id'],'policy',who[0].id)
    kill=db.get(Document,'kill-switch')
    if kill and kill.value()['enabled']:raise Denied('Emergency stop active')
    if body.repository_id:
        repo=own(db,body.repository_id,'repository',who[0].id)
        if repo.value()['campaign_id']!=id:raise Denied('Repository belongs to another campaign')
    key=request.headers.get('idempotency-key')
    if key:
        key=digest(who[0].id+':run:'+id+':'+key)[:36];old=db.get(Document,key)
        if old:return expose(old)
    if any(not __import__('math').isfinite(value) or value<=0 or value>body.budget_limit for value in body.role_budgets.values()):raise Denied('Role budgets must be positive and within the run cap')
    models={}
    for d in db.query(Document).filter_by(kind='alias',owner=who[0].id):
        a=d.value();provider=own(db,a['provider_id'],'provider',who[0].id);model=own(db,a['model_id'],'provider_model',who[0].id);models[a['alias']]={**a,'provider_version':provider.version,'model_version':model.version}
    v={**body.model_dump(),'campaign_id':id,'policy_id':p.id,'policy_hash':p.value()['hash'],'state':'CREATED','status':'queued','budget_used':0,'models':models,'deadline':time.time()+body.max_seconds,'started_at':now(),'workflow_version':'1.0'}
    pinned_skills=[d for d in db.query(Document).filter_by(kind='skill',owner=who[0].id) if d.value().get('enabled') and d.value().get('status')=='validated'][:3]
    v['skills']=[{'id':d.id,'skill_id':d.value()['skill_id'],'version':d.value()['version'],'hash':d.value()['content_hash']} for d in pinned_skills]
    d=document(db,'run',who[0].id,v,key if key else None)
    for skill in v['skills']:append(db,d.id,who[0].id,'skill_loaded',{**skill,'reason':'Validated enabled source-review procedure; subordinate to campaign policy'},id)
    append(db,d.id,who[0].id,'run_created',{'policy_hash':p.value()['hash']},id);db.commit();return expose(d)
@app.post('/api/v1/runs/{id}/control/{action}')
def run_control(id:str,action:str,who=Depends(enrolled),db=Depends(db_dep)):
    run=own(db,id,'run',who[0].id,True)
    if action not in ('pause','resume','cancel','approve','reject'):raise HTTPException(404)
    if action in ('approve','reject'):
        v=run.value();v['offline_execution_approved']=action=='approve';run.data=canonical(v);append(db,id,who[0].id,'execution_approval',{'decision':action},v['campaign_id'])
        if action=='approve':control(db,run,'resume',who[0].id)
    else:control(db,run,action,who[0].id)
    db.commit();return expose(run)
@app.get('/api/v1/runs/{id}/events')
async def events(id:str,request:Request,after:int=0,who=Depends(enrolled),db=Depends(db_dep)):
    own(db,id,'run',who[0].id)
    try:after=max(after,int(request.headers.get('last-event-id','0')))
    except ValueError:raise HTTPException(400,'Invalid event cursor')
    async def stream():
        cursor=after
        for _ in range(120):
            if await request.is_disconnected():return
            with session() as s:
                rows=s.query(Journal).filter(Journal.stream==id,Journal.sequence>cursor).order_by(Journal.sequence).limit(100).all()
                for e in rows:cursor=e.sequence;yield f'id: {e.sequence}\ndata: {e.payload}\n\n'
            yield ': heartbeat\n\n';await asyncio.sleep(1)
    return StreamingResponse(stream(),media_type='text/event-stream')

@app.get('/api/v1/providers/adapters')
def adapters(who=Depends(enrolled)):return {'adapters':ADAPTERS,'adapter_version':'1.0'}
@app.post('/api/v1/providers')
def provider_add(body:ProviderInput,who=Depends(stepup),db=Depends(db_dep)):
    d=create_provider(db,who[0].id,body);db.commit();return safe_metadata(d)
@app.post('/api/v1/providers/{id}/models')
def model_add(id:str,body:ModelInput,who=Depends(stepup),db=Depends(db_dep)):
    own(db,id,'provider',who[0].id);d=document(db,'provider_model',who[0].id,{'provider_id':id,**body.model_dump(),'verified_structured':False,'capability_status':'user_declared_unverified'});db.commit();return expose(d)
@app.get('/api/v1/providers/{id}/models')
def models(id:str,who=Depends(enrolled),db=Depends(db_dep)):
    own(db,id,'provider',who[0].id);return [expose(d) for d in db.query(Document).filter_by(kind='provider_model',owner=who[0].id) if d.value()['provider_id']==id]
class TestInput(Strict):model_id:str|None=None
@app.post('/api/v1/providers/{id}/test')
def provider_test(id:str,body:TestInput,who=Depends(stepup),db=Depends(db_dep)):
    d=own(db,id,'provider',who[0].id);auth.throttle(db,'provider-test:'+who[0].id,5)
    if body.model_id:
        m=own(db,body.model_id,'provider_model',who[0].id)
        if m.value()['provider_id']!=id:raise Denied('Model/provider mismatch')
        req=ModelRequest(model=m.value()['model_id'],messages=[{'role':'user','content':'Return only {"ok":true} as JSON.'}],max_tokens=32)
        from .gateway import reserve,settle
        mv=m.value();estimate=(128*mv['input_price']+32*mv['output_price'])/1000000
        reservation=reserve(db,who[0].id,'provider_test',estimate)
        result=Adapter(d).generate(req);settle(db,reservation,max(estimate,(result.input_tokens*mv['input_price']+result.output_tokens*mv['output_price'])/1000000))
        if result.structured_content!={'ok':True}:raise ProviderError('Structured capability probe failed')
        v=m.value();v['verified_structured']=True;v['capability_status']='structured_output_verified';m.data=canonical(v);result={'status':'structured_output_verified'}
    else:result=Adapter(d).health_check()
    v=d.value();v['health_status']='tested';v['last_tested']=now();d.data=canonical(v);audit(db,who[0].id,'provider_test',{'id':id,'status':'success'});db.commit();return result
@app.post('/api/v1/providers/{id}/models/discover')
def discover(id:str,who=Depends(stepup),db=Depends(db_dep)):
    d=own(db,id,'provider',who[0].id);auth.throttle(db,'provider-discover:'+who[0].id,5);return Adapter(d).list_models()
class KeyInput(Strict):api_key:str=Field(min_length=1,max_length=8192,repr=False)
def active_provider(db,owner,id):
    return any(v['provider_id']==id for r in db.query(Document).filter_by(kind='run',owner=owner) if r.value()['status'] not in ('completed','cancelled') for v in r.value().get('models',{}).values())
@app.post('/api/v1/providers/{id}/secret')
def rotate(id:str,body:KeyInput,who=Depends(stepup),db=Depends(db_dep)):
    d=own(db,id,'provider',who[0].id,True)
    if active_provider(db,who[0].id,id):raise HTTPException(409,'Provider pinned by active run')
    v=d.value();v['secret']=seal(body.api_key,f'provider:{d.owner}:{d.id}:1');v['fingerprint']=digest(body.api_key)[:12];v['health_status']='untested';d.data=canonical(v);d.version+=1;audit(db,who[0].id,'provider_key_rotated',{'id':id,'fingerprint':v['fingerprint']});db.commit();return safe_metadata(d)
@app.patch('/api/v1/providers/{id}')
def provider_edit(id:str,body:ProviderInput,who=Depends(stepup),db=Depends(db_dep)):
    old=own(db,id,'provider',who[0].id,True)
    if active_provider(db,who[0].id,id):raise HTTPException(409,'Provider pinned by active run')
    # New immutable connection version preserves historical metadata.
    d=create_provider(db,who[0].id,body);v=old.value();v['enabled']=False;old.data=canonical(v);old.version+=1;db.commit();return safe_metadata(d)
@app.delete('/api/v1/providers/{id}')
def provider_delete(id:str,who=Depends(stepup),db=Depends(db_dep)):
    d=own(db,id,'provider',who[0].id,True)
    if active_provider(db,who[0].id,id):raise HTTPException(409,'Provider pinned by active run')
    v=d.value();v['enabled']=False;v['deleted']=True;v['secret']=None;v['secret_headers']=seal('{}',f'headers:{d.owner}:{d.id}:1');d.data=canonical(v);d.version+=1;audit(db,who[0].id,'provider_deleted',{'id':id});db.commit();return {'status':'deleted','historical_metadata_retained':True}
class AliasInput(Strict):
    alias:Literal['fast','reasoning','verifier','embedding','vision','coding']
    provider_id:str
    model_id:str
@app.put('/api/v1/model-configs')
def alias_set(body:AliasInput,who=Depends(stepup),db=Depends(db_dep)):
    own(db,body.provider_id,'provider',who[0].id);m=own(db,body.model_id,'provider_model',who[0].id)
    if m.value()['provider_id']!=body.provider_id:raise Denied('Model/provider mismatch')
    for d in db.query(Document).filter_by(kind='alias',owner=who[0].id):
        if d.value()['alias']==body.alias:db.delete(d)
    d=document(db,'alias',who[0].id,body.model_dump());db.commit();return expose(d)

@app.get('/api/v1/corpus/stats')
def corpus_stats(who=Depends(enrolled),db=Depends(db_dep)):
    from .corpus import stats
    return stats(db)
@app.get('/api/v1/corpus/sources')
def corpus_sources(who=Depends(enrolled)):
    from .corpus import SOURCES
    return SOURCES
class Search(Strict):query:str=Field(min_length=1,max_length=500);source:str|None=None;limit:int=Field(default=5,ge=1,le=20)
@app.post('/api/v1/knowledge/search')
def knowledge_search(body:Search,who=Depends(enrolled),db=Depends(db_dep)):
    from .corpus import search
    return search(db,body.query,body.source,body.limit,who[0].id)
@app.post('/api/v1/knowledge/ingest')
async def knowledge_import(request:Request,file:UploadFile=File(...),license:str='unknown',source_url:str='owner:upload',who=Depends(enrolled),db=Depends(db_dep)):
    import tempfile
    from .corpus import import_file
    data=await file.read(20*1024*1024+1)
    if len(data)>20*1024*1024:raise HTTPException(413)
    with tempfile.TemporaryDirectory() as td:
        path=Path(td)/Path(file.filename or 'import.txt').name;path.write_bytes(data);result=import_file(db,path,license,source_url,owner=who[0].id)
    audit(db,who[0].id,'knowledge_import',{'counts':result});db.commit();return result
class CorpusSync(Strict):source:Literal['ghsa','cve','nvd','osv','kev'];limit:int=Field(default=1000,ge=1,le=100000)
@app.post('/api/v1/corpus/sync')
def corpus_sync(body:CorpusSync,who=Depends(stepup),db=Depends(db_dep)):
    d=document(db,'corpus_request',who[0].id,{**body.model_dump(),'status':'queued'});db.commit();return expose(d)
@app.post('/api/v1/runs/{id}/reports')
def report(id:str,format:Literal['markdown','json','html','sarif','pdf']='markdown',who=Depends(stepup),db=Depends(db_dep)):
    from .reporting import generate_report
    run=own(db,id,'run',who[0].id);d=generate_report(db,run,format);audit(db,who[0].id,'report_export',{'id':d.id});db.commit();return expose(d)
@app.get('/api/v1/budgets')
def budgets(who=Depends(enrolled),db=Depends(db_dep)):
    d=db.get(Document,'budget-global');return d.value() if d else {'cap':settings().monthly_budget,'spent':{},'reserved':{}}
class BudgetInput(Strict):cap:float=Field(gt=0,le=10000)
@app.patch('/api/v1/budgets')
def budget_set(body:BudgetInput,who=Depends(stepup),db=Depends(db_dep)):
    d=db.query(Document).filter_by(id='budget-global').with_for_update().first()
    if not d:d=document(db,'budget','system',{'cap':body.cap,'spent':{},'reserved':{}},'budget-global')
    else:v=d.value();v['cap']=body.cap;d.data=canonical(v)
    audit(db,who[0].id,'budget_changed',{'cap':body.cap});db.commit();return d.value()
@app.post('/api/v1/admin/kill-switch')
def kill(enabled:bool=True,who=Depends(stepup),db=Depends(db_dep)):
    d=db.get(Document,'kill-switch')
    if d:d.data=canonical({'enabled':enabled})
    else:document(db,'kill_switch','system',{'enabled':enabled},'kill-switch')
    if enabled:
        for r in db.query(Document).filter_by(kind='run'):
            if r.value()['status'] not in ('completed','cancelled'):control(db,r,'cancel',who[0].id)
    audit(db,who[0].id,'kill_switch_changed',{'enabled':enabled});db.commit();return {'enabled':enabled}
@app.get('/api/v1/doctor')
def doctor(who=Depends(enrolled),db=Depends(db_dep)):
    workers={d.id:time.time()-d.value()['timestamp']<10 for d in db.query(Document).filter_by(kind='heartbeat')}
    return {'database':'ready','master_key':'ready','workers':workers,'production':settings().production,'passkey_count':db.query(Document).filter_by(kind='passkey',owner=who[0].id).count(),'totp_enrolled':bool(who[0].totp),'target_traffic':'GET/HEAD through scoped relay; source-only modes deny target requests','sandbox':'requires_linux_user_namespaces','public_registration':False}

# Bounded object APIs share ownership policy. Internal documents and secrets are excluded.
KINDS={'campaigns':'campaign','runs':'run','findings':'finding','repositories':'repository','reports':'report','providers':'provider','model-configs':'alias','skills':'skill','benchmarks':'benchmark','approvals':'approval','usage':'usage'}
@app.get('/api/v1/{collection}')
def list_objects(collection:str,offset:int=0,limit:int=50,who=Depends(enrolled),db=Depends(db_dep)):
    if collection not in KINDS:raise HTTPException(404)
    rows=db.query(Document).filter_by(kind=KINDS[collection],owner=who[0].id).order_by(Document.created.desc()).offset(max(0,offset)).limit(min(100,max(1,limit))).all()
    return [safe_metadata(d) if collection=='providers' else {k:v for k,v in expose(d).items() if k!='path'} for d in rows]
@app.get('/api/v1/{collection}/{id}')
def get_object(collection:str,id:str,who=Depends(enrolled),db=Depends(db_dep)):
    if collection not in KINDS:raise HTTPException(404)
    d=own(db,id,KINDS[collection],who[0].id)
    return safe_metadata(d) if collection=='providers' else {k:v for k,v in expose(d).items() if k!='path'}

# Explicit registry routes are inserted before the generic collection routes below.
class SkillImport(Strict):package:str=Field(max_length=200000)
@app.post('/api/v1/skills/import')
def skill_import(body:SkillImport,who=Depends(stepup),db=Depends(db_dep)):
    from .skills import parse_skill,import_skill
    d=import_skill(db,who[0].id,parse_skill(body.package));db.commit();return expose(d)
@app.post('/api/v1/skills/{id}/control/{action}')
def skill_control(id:str,action:Literal['review','validate','enable','disable','rollback'],who=Depends(stepup),db=Depends(db_dep)):
    from .skills import review,validate,enable
    d=own(db,id,'skill',who[0].id,True)
    if action=='review':review(db,d,who[0].id)
    elif action=='validate':validate(db,d,who[0].id)
    elif action in ('enable','disable'):enable(db,d,who[0].id,action=='enable')
    else:
        v=d.value();others=[s for s in db.query(Document).filter_by(kind='skill',owner=who[0].id) if s.value()['skill_id']==v['skill_id'] and s.id!=d.id and s.value()['status']=='validated']
        if not others:raise Denied('No previously validated version')
        for s in db.query(Document).filter_by(kind='skill',owner=who[0].id):
            if s.value()['skill_id']==v['skill_id']:enable(db,s,who[0].id,False)
        enable(db,sorted(others,key=lambda s:s.created)[-1],who[0].id,True)
    db.commit();return expose(d)

@app.post('/api/v1/benchmarks/run')
def benchmark_run(who=Depends(stepup),db=Depends(db_dep)):
    d=document(db,'sandbox_benchmark_request',who[0].id,{'status':'queued','lease_until':0});db.commit();return expose(d)

@app.post('/api/v1/corpus/validate')
def corpus_validate(who=Depends(admin),db=Depends(db_dep)):
    from .records import Record
    passed=failed=0
    for record in db.query(Knowledge).filter(Knowledge.owner.in_(['public',who[0].id])).yield_per(200):
        try:Record.model_validate_json(record.record);passed+=1
        except ValueError:failed+=1
    return {'validated':passed,'failed':failed}
@app.post('/api/v1/corpus/dedupe')
def corpus_dedupe(who=Depends(stepup),db=Depends(db_dep)):
    from .corpus import near_duplicates
    return {'candidates':near_duplicates(db),'action':'review_only_no_destructive_merge'}
@app.get('/api/v1/corpus/errors')
def corpus_errors(offset:int=0,limit:int=50,who=Depends(admin),db=Depends(db_dep)):
    return [expose(d) for d in db.query(Document).filter_by(kind='import_error').offset(max(0,offset)).limit(min(100,max(1,limit)))]

class FindingUpdate(Strict):
    status:Literal['reported','fixed','closed']
    review_notes:str=Field(min_length=1,max_length=6000)
@app.patch('/api/v1/findings/{id}')
def finding_update(id:str,body:FindingUpdate,who=Depends(enrolled),db=Depends(db_dep)):
    if who[0].role not in ('owner_admin','reviewer'):raise HTTPException(403)
    d=own(db,id,'finding',who[0].id,True);v=d.value()
    transitions={'confirmed':['reported','fixed','closed'],'reported':['fixed','closed'],'fixed':['closed']}
    if body.status not in transitions.get(v['status'],[]):raise Denied('Only evidence-confirmed findings may enter reporting/fix workflow')
    v.update(body.model_dump());d.data=canonical(v);audit(db,who[0].id,'finding_status_changed',{'id':id,'status':body.status});db.commit();return expose(d)
@app.get('/api/v1/findings/{id}/evidence')
def finding_evidence(id:str,who=Depends(enrolled),db=Depends(db_dep)):
    d=own(db,id,'finding',who[0].id);return [expose(own(db,x,'artifact',who[0].id)) for x in d.value()['evidence_ids']]
@app.get('/api/v1/repositories/{id}/inventory')
def repository_inventory(id:str,who=Depends(enrolled),db=Depends(db_dep)):
    d=own(db,id,'repository',who[0].id);return d.value()['inventory']
class SourceRead(Strict):path:str;start:int=Field(default=1,ge=1);end:int=Field(default=200,ge=1)
@app.post('/api/v1/repositories/{id}/read')
def repository_read(id:str,body:SourceRead,who=Depends(enrolled),db=Depends(db_dep)):
    from .tools import Repository,ReadInput
    d=own(db,id,'repository',who[0].id);return Repository(d.value()['path']).read(ReadInput(**body.model_dump()))
@app.get('/api/v1/runs/{id}/objects/{kind}')
def run_objects(id:str,kind:Literal['hypotheses','stages','tools'],who=Depends(enrolled),db=Depends(db_dep)):
    own(db,id,'run',who[0].id)
    if kind=='stages':return [expose(d) for d in db.query(Document).filter_by(kind='stage_result',owner=id)]
    if kind=='hypotheses':return [expose(d) for d in db.query(Document).filter_by(kind='hypothesis',owner=who[0].id) if d.value()['run_id']==id]
    return [json.loads(e.payload) for e in db.query(Journal).filter_by(stream=id).order_by(Journal.sequence) if json.loads(e.payload)['type']=='policy_decision']

@app.post('/api/v1/skills/starter')
def skill_starter(who=Depends(stepup),db=Depends(db_dep)):
    from .skills import STARTER,import_skill
    d=import_skill(db,who[0].id,STARTER);db.commit();return expose(d)
@app.post('/api/v1/skills/{id}/benchmark')
def skill_benchmark(id:str,who=Depends(stepup),db=Depends(db_dep)):
    from .skills import benchmark_skill
    d=own(db,id,'skill',who[0].id,True);b=benchmark_skill(db,d,who[0].id);db.commit();return expose(b)
@app.post('/api/v1/skills/import-archive')
async def skill_archive(file:UploadFile=File(...),who=Depends(stepup),db=Depends(db_dep)):
    from .skills import parse_skill,import_skill
    data=await file.read(5*1024*1024+1)
    if len(data)>5*1024*1024:raise HTTPException(413)
    results=[]
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if len(z.infolist())>200 or sum(i.file_size for i in z.infolist())>10*1024*1024:raise Denied('Skill archive quota exceeded')
        for info in z.infolist():
            if '..' in Path(info.filename).parts or Path(info.filename).is_absolute():raise Denied('Unsafe skill reference path')
            if info.filename.endswith(('.sh','.py','.js')):
                raise Denied('Executable skill package requires separate offline review; import its declarative SKILL.md alone')
            if info.filename.endswith('SKILL.md'):results.append(expose(import_skill(db,who[0].id,parse_skill(z.read(info).decode()))))
    if not results:raise ValueError('No SKILL.md found')
    db.commit();return results

class ResumeCorpus(Strict):job_id:str;limit:int=Field(default=1000,ge=1,le=100000)
@app.post('/api/v1/corpus/resume')
def corpus_resume(body:ResumeCorpus,who=Depends(stepup),db=Depends(db_dep)):
    job=db.get(Document,body.job_id)
    if not job or job.kind!='corpus_job':raise HTTPException(404)
    d=document(db,'corpus_request',who[0].id,{'source':job.value()['source'],'limit':body.limit,'resume_id':job.id,'status':'queued'});db.commit();return expose(d)

@app.post('/api/v1/corpus/embed')
def corpus_embed(who=Depends(stepup),db=Depends(db_dep)):
    d=document(db,'index_request',who[0].id,{'status':'queued','cursor':'','processed':0,'limit':100000});db.commit();return expose(d)
@app.get('/api/v1/corpus/jobs')
def corpus_jobs(offset:int=0,limit:int=50,who=Depends(admin),db=Depends(db_dep)):
    return [expose(d) for d in db.query(Document).filter(Document.kind.in_(['corpus_job','corpus_request','index_request']),Document.owner.in_(['system',who[0].id])).order_by(Document.created.desc()).offset(max(0,offset)).limit(min(100,max(1,limit)))]
@app.get('/api/v1/corpus/export')
def corpus_export(who=Depends(stepup)):
    owner=who[0].id
    def generate():
        with session() as db:
            for k in db.query(Knowledge).filter(Knowledge.owner.in_(['public',owner])).yield_per(200):yield k.record+'\n'
    return StreamingResponse(generate(),media_type='application/x-ndjson',headers={'Content-Disposition':'attachment; filename="atlas-corpus.jsonl"'})

@app.get('/api/v1/capabilities')
def capabilities(who=Depends(enrolled)):
    from .capabilities import CAPABILITIES,TOOLS
    return {'categories':CAPABILITIES,'tools':TOOLS,'advanced_adapters':'disabled until fixture, sandbox and verifier support are available'}

class ModelBenchmarkInput(Strict):
    model_ids:list[str]=Field(min_length=1,max_length=5)
    budget_per_model:float=Field(default=1,gt=0,le=10)
@app.post('/api/v1/benchmarks/models')
def benchmark_models(body:ModelBenchmarkInput,who=Depends(stepup),db=Depends(db_dep)):
    from .model_benchmarks import create
    result=create(db,who[0].id,body.model_ids,body.budget_per_model);db.commit();return {'run_ids':result,'note':'Budgeted synthetic benchmark, not live target testing or a universal ranking'}

@app.post('/api/v1/corpus/sources')
def register_source(body:SourcePolicy,who=Depends(stepup),db=Depends(db_dep)):
    from .source_policy import register
    d=register(db,who[0].id,body);db.commit();return expose(d)
@app.get('/api/v1/corpus/sources/reviewed')
def reviewed_sources(who=Depends(admin),db=Depends(db_dep)):
    return [expose(d) for d in db.query(Document).filter_by(kind='source_policy',owner=who[0].id)]
@app.post('/api/v1/corpus/sources/{id}/sync')
def acquire_source(id:str,who=Depends(stepup),db=Depends(db_dep)):
    d=own(db,id,'source_policy',who[0].id)
    if not d.value()['enabled'] or not d.value()['owner_reviewed']:raise Denied('Source review and enablement required')
    native=d.value().get('native_source')
    job=document(db,'corpus_request' if native else 'source_acquisition_request',who[0].id,{'source_id':id,'source':native,'limit':1000,'status':'queued','lease_until':0});db.commit();return expose(job)

@app.get('/api/v1/auth/passkeys')
def passkeys(who=Depends(identity),db=Depends(db_dep)):
    return [{'id':d.id,'created':d.created,'fingerprint':digest(d.value()['credential_id'])[:12],'backed_up':d.value().get('backed_up',False),'signature_counter':d.value()['sign_count']} for d in db.query(Document).filter_by(kind='passkey',owner=who[0].id)]
@app.delete('/api/v1/auth/passkeys/{id}')
def remove_passkey(id:str,response:Response,who=Depends(security_stepup),db=Depends(db_dep)):
    d=own(db,id,'passkey',who[0].id,True)
    if db.query(Document).filter_by(kind='passkey',owner=who[0].id).count()<=1:raise Denied('Keep at least one passkey; privileged host recovery is required for complete reset')
    db.delete(d);audit(db,who[0].id,'passkey_removed',{'id':id});db.query(Session).filter_by(user_id=who[0].id).delete()
    s,t,c=auth.issue(db,who[0],True);db.commit();return set_session(response,s,t,c)
@app.post('/api/v1/auth/sessions/revoke-all')
def revoke_all_sessions(response:Response,who=Depends(security_stepup),db=Depends(db_dep)):
    db.query(Session).filter_by(user_id=who[0].id).delete();audit(db,who[0].id,'all_sessions_revoked',{});db.commit();response.delete_cookie(cookie_name(),path='/');return {'status':'revoked'}
