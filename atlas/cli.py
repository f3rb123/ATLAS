"""API-backed CLI. Host-only operations explicitly separated and never remote recovery."""
import getpass,json,os,sys
from pathlib import Path
import typer,httpx
from . import __version__
app=typer.Typer(no_args_is_help=True,pretty_exceptions_show_locals=False)
groups={}
for name in ['auth','campaign','run','finding','report','provider','corpus','skills','knowledge','scope','repo','host','benchmark']:
 g=typer.Typer(no_args_is_help=True,pretty_exceptions_show_locals=False);app.add_typer(g,name=name);groups[name]=g

def client_request(path,method='GET',body=None,files=None):
 token=os.environ.get('ATLAS_CLI_TOKEN')
 if not token:raise typer.BadParameter('Set ATLAS_CLI_TOKEN to a scoped expiring token created in Security settings')
 with httpx.Client(base_url=os.environ.get('ATLAS_API_URL','http://127.0.0.1:8000')+'/api/v1/',headers={'Authorization':'Bearer '+token},timeout=60,follow_redirects=False) as c:
  r=c.request(method,path,json=body if files is None else None,files=files)
  if not r.is_success:typer.echo(r.text,err=True);raise typer.Exit(1)
  return r.json()
def out(v):typer.echo(json.dumps(v,indent=2))
@app.command()
def version():typer.echo(__version__)
@app.command()
def doctor():out(client_request('doctor'))
@groups['campaign'].command('list')
def campaign_list():out(client_request('campaigns'))
@groups['campaign'].command('show')
def campaign_show(id:str):out(client_request('campaigns/'+id))
@groups['campaign'].command('create')
def campaign_create(file:Path):out(client_request('campaigns','POST',json.loads(file.read_text())))
@groups['scope'].command('validate')
def scope_validate(id:str,file:Path):
 import yaml
 out(client_request('campaigns/'+id+'/scope/validate','POST',yaml.safe_load(file.read_text())))
@groups['repo'].command('add')
def repo_add(id:str,file:Path):
 with file.open('rb') as f:out(client_request('campaigns/'+id+'/repositories','POST',files={'file':(file.name,f,'application/zip')}))
@groups['run'].command('start')
def run_start(campaign_id:str,repository_id:str|None=None,budget:float=1):out(client_request('campaigns/'+campaign_id+'/runs','POST',{'repository_id':repository_id,'budget_limit':budget}))
@groups['run'].command('status')
def run_status(id:str):out(client_request('runs/'+id))
@groups['run'].command('list')
def run_list():out(client_request('runs'))
def register_control(action):
 def command(id:str):out(client_request('runs/'+id+'/control/'+action,'POST',{}))
 groups['run'].command(action)(command)
for a in ['pause','resume','cancel','approve','reject']:register_control(a)
@groups['run'].command('events')
def events(id:str):
 token=os.environ.get('ATLAS_CLI_TOKEN','')
 with httpx.stream('GET',os.environ.get('ATLAS_API_URL','http://127.0.0.1:8000')+'/api/v1/runs/'+id+'/events',headers={'Authorization':'Bearer '+token},timeout=None) as r:
  if r.status_code!=200:raise typer.Exit(1)
  for line in r.iter_lines():typer.echo(line)
@groups['finding'].command('list')
def finding_list():out(client_request('findings'))
@groups['finding'].command('show')
def finding_show(id:str):out(client_request('findings/'+id))
@groups['report'].command('generate')
def report_generate(run_id:str,format:str='markdown'):out(client_request('runs/'+run_id+'/reports?format='+format,'POST',{}))
@groups['provider'].command('list')
def provider_list():out(client_request('providers'))
@groups['provider'].command('models')
def provider_models(id:str):out(client_request('providers/'+id+'/models'))
@groups['knowledge'].command('search')
def knowledge_search(query:str):out(client_request('knowledge/search','POST',{'query':query}))
@groups['knowledge'].command('ingest')
def knowledge_ingest(file:Path,license:str,source_url:str):
 with file.open('rb') as f:out(client_request('knowledge/ingest?license='+license+'&source_url='+source_url,'POST',files={'file':(file.name,f)}))
@groups['corpus'].command('stats')
def corpus_stats():out(client_request('corpus/stats'))
@groups['corpus'].command('sources')
def corpus_sources():out(client_request('corpus/sources'))
@groups['auth'].command('status')
def auth_status():out(client_request('users/me'))
@groups['auth'].command('sessions')
def auth_sessions():out(client_request('auth/sessions'))
@groups['auth'].command('login')
def auth_login():typer.echo('Sign in through the Web UI, complete passkey step-up and create a scoped CLI token in Security. Set ATLAS_CLI_TOKEN securely; browser sessions are not CLI credentials.')
@groups['host'].command('migrate')
def migrate():
 from alembic.config import Config
 from alembic import command
 command.upgrade(Config('alembic.ini'),'head');typer.echo('Migrations applied')
@groups['host'].command('init-key')
def init_key():
 from .config import settings
 p=Path(settings().master_key_file);p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f:f.write(os.urandom(32))
 typer.echo('Master key generated. Back up separately from database; never print it.')
@groups['host'].command('bootstrap')
def bootstrap():
 from .db import session
 from .auth import bootstrap_token
 if not sys.stdout.isatty():raise typer.BadParameter('Bootstrap token can be displayed only in an interactive terminal')
 with session() as s:typer.echo(bootstrap_token(s))
@groups['host'].command('corpus-sync')
def corpus_sync(source:str='ghsa',limit:int=21000,resume_id:str|None=None):
 from .corpus import sync_bulk,sync_api
 out(sync_bulk(source,limit,resume_id) if source in ('ghsa','cve') else sync_api(source,limit,job_id=resume_id))
@groups['host'].command('corpus-validate')
def corpus_validate():
 from .db import session,Knowledge
 from .records import Record
 n=0
 with session() as s:
  for k in s.query(Knowledge).yield_per(200):Record.model_validate_json(k.record);n+=1
 out({'validated':n})
@groups['host'].command('corpus-export')
def corpus_export(path:Path):
 from .db import session,Knowledge
 with session() as s,path.open('x') as f:
  for k in s.query(Knowledge).yield_per(200):f.write(k.record+'\n')
@groups['host'].command('break-glass')
def break_glass():
 if not sys.stdin.isatty() or not typer.confirm('Privileged host recovery: revoke ALL sessions, tokens and authenticators?'):raise typer.Exit(1)
 from .db import session,User,Session,Document,append
 from .auth import password_ok,ph
 password=getpass.getpass('New owner passphrase: ');password_ok(password)
 with session() as s:
  u=s.query(User).filter_by(role='owner_admin').one();u.password=ph.hash(password);u.mfa=0;u.totp=None;u.totp_counter=-1
  s.query(Session).delete()
  for kind in ['passkey','recovery','challenge','totp_pending']:s.query(Document).filter_by(kind=kind).delete()
  append(s,u.id,'host_operator','break_glass_recovery',{});s.commit()
 typer.echo('All sessions and authenticators revoked. Sign in and enroll new passkeys.')


@groups['provider'].command('add')
def provider_add(config_file:Path):
 v=json.loads(config_file.read_text());v['api_key']=getpass.getpass('Provider API key (write-only): ');out(client_request('providers','POST',v))
@groups['provider'].command('test')
def provider_test(id:str,model_id:str|None=None):out(client_request('providers/'+id+'/test','POST',{'model_id':model_id}))
@groups['provider'].command('rotate-key')
def provider_rotate(id:str):out(client_request('providers/'+id+'/secret','POST',{'api_key':getpass.getpass('New provider API key: ')}))
@groups['provider'].command('disable')
def provider_disable(id:str):out(client_request('providers/'+id,'DELETE'))
@groups['provider'].command('set-model')
def set_model(alias:str,provider_id:str,model_id:str):out(client_request('model-configs','PUT',{'alias':alias,'provider_id':provider_id,'model_id':model_id}))
@groups['corpus'].command('sync')
def api_sync(source:str,limit:int=1000):out(client_request('corpus/sync','POST',{'source':source,'limit':limit}))
@groups['corpus'].command('resume')
def api_resume(job_id:str,limit:int=1000):out(client_request('corpus/resume','POST',{'job_id':job_id,'limit':limit}))
@groups['corpus'].command('import')
def corpus_import(file:Path,license:str,source_url:str):knowledge_ingest(file,license,source_url)
@groups['corpus'].command('validate')
def corpus_validate_api():out(client_request('corpus/validate','POST',{}))
@groups['corpus'].command('dedupe')
def corpus_dedupe_api():out(client_request('corpus/dedupe','POST',{}))
@groups['skills'].command('import')
def skill_import(file:Path):out(client_request('skills/import','POST',{'package':file.read_text()}))
def skill_control(action):
 def command(id:str):out(client_request('skills/'+id+'/control/'+action,'POST',{}))
 groups['skills'].command(action)(command)
for action in ['review','validate','enable','disable','rollback']:skill_control(action)
@groups['host'].command('corpus-load')
def load_records():
 from .records import Record
 from .corpus import ingest
 from .db import session
 from .config import settings
 n=0
 with session() as s:
  for line in sys.stdin:
   r=Record.model_validate_json(line)
   raw_path=Path(settings().data_dir)/'corpus_raw'/r.source.content_hash_sha256[:2]/r.source.content_hash_sha256
   raw=raw_path.read_bytes()
   if __import__('hashlib').sha256(raw).hexdigest()!=r.source.content_hash_sha256:raise ValueError('Raw artifact checksum mismatch')
   ingest(s,r,raw);n+=1
   if n%200==0:s.commit()
  s.commit()
 out({'processed':n})


@groups['corpus'].command('embed')
def corpus_embed():out(client_request('corpus/embed','POST',{}))
@groups['corpus'].command('export')
def corpus_export_api(path:Path):
 token=os.environ.get('ATLAS_CLI_TOKEN')
 if not token:raise typer.BadParameter('Set a fresh scoped CLI token from WebAuthn step-up')
 with httpx.stream('GET',os.environ.get('ATLAS_API_URL','http://127.0.0.1:8000')+'/api/v1/corpus/export',headers={'Authorization':'Bearer '+token},timeout=120) as response:
  if response.status_code!=200:raise typer.Exit(1)
  with path.open('xb') as f:
   for data in response.iter_bytes():f.write(data)
 typer.echo('Corpus exported to '+str(path))


@groups['benchmark'].command('run')
def benchmark_run(model_id:str|None=None,budget:float=1):
 if model_id:out(client_request('benchmarks/models','POST',{'model_ids':[model_id],'budget_per_model':budget}))
 else:out(client_request('benchmarks/run','POST',{}))


@groups['host'].command('rotate-kek')
def rotate_kek(new_key_file:Path):
 if not sys.stdin.isatty() or not typer.confirm('Have all API/gateway/worker processes been stopped for KEK maintenance?'):raise typer.Exit(1)
 from .db import session
 from .vault import rotate_database_keys
 if new_key_file.stat().st_mode&0o077:raise typer.BadParameter('New key must be mode 0600/0400')
 with session() as db:n=rotate_database_keys(db,new_key_file.read_bytes());db.commit()
 typer.echo(f'Rewrapped {n} envelopes. Install the new KEK before restarting; keep the old KEK for old backups.')
if __name__=='__main__':app()
