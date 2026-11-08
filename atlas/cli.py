"""API-backed CLI. Host-only operations explicitly separated and never remote recovery."""
import getpass,json,os,sys
from pathlib import Path
import typer,httpx
from . import __version__
app=typer.Typer(no_args_is_help=True)
groups={}
for name in ['auth','campaign','run','finding','report','provider','corpus','skills','knowledge','scope','repo','host']:
 g=typer.Typer(no_args_is_help=True);app.add_typer(g,name=name);groups[name]=g

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
if __name__=='__main__':app()
