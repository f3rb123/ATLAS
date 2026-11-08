"""Typed, bounded repository tools and an offline Linux namespace sandbox."""
import ast,os,re,resource,shutil,subprocess,zipfile,io
from pathlib import Path
from typing import Literal
from pydantic import Field
from .policy import Strict,Denied,Scope,request
from .db import document,append,canonical,digest,uid,now
from .config import settings
from .vault import redact

EXCLUDED={'.git','.env','.venv','node_modules','vendor','dist','build','.next','__pycache__'}
SECRET=re.compile(r'(?i)(\.env|id_rsa|id_ed25519|\.pem$|\.key$|credentials|secret|\.p12$)')
class ReadInput(Strict):
    path:str
    start:int=Field(default=1,ge=1)
    end:int=Field(default=200,ge=1,le=1000000)
class SearchInput(Strict):
    query:str=Field(min_length=1,max_length=200)
class ExecutionInput(Strict):
    template:Literal['python_unittest','python_compile']
    test_path:str=Field(default='tests')

class Repository:
    def __init__(self,root):self.root=Path(root).resolve()
    def path(self,path):
        p=(self.root/path).resolve()
        if not p.is_relative_to(self.root) or any(x in EXCLUDED for x in p.relative_to(self.root).parts) or SECRET.search(path):raise Denied('Path excluded or outside snapshot')
        return p
    def files(self):
        files=[];ignored=[];total=0
        for root,dirs,names in os.walk(self.root,followlinks=False):
            dirs[:]=sorted(d for d in dirs if d not in EXCLUDED and not Path(root,d).is_symlink())
            for name in sorted(names):
                p=Path(root,name);rel=str(p.relative_to(self.root))
                if p.is_symlink() or SECRET.search(rel) or p.stat().st_size>512000:ignored.append(rel);continue
                total+=p.stat().st_size
                if len(files)>=10000 or total>50*1024*1024:raise Denied('Repository indexing quota exceeded')
                files.append(rel)
        return files,ignored
    def read(self,r):
        if r.end-r.start>400:raise Denied('Read range too large')
        p=self.path(r.path)
        if not p.is_file() or p.stat().st_size>512000:raise Denied('File exceeds read policy')
        text=redact(p.read_text(errors='replace'));lines=text.splitlines()
        return {'path':r.path,'start':r.start,'end':min(r.end,len(lines)),'text':'\n'.join(lines[r.start-1:r.end]),'sha256':digest(p.read_bytes()),'trust':'untrusted_repository_data'}
    def inventory(self):
        files,ignored=self.files();symbols=[]
        for f in files:
            if f.endswith('.py'):
                try:
                    tree=ast.parse(self.path(f).read_text())
                    for node in ast.walk(tree):
                        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):symbols.append({'path':f,'name':node.name,'line':node.lineno,'end':node.end_lineno})
                except (SyntaxError,UnicodeDecodeError):pass
        return {'files':files,'ignored':ignored,'symbols':symbols[:10000],'snapshot_hash':digest(canonical([(f,digest(self.path(f).read_bytes())) for f in files]))}
    def search(self,query):
        files,_=self.files();results=[]
        for f in files:
            text=redact(self.path(f).read_text(errors='replace'))
            for i,line in enumerate(text.splitlines(),1):
                if query.casefold() in line.casefold():results.append({'path':f,'line':i,'text':line[:500]})
                if len(results)>=100:return results
        return results

def upload_snapshot(data):
    if len(data)>20*1024*1024:raise Denied('Upload too large')
    root=Path(settings().data_dir)/'repos'/uid();root.mkdir(parents=True,mode=0o700)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos=z.infolist()
            if len(infos)>10000 or sum(i.file_size for i in infos)>50*1024*1024:raise Denied('Archive quota exceeded')
            for i in infos:
                if i.is_dir():continue
                p=Path(i.filename)
                if p.is_absolute() or '..' in p.parts or (i.external_attr>>16)&0o170000==0o120000:raise Denied('Unsafe archive path')
                if any(x in EXCLUDED for x in p.parts) or SECRET.search(i.filename):continue
                target=root/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(i))
        return root
    except Exception:shutil.rmtree(root);raise

def sandbox_limits():
    resource.setrlimit(resource.RLIMIT_CPU,(20,20));resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024));resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024*1024,2*1024*1024));resource.setrlimit(resource.RLIMIT_NOFILE,(64,64));current_uid=os.getuid();existing=0
    for process in Path('/proc').iterdir():
        try:
            if process.name.isdigit() and process.stat().st_uid==current_uid:existing+=len(list((process/'task').iterdir()))
        except FileNotFoundError:pass
    # RLIMIT_NPROC counts all host processes of this UID, including the API/Node.
    resource.setrlimit(resource.RLIMIT_NPROC,(existing+32,existing+32))

def execute_offline(repo,args):
    if not shutil.which('bwrap'):raise Denied('Offline sandbox unavailable')
    target=repo.path(args.test_path)
    if not target.exists():raise Denied('Test path missing')
    if args.template=='python_unittest':command=['/usr/bin/python3','-I','-m','unittest','discover','-s','/work/'+args.test_path,'-v']
    else:command=['/usr/bin/python3','-I','-m','compileall','-q','/work/'+args.test_path]
    base=['bwrap','--unshare-all','--die-with-parent','--new-session','--cap-drop','ALL','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--ro-bind',str(repo.root),'/work','--chdir','/work','--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','HOME','/tmp','--setenv','PYTHONDONTWRITEBYTECODE','1']
    # Output to bounded file avoids PIPE RAM exhaustion; process creates a new session.
    import tempfile
    with tempfile.TemporaryFile() as f:
        try:
            p=subprocess.run(base+command,stdout=f,stderr=subprocess.STDOUT,timeout=30,preexec_fn=sandbox_limits)
            f.seek(0);text=redact(f.read(1024*1024).decode(errors='replace'));return {'exit_code':p.returncode,'output':text,'template':args.template,'snapshot':repo.inventory()['snapshot_hash'],'timed_out':False}
        except subprocess.TimeoutExpired:return {'exit_code':None,'output':'Sandbox timeout','timed_out':True}

TOOLS={'list_repo_files':('read_only',None),'read_file_range':('read_only',ReadInput),'search_symbols':('read_only',SearchInput),'search_text':('read_only',SearchInput),'read_manifest':('read_only',ReadInput),'read_test_metadata':('read_only',ReadInput),'get_repo_commit_metadata':('read_only',None),'run_approved_test_command':('gated',ExecutionInput),'run_local_reproduction':('gated',ExecutionInput)}

def broker(db,run,repo,name,payload,actor):
    v=run.value();decision='deny'
    try:
        if name not in TOOLS:raise Denied('Tool not registered')
        if v.get('status') not in ('running','queued'):raise Denied('Run is not active')
        kill=db.get(type(run),'kill-switch')
        if kill and kill.value().get('enabled'):raise Denied('Emergency stop active')
        if v.get('tool_calls',0)>=v.get('max_tool_calls',50):raise Denied('Tool budget exhausted')
        risk,model=TOOLS[name];args=model.model_validate(payload) if model else None
        if risk=='gated' and not v.get('offline_execution_approved'):raise Denied('Explicit offline execution approval required')
        if name=='list_repo_files':result=repo.inventory()
        elif name in ('read_file_range','read_manifest','read_test_metadata'):result=repo.read(args)
        elif name in ('search_symbols','search_text'):result=repo.search(args.query)
        elif name=='get_repo_commit_metadata':result={'snapshot_hash':repo.inventory()['snapshot_hash'],'origin':'owner_upload'}
        else:result=execute_offline(repo,args)
        v['tool_calls']=v.get('tool_calls',0)+1;run.data=canonical(v);decision='allow'
        artifact=document(db,'artifact',run.owner,{'sha256':digest(canonical(result)),'media_type':'application/json','payload':result,'sensitivity':'campaign_private'})
        return {'artifact_id':artifact.id,'trust':'untrusted_tool_data','result':result}
    finally:append(db,run.id,actor,'policy_decision',{'tool':name,'decision':decision,'input_hash':digest(canonical(payload))},v['campaign_id'])
