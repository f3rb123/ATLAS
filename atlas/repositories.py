"""Authorized bounded GitHub source acquisition; no checkout hooks, submodules or scripts."""
import os,re,resource,subprocess,tarfile,shutil,tempfile
from pathlib import Path
from .policy import normalize,addresses,Denied
from .config import settings
from .db import uid
from .tools import Repository,EXCLUDED,SECRET

def git_limits():
    resource.setrlimit(resource.RLIMIT_FSIZE,(100*1024*1024,100*1024*1024));resource.setrlimit(resource.RLIMIT_CPU,(45,45))

def clone_snapshot(url,ref='HEAD'):
    n,host,port,path,scheme=normalize(url)
    if scheme!='https' or host!='github.com' or port!=443 or '?' in n or not re.fullmatch(r'/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?',path):raise Denied('Only explicit HTTPS GitHub repository URLs are enabled')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/._-]{0,199}',ref) or '..' in ref:raise Denied('Invalid Git ref')
    ip=addresses(host,port)[0]
    root=Path(settings().data_dir);id=uid();cache=root/'git-cache'/id;snapshot=root/'repos'/id
    cache.parent.mkdir(parents=True,exist_ok=True,mode=0o700);snapshot.mkdir(parents=True,mode=0o700)
    env={**os.environ,'GIT_TERMINAL_PROMPT':'0','GIT_LFS_SKIP_SMUDGE':'1'}
    base=['git','-c','core.hooksPath=/dev/null','-c','http.followRedirects=false','-c','protocol.file.allow=never','-c','http.curloptResolve=github.com:443:'+ip]
    process=None
    try:
        command=base+['clone','--bare','--filter=blob:none','--depth','1','--no-tags',n,str(cache)]
        result=subprocess.run(command,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=60,preexec_fn=git_limits)
        if result.returncode:raise Denied('Repository clone failed; verify access, ref and bounded repository size')
        if ref!='HEAD':
            r=subprocess.run(base+['-C',str(cache),'fetch','--depth','1','origin',ref],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=60,preexec_fn=git_limits)
            if r.returncode:raise Denied('Requested repository ref unavailable')
        target='FETCH_HEAD' if ref!='HEAD' else 'HEAD'
        commit=subprocess.check_output(base+['-C',str(cache),'rev-parse','--verify',target+'^{commit}'],env=env,text=True,timeout=10).strip()
        archive_file=tempfile.TemporaryFile()
        archived=subprocess.run(base+['-C',str(cache),'archive','--format=tar',commit],env=env,stdout=archive_file,stderr=subprocess.DEVNULL,preexec_fn=git_limits,timeout=60)
        if archived.returncode:raise Denied('Repository archive failed')
        archive_file.seek(0);count=size=0
        with tarfile.open(fileobj=archive_file,mode='r|') as archive:
            for member in archive:
                if not member.isfile():continue
                p=Path(member.name)
                if p.is_absolute() or '..' in p.parts:raise Denied('Unsafe Git archive path')
                if any(x in EXCLUDED for x in p.parts) or SECRET.search(str(p)):continue
                count+=1;size+=member.size
                if count>10000 or size>50*1024*1024:raise Denied('Repository snapshot exceeds quota')
                if member.size>512000:continue
                dest=snapshot/p;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(archive.extractfile(member).read());dest.chmod(0o600)
        archive_file.close()
        inventory=Repository(snapshot).inventory()
        return {'path':str(snapshot),'git_cache':str(cache),'origin':n,'commit_hash':commit,'branch':ref,'snapshot_hash':inventory['snapshot_hash'],'inventory':inventory}
    except (subprocess.SubprocessError,OSError):
        raise Denied('Repository acquisition failed or timed out') from None
    finally:
        if 'archive_file' in locals():archive_file.close()
        # Snapshot is retained only on complete successful inventory.
        if 'inventory' not in locals():shutil.rmtree(snapshot,ignore_errors=True);shutil.rmtree(cache,ignore_errors=True)
