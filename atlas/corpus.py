"""Policy-reviewed acquisition, canonical conversion, durable ingest and citation retrieval."""
import csv,hashlib,io,json,math,re,tarfile,time,zipfile,urllib.request
from pathlib import Path
from collections import Counter
import numpy as np
from sqlalchemy import func
from .db import Knowledge,Alias,Chunk,Document,session,document,canonical,digest,uid,now
from .records import Record,Source
from .config import settings
from .vault import redact

SOURCES={
 'ghsa':{'name':'GitHub Advisory Database','url':'https://github.com/github/advisory-database','terms':'https://raw.githubusercontent.com/github/advisory-database/main/LICENSE.md','license':'CC-BY-4.0','policy':'allowed','bulk':'https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main'},
 'cve':{'name':'CVE Program','url':'https://github.com/CVEProject/cvelistV5','terms':'https://www.cve.org/Legal/TermsOfUse','license':'LicenseRef-CVE-Terms','policy':'allowed','bulk':'https://codeload.github.com/CVEProject/cvelistV5/tar.gz/refs/heads/main'},
 'nvd':{'name':'NVD','url':'https://services.nvd.nist.gov/rest/json/cves/2.0','terms':'https://nvd.nist.gov/general/faq','license':'CC0-1.0','policy':'allowed'},
 'osv':{'name':'OSV','url':'https://api.osv.dev/v1/vulns','terms':'https://github.com/google/osv.dev/blob/master/LICENSE','license':'CC-BY-4.0','policy':'allowed'},
 'kev':{'name':'CISA KEV','url':'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json','terms':'https://www.cisa.gov/about/website-policies','license':'LicenseRef-US-Government','policy':'allowed'},
}

# Versioned deterministic local lexical embedding. No model download or billable API.
DIM=128
EMBEDDING_VERSION='signed-token-hash-v1-128'
def embed(text):
    v=np.zeros(DIM,dtype=np.float32)
    for token in re.findall(r'[a-z0-9_+-]+',text.lower()):
        b=hashlib.sha256(token.encode()).digest();v[int.from_bytes(b[:4])%DIM]+=1 if b[4]%2 else -1
    n=np.linalg.norm(v)
    return (v/n if n else v).tolist()

def source_record(source,item,raw,url=None):
    cfg=SOURCES[source];aliases=[];title='';summary='';kind='security_advisory';published=None;target={};classification={};research={}
    if source in ('ghsa','osv'):
        native=item['id'];aliases=list(set([native]+item.get('aliases',[])));title=item.get('summary') or native;summary=item.get('details','')
        published=item.get('published');kind='ghsa' if source=='ghsa' else 'osv'
        affected=item.get('affected',[])
        if affected:
            a=affected[0];pkg=a.get('package',{});target={'ecosystem':pkg.get('ecosystem'),'package':pkg.get('name'),'affected_versions':a.get('versions',[]),'fixed_versions':[e['fixed'] for r in a.get('ranges',[]) for e in r.get('events',[]) if 'fixed' in e]}
        classification['cwe']=item.get('database_specific',{}).get('cwe_ids',[])
        classification['severity_label']=item.get('database_specific',{}).get('severity')
        refs=[r['url'] for r in item.get('references',[]) if r.get('type')=='FIX'];research['patch_references']=refs
        if item.get('withdrawn'):raise ValueError('Withdrawn advisory: takedown required')
    elif source=='cve':
        meta=item['cveMetadata'];native=meta['cveId']
        if meta.get('state')!='PUBLISHED':raise ValueError('CVE not published')
        aliases=[native];cna=item['containers']['cna'];title=cna.get('title') or native;summary='\n'.join(d['value'] for d in cna.get('descriptions',[]) if d.get('lang','').startswith('en'));published=meta.get('datePublished');kind='cve'
        a=next(iter(cna.get('affected',[])),{});target={'vendor':a.get('vendor'),'product':a.get('product'),'affected_versions':a.get('versions',[])}
        classification['cwe']=[d['cweId'] for p in cna.get('problemTypes',[]) for d in p.get('descriptions',[]) if d.get('cweId')]
    elif source=='nvd':
        c=item.get('cve',item);native=c['id'];aliases=[native];title=native;summary='\n'.join(d['value'] for d in c.get('descriptions',[]) if d['lang']=='en');published=c.get('published');kind='cve'
    elif source=='kev':
        native=item['cveID'];aliases=[native];title=item['vulnerabilityName'];summary=item['shortDescription'];research['remediation']=item.get('requiredAction');target={'vendor':item.get('vendorProject'),'product':item.get('product')}
    else:raise ValueError('Unknown structured adapter')
    classification.update(cve=[a for a in aliases if a.startswith('CVE-')],ghsa=[a for a in aliases if a.startswith('GHSA-')],osv=[a for a in aliases if not a.startswith(('CVE-','GHSA-'))])
    key=next(iter(sorted(classification['cve'])),native)
    url=url or (f'https://github.com/advisories/{native}' if source=='ghsa' else cfg['url']+'/'+native)
    r=Record(canonical_key=key,record_type=kind,title=title,summary=redact(summary),source=Source(source_id=source,source_name=cfg['name'],source_url=url,source_record_id=native,published_at=published,terms_url=cfg['terms'],license=cfg['license'],full_text_policy=cfg['policy'],content_hash_sha256=digest(raw),parser_name=source+'-v1'),target=target,classification=classification,research=research,deduplication={'source_aliases':aliases})
    if r.summary!=summary:r.content.redaction_status='redacted'
    return r

def store_raw(raw):
    h=digest(raw);p=Path(settings().data_dir)/'corpus_raw'/h[:2]/h;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if not p.exists():
        p.write_bytes(raw);p.chmod(0o600)
    return str(p)

def category(r):
    return 'full_text_research_reports' if r.record_type in ('research_report','bug_bounty_disclosure') else 'patch_and_commit_records' if r.record_type=='patch_analysis' else 'training_and_reference_resources' if r.record_type=='training_reference' else 'structured_vulnerability_advisories'

def ingest(db,r,raw):
    # Raw artifact retained only under explicit permission, before publication.
    if r.source.full_text_policy not in ('allowed','derived_only'):raise ValueError('Full-text permission requires review')
    aliases=set(r.deduplication.source_aliases+[r.canonical_key])
    found=db.query(Alias).filter(Alias.alias.in_(aliases)).first()
    existing=db.get(Knowledge,found.record_id) if found else db.query(Knowledge).filter_by(content_hash=r.source.content_hash_sha256).first()
    if existing:
        for a in aliases:
            if not db.get(Alias,a):db.add(Alias(alias=a,record_id=existing.id))
        # Preserve all source versions/provenance as linked artifacts, not independent records.
        link_id=digest(r.source.source_id+':'+r.source.content_hash_sha256)[:36]
        if not db.get(Document,link_id):document(db,'corpus_provenance',existing.id,{'source':r.source.model_dump(),'raw':store_raw(raw)},link_id)
        db.flush();return 'duplicate'
    r.content.raw_artifact_ref=store_raw(raw)
    text=redact(r.title+'\n'+r.summary)
    pieces=[text[i:i+1600] for i in range(0,len(text),1400)][:100]
    r.content.chunks=[{'index':i,'page':None,'section':r.title,'hash':digest(p),'embedding_version':EMBEDDING_VERSION} for i,p in enumerate(pieces)]
    record=r.model_dump(by_alias=True);Record.model_validate(record)
    db.add(Knowledge(id=r.record_id,canonical_key=r.canonical_key,category=category(r),source=r.source.source_id,title=r.title,content_hash=r.source.content_hash_sha256,record=canonical(record)));db.flush()
    for a in aliases:db.add(Alias(alias=a,record_id=r.record_id))
    for i,p in enumerate(pieces):db.add(Chunk(record_id=r.record_id,position=i,text=p,embedding=canonical(embed(p))))
    db.flush();return 'ingested'

def stats(db):
    cats=dict(db.query(Knowledge.category,func.count()).group_by(Knowledge.category).all());sources=dict(db.query(Knowledge.source,func.count()).group_by(Knowledge.source).all())
    for c in ['full_text_research_reports','structured_vulnerability_advisories','patch_and_commit_records','training_and_reference_resources']:cats.setdefault(c,0)
    return {'unique_normalized_records':sum(cats.values()),'categories':cats,'by_source':sources,'aliases':db.query(Alias).count(),'chunks':db.query(Chunk).count(),'embedding':EMBEDDING_VERSION,'parser_errors':db.query(Document).filter_by(kind='import_error').count(),'jobs':[{'id':j.id,**j.value()} for j in db.query(Document).filter_by(kind='corpus_job')],'scale_target':20000,'scale_status':'passed' if sum(cats.values())>=20000 else 'partial','full_text_report_count':cats['full_text_research_reports']}

def search(db,query,source=None,limit=5):
    limit=min(max(limit,1),20);tokens=list(set(re.findall(r'[a-z0-9_+-]+',query.lower())))[:20]
    if not tokens:return []
    # Candidate filter bounds scoring work; exact cosine over filtered lexical vectors.
    from sqlalchemy import or_
    q=db.query(Chunk,Knowledge).join(Knowledge,Knowledge.id==Chunk.record_id).filter(or_(*[Chunk.text.ilike('%'+t.replace('%','')+'%') for t in tokens]))
    if source:q=q.filter(Knowledge.source==source)
    v=np.array(embed(query));results=[]
    for c,k in q.limit(2000):
        score=float(np.dot(v,np.array(json.loads(c.embedding))));r=json.loads(k.record)
        results.append({'record_id':k.id,'title':k.title,'text':c.text,'score':score,'source_url':r['source']['source_url'],'license':r['source']['license'],'hash':k.content_hash,'chunk_index':c.position})
    results.sort(key=lambda x:x['score'],reverse=True);return results[:limit]

def import_parts(path,max_size=20*1024*1024):
    p=Path(path)
    if p.stat().st_size>max_size:raise ValueError('Input too large')
    data=p.read_bytes();ext=p.suffix.lower()
    if ext=='.zip':
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if len(z.infolist())>1000 or sum(i.file_size for i in z.infolist())>max_size:raise ValueError('Archive exceeds quota')
            for info in z.infolist():
                if info.is_dir():continue
                if info.filename.startswith('/') or '..' in Path(info.filename).parts or (info.external_attr>>16)&0o170000==0o120000:raise ValueError('Unsafe archive member')
                import tempfile
                with tempfile.TemporaryDirectory() as td:
                    f=Path(td)/Path(info.filename).name;f.write_bytes(z.read(info));yield from import_parts(f,max_size)
    elif ext=='.pdf':
        from pypdf import PdfReader
        for n,page in enumerate(PdfReader(io.BytesIO(data)).pages):yield {'title':p.name+f' page {n+1}','text':page.extract_text() or '', 'page':n+1,'raw':data}
    elif ext=='.docx':
        from docx import Document as Docx
        yield {'title':p.name,'text':'\n'.join(p.text for p in Docx(io.BytesIO(data)).paragraphs),'raw':data}
    elif ext in ('.json','.jsonl','.csv'):
        text=data.decode('utf-8');items=list(csv.DictReader(io.StringIO(text))) if ext=='.csv' else [json.loads(l) for l in text.splitlines() if l.strip()] if ext=='.jsonl' else json.loads(text)
        if not isinstance(items,list):items=[items]
        for item in items:yield {'title':item.get('title',p.name),'text':canonical(item),'structured':item,'raw':data}
    elif ext in ('.md','.txt','.html','.htm'):
        text=data.decode('utf-8')
        if ext in ('.html','.htm'):
            from bs4 import BeautifulSoup
            soup=BeautifulSoup(text,'html.parser')
            for tag in soup(['script','style','iframe']):tag.decompose()
            text=soup.get_text('\n')
        yield {'title':p.name,'text':text,'raw':data}
    else:raise ValueError('Unsupported input format')

def import_file(db,path,license,source_url,record_type='research_report'):
    if license=='unknown':raise ValueError('Confirm source permission before import')
    counts=Counter()
    for part in import_parts(path):
        r=Record(canonical_key=digest((source_url+part['title']+digest(part['raw'])).encode()),record_type=record_type,title=part['title'],summary=redact(part['text']),source=Source(source_id='owner',source_name='Owner import',source_url=source_url,license=license,full_text_policy='allowed',content_hash_sha256=digest(part['raw']),parser_name='owner-'+Path(path).suffix))
        counts[ingest(db,r,part['raw'])]+=1
    db.commit();return dict(counts)

class ReadStream:
    def __init__(self,response):self.response=response
    def read(self,n):return self.response.read(n)

def sync_bulk(source='ghsa',limit=21000,job_id=None):
    if source not in ('ghsa','cve'):raise ValueError('No official bulk connector for source')
    cfg=SOURCES[source]
    with session() as db:
        job=db.get(Document,job_id) if job_id else document(db,'corpus_job','system',{'source':source,'cursor':0,'counts':{},'status':'running','started':now()})
        if not job or job.kind!='corpus_job' or job.value()['source']!=source:raise ValueError('Invalid resume job')
        state=job.value();counts=Counter(state['counts']);cursor=state['cursor'];job_id=job.id;state['status']='running';job.data=canonical(state);db.commit()
    req=urllib.request.Request(cfg['bulk'],headers={'User-Agent':'ATLAS/0.1 lawful advisory import','Accept-Encoding':'identity'})
    try:
        with urllib.request.urlopen(req,timeout=120) as response,tarfile.open(fileobj=ReadStream(response),mode='r|gz') as tar:
            index=0
            for member in tar:
                if not member.isfile() or not member.name.endswith('.json'):continue
                if source=='ghsa' and '/advisories/github-reviewed/' not in member.name:continue
                if source=='cve' and '/cves/' not in member.name:continue
                index+=1
                if index<=cursor:continue
                if member.size>2*1024*1024:continue
                raw=tar.extractfile(member).read()
                with session() as db:
                    try:
                        r=source_record(source,json.loads(raw),raw,cfg['url']+'/blob/main/'+member.name.split('/',1)[1]);counts[ingest(db,r,raw)]+=1
                    except Exception as e:
                        db.rollback();counts['errors']+=1;document(db,'import_error','system',{'source':source,'path':member.name,'reason':type(e).__name__,'job_id':job_id})
                    job=db.get(Document,job_id);state.update(cursor=index,counts=dict(counts),updated=now(),status='running');job.data=canonical(state);db.commit()
                if index%500==0:print(canonical({'job_id':job_id,**state}),flush=True)
                if counts['ingested']>=limit:break
        with session() as db:
            job=db.get(Document,job_id);state['status']='completed';job.data=canonical(state);db.commit()
        return {'job_id':job_id,**state}
    except Exception as e:
        with session() as db:
            job=db.get(Document,job_id);state.update(status='blocked',error=type(e).__name__);job.data=canonical(state);db.commit()
        raise
