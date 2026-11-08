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

class WithdrawnRecord(ValueError):
    def __init__(self,record_id):self.record_id=record_id;super().__init__('Source withdrew this record')

SOURCES={
 'ghsa':{'name':'GitHub Advisory Database','url':'https://github.com/github/advisory-database','terms':'https://raw.githubusercontent.com/github/advisory-database/main/LICENSE.md','license':'CC-BY-4.0','policy':'allowed','bulk':'https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main'},
 'cve':{'name':'CVE Program','url':'https://github.com/CVEProject/cvelistV5','terms':'https://www.cve.org/Legal/TermsOfUse','license':'LicenseRef-CVE-Terms','policy':'allowed','bulk':'https://codeload.github.com/CVEProject/cvelistV5/tar.gz/refs/heads/main'},
 'nvd':{'name':'NVD','url':'https://services.nvd.nist.gov/rest/json/cves/2.0','terms':'https://www.nist.gov/copyrights-disclaimers','license':'LicenseRef-NIST-PublicInformation','policy':'allowed'},
 'osv':{'name':'OSV','url':'https://api.osv.dev/v1/vulns','terms':'https://osv.dev/docs/','license':'upstream-dependent','policy':'unknown_or_restricted'},
 'kev':{'name':'CISA KEV','url':'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json','terms':'https://www.cisa.gov/about/website-policies','license':'unknown','policy':'unknown_or_restricted'},
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

def source_config(source):
    cfg=dict(SOURCES[source])
    with session() as db:
        for d in db.query(Document).filter_by(kind='source_policy').order_by(Document.created):
            v=d.value()
            if v.get('native_source')==source:
                cfg.update(license=v['license'],terms=v['terms_url'],policy='allowed' if v.get('enabled') and v.get('owner_reviewed') else 'unknown_or_restricted',operator_disabled=not v.get('enabled'))
    return cfg

def source_record(source,item,raw,url=None):
    cfg=source_config(source)
    if source=='osv' and item.get('id','').startswith('GHSA-') and not cfg.get('operator_disabled'):
        cfg.update(license=SOURCES['ghsa']['license'],terms=SOURCES['ghsa']['terms'],policy='allowed')
    aliases=[];title='';summary='';kind='security_advisory';published=None;target={};classification={};research={}
    if source in ('ghsa','osv'):
        native=item['id'];aliases=list(set([native]+item.get('aliases',[])));title=item.get('summary') or native;summary=item.get('details','')
        published=item.get('published');kind='ghsa' if source=='ghsa' else 'osv'
        affected=item.get('affected',[])
        if affected:
            a=affected[0];pkg=a.get('package',{});target={'ecosystem':pkg.get('ecosystem'),'package':pkg.get('name'),'affected_versions':a.get('versions',[]),'fixed_versions':[e['fixed'] for r in a.get('ranges',[]) for e in r.get('events',[]) if 'fixed' in e]}
        classification['cwe']=item.get('database_specific',{}).get('cwe_ids',[])
        classification['severity_label']=item.get('database_specific',{}).get('severity')
        refs=[r['url'] for r in item.get('references',[]) if r.get('type')=='FIX'];research['patch_references']=refs
        if item.get('withdrawn'):raise WithdrawnRecord(native)
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
    matches=db.query(Alias).filter(Alias.alias.in_(aliases)).all()
    roots=sorted({a.record_id for a in matches})
    existing=db.get(Knowledge,roots[0]) if roots else db.query(Knowledge).filter_by(content_hash=r.source.content_hash_sha256,owner=r.access_owner).first()
    # Official alias bridges collapse identity groups, preserving every source version.
    for id in roots[1:]:
        old=db.get(Knowledge,id)
        if old.owner!=r.access_owner:raise ValueError('Cross-owner alias collision')
        document(db,'corpus_provenance',existing.id,{'record':json.loads(old.record),'duplicate_of':existing.id,'reason':'official_alias_bridge'})
        db.query(Alias).filter_by(record_id=id).update({'record_id':existing.id})
        db.query(Chunk).filter_by(record_id=id).delete();db.delete(old);db.flush()
    if existing:
        for a in aliases:
            if not db.get(Alias,a):db.add(Alias(alias=a,record_id=existing.id))
        # Preserve all source versions/provenance as linked artifacts, not independent records.
        link_id=digest(r.source.source_id+':'+r.source.content_hash_sha256)[:36]
        if not db.get(Document,link_id):document(db,'corpus_provenance',existing.id,{'source':r.source.model_dump(),'raw':store_raw(raw)},link_id)
        old_record=Record.model_validate_json(existing.record)
        if old_record.source.source_id==r.source.source_id and old_record.source.source_record_id==r.source.source_record_id and old_record.source.content_hash_sha256!=r.source.content_hash_sha256:
            document(db,'corpus_provenance',existing.id,{'record':old_record.model_dump(by_alias=True),'reason':'source_revision'})
            r.record_id=existing.id;r.canonical_key=existing.canonical_key;r.created_at=old_record.created_at;r.updated_at=now();r.content.raw_artifact_ref=store_raw(raw)
            r.deduplication.source_aliases=sorted({a.alias for a in db.query(Alias).filter_by(record_id=existing.id)})
            existing.record=canonical(r.model_dump(by_alias=True));existing.title=r.title;existing.content_hash=r.source.content_hash_sha256
            reindex_record(db,existing);db.flush();return 'updated'
        db.flush();return 'duplicate'
    r.content.raw_artifact_ref=store_raw(raw)
    text=redact(r.title+'\n'+r.summary)
    page_parts=[c for c in r.content.chunks if 'text' in c]
    pieces=[];metadata=[]
    for part in (page_parts or [{'text':text,'page':None}]):
        t=redact(part['text'])
        for start in range(0,len(t),1400):
            pieces.append(t[start:start+1600]);metadata.append({'index':len(pieces)-1,'page':part.get('page'),'section':r.title,'hash':digest(pieces[-1]),'embedding_version':EMBEDDING_VERSION,'text':pieces[-1]})
    if len(pieces)>2000:raise ValueError('Document exceeds chunk quota')
    r.content.chunks=metadata
    record=r.model_dump(by_alias=True);Record.model_validate(record)
    db.add(Knowledge(id=r.record_id,owner=r.access_owner,canonical_key=r.canonical_key,category=category(r),source=r.source.source_id,title=r.title,content_hash=r.source.content_hash_sha256,record=canonical(record)));db.flush()
    for a in aliases:db.add(Alias(alias=a,record_id=r.record_id))
    for i,p in enumerate(pieces):db.add(Chunk(record_id=r.record_id,position=i,text=p,embedding=canonical(embed(p))))
    db.flush()
    if db.bind.dialect.name=='postgresql':
        from sqlalchemy import text
        for c in db.query(Chunk).filter_by(record_id=r.record_id):db.execute(text('UPDATE knowledge_chunks SET embedding_vector=CAST(:v AS vector) WHERE id=:id'),{'v':c.embedding,'id':c.id})
    return 'ingested'

def stats(db):
    cats=dict(db.query(Knowledge.category,func.count()).group_by(Knowledge.category).all());sources=dict(db.query(Knowledge.source,func.count()).group_by(Knowledge.source).all())
    for c in ['full_text_research_reports','structured_vulnerability_advisories','patch_and_commit_records','training_and_reference_resources']:cats.setdefault(c,0)
    return {'unique_normalized_records':sum(cats.values()),'categories':cats,'by_source':sources,'aliases':db.query(Alias).count(),'chunks':db.query(Chunk).count(),'embedding':EMBEDDING_VERSION,'quarantined_items':db.query(Document).filter_by(kind='import_error').count(),'parser_errors':db.query(Document).filter_by(kind='import_error').filter(~Document.data.like('%"reason":"ValueError"%')).count(),'jobs':[{'id':j.id,**j.value()} for j in db.query(Document).filter_by(kind='corpus_job')],'scale_target':20000,'scale_status':'passed' if sum(cats.values())>=20000 else 'partial','full_text_report_count':cats['full_text_research_reports']}

def search(db,query,source=None,limit=5,owner='public'):
    limit=min(max(limit,1),20);tokens=list(set(re.findall(r'[a-z0-9_+-]+',query.lower())))[:20]
    if not tokens:return []
    # Candidate filter bounds scoring work; exact cosine over filtered lexical vectors.
    from sqlalchemy import or_
    q=db.query(Chunk,Knowledge).join(Knowledge,Knowledge.id==Chunk.record_id).filter(Knowledge.owner.in_(['public',owner])).filter(or_(*[Chunk.text.ilike('%'+t.replace('%','')+'%') for t in tokens]))
    if source:q=q.filter(Knowledge.source==source)
    if db.bind.dialect.name=='postgresql':
        from sqlalchemy import text
        q=q.order_by(text('knowledge_chunks.embedding_vector <=> CAST(:query_embedding AS vector)')).params(query_embedding=canonical(embed(query)))
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

def import_file(db,path,license,source_url,record_type='research_report',owner='public'):
    if license=='unknown':raise ValueError('Confirm source permission before import')
    counts=Counter()
    parts=list(import_parts(path))
    if Path(path).suffix.lower()=='.pdf':
        pages=parts;parts=[{'title':Path(path).name,'text':'\n'.join(x['text'] for x in pages),'raw':Path(path).read_bytes(),'pages':pages}]
    for part in parts:
        if not part['text'].strip():raise ValueError('No extractable text; OCR is not enabled')
        r=Record(canonical_key=digest((source_url+part['title']+digest(part['raw'])).encode()),record_type=record_type,title=part['title'],summary=redact(part['text']),source=Source(source_id='owner',source_name='Owner import',source_url=source_url,license=license,full_text_policy='allowed',content_hash_sha256=digest(part['raw']),parser_name='owner-'+Path(path).suffix))
        if part.get('pages'):r.content.chunks=[{'page':p['page'],'text':p['text']} for p in part['pages']]
        r.access_owner=owner
        if owner!='public':r.canonical_key=owner+':'+r.canonical_key;r.deduplication.source_aliases=[r.canonical_key]
        counts[ingest(db,r,part['raw'])]+=1
    db.commit();return dict(counts)

class ReadStream:
    def __init__(self,response):self.response=response
    def read(self,n):return self.response.read(n)

def sync_bulk(source='ghsa',limit=21000,job_id=None):
    if source not in ('ghsa','cve'):raise ValueError('No official bulk connector for source')
    cfg=source_config(source)
    if cfg['policy']!='allowed':raise ValueError('Source terms/permission review required')
    with session() as db:
        job=db.get(Document,job_id) if job_id else document(db,'corpus_job','system',{'source':source,'cursor':0,'counts':{},'status':'running','started':now()})
        if not job or job.kind!='corpus_job' or job.value()['source']!=source:raise ValueError('Invalid resume job')
        state=job.value();counts=Counter(state['counts']);cursor=state['cursor'];job_id=job.id
        if counts['ingested']>=limit:return {'job_id':job_id,**state}
        state['status']='running';job.data=canonical(state);db.commit()
    if not state.get('snapshot_sha'):
        import subprocess
        remote=subprocess.run(['git','ls-remote',cfg['url']+'.git','HEAD'],capture_output=True,text=True,timeout=30,check=True).stdout.split()
        if not remote or not re.fullmatch(r'[0-9a-f]{40}',remote[0]):raise ValueError('Unable to pin source snapshot')
        state['snapshot_sha']=remote[0]
        with session() as db:
            job=db.get(Document,job_id);job.data=canonical(state);db.commit()
    bulk_url=cfg['bulk'].replace('refs/heads/main',state['snapshot_sha'])
    req=urllib.request.Request(bulk_url,headers={'User-Agent':'ATLAS/0.1 lawful advisory import','Accept-Encoding':'identity'})
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
                    except WithdrawnRecord as e:
                        db.rollback();counts['withdrawn']+=1
                        alias=db.get(Alias,e.record_id)
                        if alias:remove_record(db,alias.record_id,'upstream_withdrawal')
                        document(db,'corpus_exclusion','system',{'source':source,'source_record_id':e.record_id,'reason':'upstream_withdrawal','job_id':job_id})
                    except Exception as e:
                        db.rollback();counts['errors']+=1;document(db,'import_error','system',{'source':source,'path':member.name,'reason':type(e).__name__,'job_id':job_id})
                    job=db.get(Document,job_id);state.update(cursor=index,counts=dict(counts),updated=now(),status='running');job.data=canonical(state);db.commit()
                if index%500==0:print(canonical({'job_id':job_id,**state}),flush=True)
                if counts['ingested']>=limit or index>=max(limit*2,limit+1000):break
        with session() as db:
            job=db.get(Document,job_id);state['status']='completed';job.data=canonical(state);db.commit()
        return {'job_id':job_id,**state}
    except Exception as e:
        with session() as db:
            job=db.get(Document,job_id);state.update(status='blocked',error=type(e).__name__);job.data=canonical(state);db.commit()
        raise

# API connectors retain source cursors and conditional-fetch metadata independently.
def fetch_json(source,url,etag=None):
    import urllib.error
    headers={'User-Agent':'ATLAS/0.1 (+local-owner-controlled-advisory-ingest)','Accept':'application/json'}
    if etag:headers['If-None-Match']=etag
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=30) as r:
                data=r.read(16*1024*1024+1)
                if len(data)>16*1024*1024:raise ValueError('Source response exceeds quota')
                return json.loads(data),r.headers.get('ETag')
        except urllib.error.HTTPError as e:
            if e.code==304:return None,etag
            if e.code not in (429,500,502,503,504) or attempt==2:raise
            delay=min(int(e.headers.get('Retry-After','6')),60);time.sleep(delay*(attempt+1))
    raise ValueError('Fetch exhausted')

def sync_api(source,limit=10,ids=None,job_id=None):
    if source not in ('nvd','osv','kev'):raise ValueError('Unsupported API source')
    with session() as db:
        job=db.get(Document,job_id) if job_id else document(db,'corpus_job','system',{'source':source,'cursor':0,'counts':{},'status':'running','started':now(),'etag':None})
        if not job or job.value()['source']!=source:raise ValueError('Resume source mismatch')
        state=job.value();job_id=job.id;db.commit()
        if source=='osv' and not ids:ids=[r.alias for r in db.query(Alias).filter(Alias.alias.like('GHSA-%')).limit(limit)]
    counts=Counter(state.get('counts',{}))
    try:
        if source!='osv' and source_config(source)['policy']!='allowed':raise ValueError('Source terms/permission review required')
        while state['cursor']<limit:
            cursor=state['cursor']
            if source=='nvd':url=SOURCES[source]['url']+f'?startIndex={cursor}&resultsPerPage={min(100,limit-cursor)}'
            elif source=='osv':
                if cursor>=len(ids):break
                url=SOURCES[source]['url']+'/'+ids[cursor]
            else:url=SOURCES[source]['url']
            payload,etag=fetch_json(source,url,state.get('etag') if source=='kev' else None)
            if payload is None:break
            items=payload.get('vulnerabilities',[]) if source in ('nvd','kev') else [payload]
            if not items:break
            for item in items[:limit-state['cursor']]:
                raw=canonical(item).encode()
                with session() as db:
                    try:counts[ingest(db,source_record(source,item,raw,url),raw)]+=1
                    except Exception as e:
                        db.rollback();counts['errors']+=1;document(db,'import_error','system',{'source':source,'reason':type(e).__name__,'job_id':job_id})
                    state.update(cursor=state['cursor']+1,counts=dict(counts),updated=now(),status='running',etag=etag)
                    job=db.get(Document,job_id);job.data=canonical(state);db.commit()
            if source=='kev':break
            time.sleep(6 if source=='nvd' else 1)
        state['status']='completed'
    except Exception as e:state.update(status='blocked',error=type(e).__name__)
    with session() as db:
        job=db.get(Document,job_id);job.data=canonical(state);db.commit()
    return {'job_id':job_id,**state}

def remove_record(db,record_id,reason):
    k=db.get(Knowledge,record_id)
    if not k:raise ValueError('Record not found')
    raw=json.loads(k.record)['content']['raw_artifact_ref']
    db.query(Chunk).filter_by(record_id=record_id).delete();db.query(Alias).filter_by(record_id=record_id).delete()
    # Keep only minimal tombstone; remove full text and secondary indexes.
    document(db,'corpus_tombstone','system',{'record_id':record_id,'hash':k.content_hash,'reason':reason,'deleted_at':now()});db.delete(k)
    if raw:
        p=Path(raw).resolve();root=(Path(settings().data_dir)/'corpus_raw').resolve()
        if p.is_relative_to(root):p.unlink(missing_ok=True)
    db.commit()

def near_duplicates(db,threshold=0.92):
    groups={};candidates=[]
    for k in db.query(Knowledge).yield_per(200):
        r=json.loads(k.record);tokens=re.findall(r'\w+',r['summary'].lower())
        if len(tokens)<20:continue
        signature=digest(' '.join(tokens[:12]))[:16];shingles=set(tuple(tokens[i:i+3]) for i in range(len(tokens)-2))
        for previous,other in groups.get(signature,[])[:20]:
            score=len(shingles&other)/max(1,len(shingles|other))
            if score>=threshold:candidates.append({'left':previous,'right':k.id,'score':score,'status':'needs_review'})
        groups.setdefault(signature,[]).append((k.id,shingles))
    return candidates

def reindex_record(db,k):
    r=Record.model_validate_json(k.record)
    pages=[c for c in r.content.chunks if 'text' in c]
    if not pages:pages=[{'text':' '.join([r.title,r.canonical_key,*r.deduplication.source_aliases])+'\n'+r.summary,'page':None}]
    db.query(Chunk).filter_by(record_id=k.id).delete();metadata=[]
    for part in pages:
        text=redact(part['text'])
        for start in range(0,len(text),1400):
            piece=text[start:start+1600];position=len(metadata)
            metadata.append({'index':position,'text':piece,'page':part.get('page'),'section':r.title,'hash':digest(piece),'embedding_version':EMBEDDING_VERSION})
            c=Chunk(record_id=k.id,position=position,text=piece,embedding=canonical(embed(piece)));db.add(c);db.flush()
            if db.bind.dialect.name=='postgresql':
                from sqlalchemy import text as sqltext
                db.execute(sqltext('UPDATE knowledge_chunks SET embedding_vector=CAST(:v AS vector) WHERE id=:id'),{'v':c.embedding,'id':c.id})
    r.content.chunks=metadata;r.updated_at=now();k.record=canonical(r.model_dump(by_alias=True));db.flush()

def reindex_job(id):
    with session() as db:job=db.get(Document,id);v=job.value();owner=job.owner
    total=v.get('processed',0)
    while total<v.get('limit',100000):
        with session() as db:
            records=db.query(Knowledge).filter(Knowledge.owner.in_(['public',owner]),Knowledge.id>v.get('cursor','')).order_by(Knowledge.id).limit(100).all()
            if not records:break
            for k in records:reindex_record(db,k);total+=1;v['cursor']=k.id
            v.update(processed=total,lease_until=time.time()+600);job=db.get(Document,id);job.data=canonical(v);db.commit()
    with session() as db:job=db.get(Document,id);v.update(status='completed',processed=total);job.data=canonical(v);db.commit()
    return v
