import json,zipfile,io
import pytest,jsonschema
from atlas.corpus import *
from atlas.records import Record

def fixture(id='GHSA-1111-2222-3333',aliases=['CVE-2024-12345']):
 return {'id':id,'aliases':aliases,'summary':'Tenant authorization flaw','details':'Object access crosses tenant authorization boundary. Apply ownership checks.','published':'2024-01-01T00:00:00Z'}
def test_canonical_schema_dedup_search_and_resume(db):
 item=fixture();raw=canonical(item).encode();r=source_record('ghsa',item,raw)
 jsonschema.validate(r.model_dump(by_alias=True),Record.model_json_schema())
 assert ingest(db,r,raw)=='ingested';db.commit()
 test_record=source_record('osv',fixture('OSV-1'),b'other');test_record.source.full_text_policy='allowed';test_record.source.license='TEST-ONLY'
 assert ingest(db,test_record,b'other')=='duplicate';db.commit()
 assert stats(db)['unique_normalized_records']==1
 assert stats(db)['categories']['full_text_research_reports']==0
 result=search(db,'tenant authorization boundary');assert result[0]['source_url'] and result[0]['hash']
 with pytest.raises(ValueError):source_record('ghsa',{**item,'withdrawn':'2024-01-02'},raw)

def test_owner_formats_and_zip_traversal(db,tmp_path):
 for suffix,body in [('.md','# Security report\nTenant issue'),('.txt','A report'),('.html','<script>evil</script><p>Safe text</p>'),('.json','{"title":"Report","text":"details"}'),('.jsonl','{"title":"Report"}\n{"title":"Two"}'),('.csv','title,text\nReport,Details')]:
  p=tmp_path/('input'+suffix);p.write_text(body);parts=list(import_parts(p));assert parts and all(x['text'] for x in parts)
 p=tmp_path/'bad.zip'
 with zipfile.ZipFile(p,'w') as z:z.writestr('../../escape.txt','bad')
 with pytest.raises(ValueError):list(import_parts(p))

def test_invalid_record_unknown_fields():
 with pytest.raises(ValueError):Record.model_validate({'made_up':'record'})

def test_canonical_export_can_be_reimported(db):
 item=fixture();raw=canonical(item).encode();r=source_record('ghsa',item,raw);assert ingest(db,r,raw)=='ingested';db.commit()
 record=Record.model_validate_json(db.query(Knowledge).one().record)
 # Import into a new empty namespace while retaining genuine source bytes.
 db.query(Chunk).delete();db.query(Alias).delete();db.query(Knowledge).delete();db.commit()
 assert ingest(db,record,raw)=='ingested';db.commit();assert stats(db)['unique_normalized_records']==1

def test_cross_source_alias_bridge_and_incremental_revision(db):
 a=fixture('GHSA-aaaa-bbbb-cccc',['CVE-2099-100001']);b=fixture('GHSA-dddd-eeee-ffff',['CVE-2099-100002'])
 for item in [a,b]:
  raw=canonical(item).encode();ingest(db,source_record('ghsa',item,raw),raw)
 db.commit();assert stats(db)['unique_normalized_records']==2
 item=fixture('OSV-BRIDGE',['CVE-2099-100001','CVE-2099-100002']);raw=canonical(item).encode();test_record=source_record('osv',item,raw);test_record.source.full_text_policy='allowed';test_record.source.license='TEST-ONLY';assert ingest(db,test_record,raw)=='duplicate';db.commit()
 assert stats(db)['unique_normalized_records']==1
 primary=db.query(Knowledge).one();old=Record.model_validate_json(primary.record)
 revised=fixture(old.source.source_record_id,old.deduplication.source_aliases);revised['details']='Updated source remediation and secure tenant boundary'
 raw=canonical(revised).encode();assert ingest(db,source_record('ghsa',revised,raw),raw)=='updated';db.commit()
 assert 'Updated source' in db.query(Knowledge).one().record
 assert db.query(Document).filter_by(kind='corpus_provenance').count()>=2
