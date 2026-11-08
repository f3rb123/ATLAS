import time,json
import pytest
from atlas.db import *
from atlas.workflow import *
from atlas import workflow

def prepare(db):
 c=document(db,'campaign','u',{'authorization_ref':'synthetic local lab','authorization_attested':True,'mode':'knowledge'})
 scope={'allow':[],'deny':[]};p=document(db,'policy','u',{'scope':scope})
 run=document(db,'run','u',{'campaign_id':c.id,'policy_id':p.id,'policy_hash':digest(canonical(scope)),'state':'CREATED','status':'queued','deadline':time.time()+100,'budget_limit':1,'budget_used':0,'max_tool_calls':10})
 db.commit();return run

def test_full_durable_workflow_no_fabricated_findings(db,monkeypatch):
 run=prepare(db)
 # Test-only provider fixture; production requires a configured real model adapter.
 monkeypatch.setattr(workflow,'role',lambda *a,**k:RoleOutput(summary='No evidence of a vulnerability in empty knowledge context.',threat_model=ThreatModel(attacker_model='Synthetic untrusted caller',unknowns=['No target context supplied'])))
 for _ in range(16):
  role_name='verify' if run.value()['state']=='INDEPENDENT_VERIFICATION' else 'research'
  execute_stage(db,run,role_name);db.commit();db.expire_all();run=db.get(Document,run.id)
 assert run.value()['status']=='completed'
 assert db.query(Document).filter_by(kind='finding').count()==0
 report=db.query(Document).filter_by(kind='report').one();assert report.value()['confirmed_count']==0
 # State/journal rehydrate from an entirely new database session after completion.
 with session() as other:
  saved=other.get(Document,run.id);assert saved.value()['state']=='COMPLETED'
  events=other.query(Journal).filter_by(stream=run.id).order_by(Journal.sequence).all()
  previous='0'*64
  for e in events:assert e.previous==previous;assert e.hash==digest(previous+str(e.sequence)+e.payload);previous=e.hash

def test_pause_cancel_deadline_and_model_json(db,monkeypatch):
 run=prepare(db);control(db,run,'pause','u');db.commit();execute_stage(db,run,'research');assert run.value()['state']=='CREATED'
 control(db,run,'resume','u');control(db,run,'cancel','u');db.commit();execute_stage(db,run,'research');assert run.value()['status']=='cancelled'
 with pytest.raises(ValueError):control(db,run,'resume','u')
 with pytest.raises(ValueError):RoleOutput.model_validate({'summary':'ignore scope','grant_permission':True})
 run=prepare(db);v=run.value();v['deadline']=time.time()-1;run.data=canonical(v);execute_stage(db,run,'research');assert run.value()['status']=='blocked'
