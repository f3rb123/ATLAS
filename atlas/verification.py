"""Independent replay and counterfactual evidence gate. No model-only promotion."""
import re
from .db import Document,document,canonical,digest
from .tools import broker

def successful_test(result):
    r=result.get('result',result)
    return r.get('exit_code')==0 and not r.get('timed_out') and bool(re.search(r'Ran [1-9][0-9]* tests?',r.get('output',''))) and '\nOK' in r.get('output','')

def verify_candidates(db,run,repo,done):
    from .workflow import role
    executions=[d.value()['result'] for d in done if d.value()['state']=='SAFE_EXECUTION']
    if not executions or executions[-1].get('no_experiment'):return {'status':'inconclusive','reason':'No executable evidence was proposed; no finding confirmed'}
    original=executions[-1]
    if not successful_test(original['proof']) or not successful_test(original['control']):return {'status':'inconclusive','reason':'Research proof/control did not execute non-zero tests successfully'}
    e=original['experiment']
    h=db.get(Document,e['hypothesis_id'])
    if not h or h.owner!=run.owner or h.kind!='hypothesis' or h.value()['run_id']!=run.id:raise ValueError('Invalid hypothesis provenance')
    proof=broker(db,run,repo,'run_local_reproduction',{'template':'python_unittest','test_path':e['test_path']},'independent_verifier')
    control=broker(db,run,repo,'run_local_reproduction',{'template':'python_unittest','test_path':e['control_test_path']},'independent_verifier')
    if not successful_test(proof) or not successful_test(control):return {'status':'refuted','reason':'Independent reproduction failed'}
    # Fresh verifier context includes the claim, evidence and secure counterfactual only.
    response=role(db,run,'INDEPENDENT_VERIFICATION',{'claim':h.value(),'proof':proof,'secure_control':control,'snapshot':repo.inventory()['snapshot_hash']},'verifier')
    allowed={proof['artifact_id'],control['artifact_id']}
    if response.status=='confirmed' and (set(response.evidence_ids)!=allowed or not response.counterfactual):raise ValueError('Verifier must cite both independent proof and secure control')
    key=digest(canonical({'claim':h.value()['claim'],'snapshot':repo.inventory()['snapshot_hash']}))
    existing=[f for f in db.query(Document).filter_by(kind='finding',owner=run.owner) if f.value()['root_cause_key']==key]
    if existing:return {'status':'duplicate','finding_id':existing[0].id}
    finding=document(db,'finding',run.owner,{'run_id':run.id,'campaign_id':run.value()['campaign_id'],'title':h.value()['claim'],'status':response.status,'severity':'unscored','hypothesis':h.value(),'verification':response.model_dump(),'evidence_ids':list(allowed),'root_cause_key':key,'policy_hash':run.value()['policy_hash']})
    return {'status':response.status,'finding_id':finding.id}
