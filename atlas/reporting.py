"""Evidence-preserving deterministic report renderers; never render untrusted HTML."""
import json,html
from .db import Document,document,canonical,now

def render(findings,format):
    if format=='json':return canonical({'schema':'atlas-finding-report','version':'1.0','generated_at':now(),'findings':findings})
    if format=='sarif':return canonical({'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{'tool':{'driver':{'name':'ATLAS','version':'0.1.0'}},'results':[{'ruleId':'ATLAS.evidence-confirmed','message':{'text':f['title']},'level':'warning','properties':{'verification':f['verification'],'evidence_ids':f['evidence_ids']}} for f in findings]}]})
    lines=['# ATLAS evidence report','Generated '+now(),'Only confirmed findings are included. Severity is unscored unless reviewed.']
    for f in findings:lines+=['\n## '+f['title'],'Status: '+f['status'],'Policy: '+f['policy_hash'],'\nClaimed impact: '+f['hypothesis']['impact'],'\nVerification: '+f['verification']['reason'],'\nSecure counterfactual: '+f['verification']['counterfactual'],'Evidence: '+', '.join(f['evidence_ids']),'\nReproduction and preconditions:\n'+json.dumps(f['hypothesis'],indent=2)]
    text='\n\n'.join(lines)
    if format=='html':return '<!doctype html><html><meta charset="utf-8"><title>ATLAS report</title><body><pre>'+html.escape(text)+'</pre></body></html>'
    if format!='markdown':raise ValueError('Unsupported report format')
    return text

def generate_report(db,run,format):
    findings=[f.value() for f in db.query(Document).filter_by(kind='finding',owner=run.owner) if f.value()['run_id']==run.id and f.value()['status']=='confirmed']
    return document(db,'report',run.owner,{'run_id':run.id,'format':format,'content':render(findings,format),'confirmed_count':len(findings)})
