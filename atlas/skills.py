"""Versioned reviewed procedures; content never grants tool authority."""
import json,re,yaml
from pathlib import Path
from typing import Literal
from pydantic import Field
from .policy import Strict,Denied
from .db import Document,document,canonical,digest,append

class Skill(Strict):
    skill_id:str=Field(pattern=r'^[a-z0-9_-]{1,80}$')
    name:str;version:str=Field(pattern=r'^\d+\.\d+\.\d+$')
    description:str;author:str;source:str;license:str
    category:Literal['recon','web','api','authz','injection','business_logic','cloud','mobile','source','verification','reporting','training']
    languages:list[str]=[];frameworks:list[str]=[];prerequisites:list[str]=[]
    inputs:list[str]=[];outputs:list[str]=[];required_tools:list[str]=[]
    risk:Literal['read_only','low_impact','gated']='read_only'
    prohibited_actions:list[str]=[];required_approvals:list[str]=[]
    scope_requirements:list[str]=[];timeout_seconds:int=Field(default=60,ge=1,le=300)
    max_tokens:int=Field(default=2000,ge=1,le=32000);max_tool_calls:int=Field(default=5,ge=0,le=20)
    references:list[str]=[];fixtures:list[str]=[];limitations:list[str]=[];changelog:str=''
    content:str
    provenance:Literal['atlas_authored','owner_supplied','community_import']='community_import'


def parse_skill(text):
    if text.startswith('---\n'):
        _,front,content=text.split('---',2);v=yaml.safe_load(front);v['content']=content.strip()
    else:v=json.loads(text)
    skill=Skill.model_validate(v)
    if re.search(r'(?im)^\s*(install_hook|postinstall|exec|shell)\s*:',text):raise Denied('Executable installation hooks prohibited')
    return skill

def import_skill(db,owner,skill):
    existing=[d for d in db.query(Document).filter_by(kind='skill',owner=owner) if d.value()['skill_id']==skill.skill_id and d.value()['version']==skill.version]
    if existing:raise ValueError('Skill versions are immutable; increment version')
    from .tools import TOOLS
    if any(t not in TOOLS for t in skill.required_tools):raise Denied('Unknown tool capability')
    d=document(db,'skill',owner,{**skill.model_dump(),'content_hash':digest(canonical(skill.model_dump())),'status':'draft','enabled':False,'reviewed_by':None,'validation':None})
    append(db,owner,owner,'skill_imported',{'id':d.id,'hash':d.value()['content_hash']});return d

def review(db,d,actor):
    v=d.value();v.update(status='reviewed',reviewed_by=actor,enabled=False);d.data=canonical(v);append(db,d.owner,actor,'skill_reviewed',{'id':d.id,'hash':v['content_hash']})

def validate(db,d,actor):
    v=d.value()
    if v['status']!='reviewed':raise Denied('Human review is required first')
    if not v['fixtures']:raise Denied('Attach passing versioned fixture results before validation')
    results=[]
    for id in v['fixtures']:
        f=db.get(Document,id)
        if not f or f.owner!=d.owner or f.kind!='benchmark' or not f.value().get('passed') or f.value().get('skill_hash')!=v['content_hash']:raise Denied('Missing passing fixture bound to this skill hash')
        results.append(id)
    v.update(status='validated',validation={'fixture_ids':results,'skill_hash':v['content_hash']});d.data=canonical(v);append(db,d.owner,actor,'skill_validated',{'id':d.id,'fixtures':results})

def enable(db,d,actor,enabled):
    v=d.value()
    if enabled and (v['status']!='validated' or not v['validation']):raise Denied('Only independently validated procedures can execute')
    v['enabled']=enabled;d.data=canonical(v);append(db,d.owner,actor,'skill_enablement_changed',{'id':d.id,'enabled':enabled})
